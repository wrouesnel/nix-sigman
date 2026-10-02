package resigning_test

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	. "gopkg.in/check.v1"
)

type RulesSuite struct {
	upstream    nixtypes.NamedPrivateKey
	privateKeys map[string]nixtypes.NamedPrivateKey
	publicKeys  map[string]nixtypes.NamedPublicKey
}

var _ = Suite(&RulesSuite{})

func (s *RulesSuite) SetUpSuite(c *C) {
	var err error
	s.upstream, err = nixtypes.GeneratePrivateKey("upstream-1")
	c.Assert(err, IsNil)
	local, err := nixtypes.GeneratePrivateKey("local-1")
	c.Assert(err, IsNil)
	s.privateKeys = map[string]nixtypes.NamedPrivateKey{"local-1": local}
	s.publicKeys = map[string]nixtypes.NamedPublicKey{"upstream-1": s.upstream.PublicKey()}
}

func condition(c *C, text string) *resigning.Condition {
	cond := new(resigning.Condition)
	c.Assert(json.Unmarshal([]byte(text), cond), IsNil)
	return cond
}

func (s *RulesSuite) TestConditionValidate(c *C) {
	for text, valid := range map[string]bool{
		`{"name":"bash-*"}`:                                    true,
		`{"signed":false}`:                                     true,
		`{"signed_by":"upstream-1"}`:                           true,
		`{"not":{"signed":true}}`:                              true,
		`{"and":[{"name":"a*"},{"signed":true}]}`:              true,
		`{"or":[{"name":"a*"},{"not":{"or":[{"name":"b"}]}}]}`: true,
		`{}`:                         false,
		`{"name":"a","signed":true}`: false,
		`{"and":[]}`:                 false,
		`{"or":[{}]}`:                false,
		`{"not":{"name":"[x"}}`:      false,
		`{"signed_by":"unknown-1"}`:  false,
		`{"name":"[x"}`:              false,
	} {
		err := condition(c, text).Validate(s.publicKeys)
		c.Check(err == nil, Equals, valid, Commentf("%s: %v", text, err))
	}
	var nilCondition *resigning.Condition
	c.Check(nilCondition.Validate(s.publicKeys), NotNil)
}

func (s *RulesSuite) TestConditionMatches(c *C) {
	unsigned := testNarInfo()
	signed := testNarInfo()
	_, _, err := signed.Sign(s.upstream)
	c.Assert(err, IsNil)

	for text, expected := range map[string][2]bool{
		// {unsigned, signed}
		`{"name":"bash-*"}`:                           {true, true},
		`{"name":"bash"}`:                             {false, false},
		`{"name":"58br*"}`:                            {false, false},
		`{"signed":true}`:                             {false, true},
		`{"signed":false}`:                            {true, false},
		`{"signed_by":"upstream-1"}`:                  {false, true},
		`{"not":{"signed_by":"upstream-1"}}`:          {true, false},
		`{"and":[{"name":"bash-*"},{"signed":true}]}`: {false, true},
		`{"or":[{"name":"zsh-*"},{"signed":false}]}`:  {true, false},
	} {
		cond := condition(c, text)
		c.Check(cond.Matches(&unsigned, s.publicKeys), Equals, expected[0], Commentf("%s unsigned", text))
		c.Check(cond.Matches(&signed, s.publicKeys), Equals, expected[1], Commentf("%s signed", text))
	}

	var nilCondition *resigning.Condition
	c.Check(nilCondition.Matches(&unsigned, s.publicKeys), Equals, true)

	// A signature claiming a key name but not made by that key doesn't match.
	other, err := nixtypes.GeneratePrivateKey("upstream-1")
	c.Assert(err, IsNil)
	forged := testNarInfo()
	_, _, err = forged.Sign(other)
	c.Assert(err, IsNil)
	c.Check(condition(c, `{"signed_by":"upstream-1"}`).Matches(&forged, s.publicKeys), Equals, false)
}

func (s *RulesSuite) TestRuleValidate(c *C) {
	rule := resigning.Rule{SignWith: []string{"local-1"}}
	c.Check(rule.Validate(s.privateKeys, s.publicKeys), IsNil)

	rule.SignWith = nil
	c.Check(rule.Validate(s.privateKeys, s.publicKeys), ErrorMatches, "sign_with must name.*")
	// Only private keys can sign.
	rule.SignWith = []string{"upstream-1"}
	c.Check(rule.Validate(s.privateKeys, s.publicKeys), ErrorMatches, "private key not loaded: upstream-1")

	rule.SignWith = []string{"local-1"}
	rule.Condition = &resigning.Condition{SignedBy: "missing-1"}
	c.Check(rule.Validate(s.privateKeys, s.publicKeys), ErrorMatches, "invalid condition: public key not loaded: missing-1")
}

func (s *RulesSuite) TestRuleActive(c *C) {
	now := time.Now()
	rule := resigning.Rule{}
	c.Check(rule.Active(now), Equals, true)
	rule.Expires = lo.ToPtr(now.Add(time.Second))
	c.Check(rule.Active(now), Equals, true)
	c.Check(rule.Active(now.Add(time.Second)), Equals, false)
}

func (s *RulesSuite) TestNewRuleID(c *C) {
	id := resigning.NewRuleID()
	c.Check(id, HasLen, 32)
	c.Check(resigning.NewRuleID(), Not(Equals), id)
}

type RuleStoreSuite struct {
	path  string
	store *resigning.RuleStore
	now   time.Time
}

var _ = Suite(&RuleStoreSuite{})

func (s *RuleStoreSuite) SetUpTest(c *C) {
	var err error
	// The parent directory is created.
	s.path = filepath.Join(c.MkDir(), "state", "rules.sqlite")
	s.store, err = resigning.OpenRuleStore(s.path)
	c.Assert(err, IsNil)
	s.now = time.UnixMilli(1_700_000_000_000)
	s.store.SetClock(func() time.Time { return s.now })
}

func (s *RuleStoreSuite) TearDownTest(c *C) {
	c.Check(s.store.Close(), IsNil)
}

func (s *RuleStoreSuite) create(c *C, owner string, ttl time.Duration, keys ...string) resigning.Rule {
	rule := resigning.Rule{
		ID:       resigning.NewRuleID(),
		Owner:    owner,
		SignWith: keys,
		Created:  s.now,
	}
	if ttl > 0 {
		rule.Expires = lo.ToPtr(s.now.Add(ttl))
	}
	c.Assert(s.store.Create(&rule), IsNil)
	// Keep creation order distinct.
	s.now = s.now.Add(time.Millisecond)
	return rule
}

func ids(rules []resigning.Rule) []string {
	return lo.Map(rules, func(r resigning.Rule, _ int) string { return r.ID })
}

func (s *RuleStoreSuite) TestRoundTrip(c *C) {
	rule := resigning.Rule{
		ID:          resigning.NewRuleID(),
		Owner:       "alice",
		Description: "release builds",
		Condition:   &resigning.Condition{And: []*resigning.Condition{{Name: "app-*"}, {Signed: lo.ToPtr(false)}}},
		SignWith:    []string{"a-1", "b-1"},
		Created:     s.now,
		Expires:     lo.ToPtr(s.now.Add(time.Hour)),
	}
	c.Assert(s.store.Create(&rule), IsNil)
	got, err := s.store.Get(rule.ID)
	c.Assert(err, IsNil)
	c.Assert(got, NotNil)
	c.Check(got.ID, Equals, rule.ID)
	c.Check(got.Owner, Equals, rule.Owner)
	c.Check(got.Description, Equals, rule.Description)
	c.Check(got.Condition, DeepEquals, rule.Condition)
	c.Check(got.SignWith, DeepEquals, rule.SignWith)
	c.Check(got.Created.Equal(rule.Created), Equals, true)
	c.Check(got.Expires.Equal(*rule.Expires), Equals, true)

	// Rules without a condition or expiry round trip too.
	bare := s.create(c, "bob", 0, "a-1")
	got, err = s.store.Get(bare.ID)
	c.Assert(err, IsNil)
	c.Check(got.Condition, IsNil)
	c.Check(got.Expires, IsNil)

	// Duplicate IDs are rejected.
	c.Check(s.store.Create(&bare), NotNil)

	got, err = s.store.Get("missing")
	c.Check(err, IsNil)
	c.Check(got, IsNil)
}

func (s *RuleStoreSuite) TestPersists(c *C) {
	rule := s.create(c, "alice", 0, "a-1")
	c.Assert(s.store.Close(), IsNil)
	var err error
	s.store, err = resigning.OpenRuleStore(s.path)
	c.Assert(err, IsNil)
	rules, err := s.store.List(resigning.RuleFilter{})
	c.Assert(err, IsNil)
	c.Check(ids(rules), DeepEquals, []string{rule.ID})
}

func (s *RuleStoreSuite) TestListFilters(c *C) {
	a1 := s.create(c, "alice", 0, "a-1")
	a2 := s.create(c, "alice", 0, "a-1", "b-1")
	b1 := s.create(c, "bob", 0, "b-1")

	for filter, expected := range map[resigning.RuleFilter][]string{
		{}:                                {a1.ID, a2.ID, b1.ID},
		{Owner: "alice"}:                  {a1.ID, a2.ID},
		{Owner: "carol"}:                  {},
		{SignWith: "b-1"}:                 {a2.ID, b1.ID},
		{Owner: "alice", SignWith: "b-1"}: {a2.ID},
		{ID: b1.ID}:                       {b1.ID},
		{ID: b1.ID, Owner: "alice"}:       {},
	} {
		rules, err := s.store.List(filter)
		c.Assert(err, IsNil)
		c.Check(ids(rules), DeepEquals, expected, Commentf("%+v", filter))
	}
}

func (s *RuleStoreSuite) TestDelete(c *C) {
	a1 := s.create(c, "alice", 0, "a-1")
	a2 := s.create(c, "alice", 0, "a-1", "b-1")
	b1 := s.create(c, "bob", 0, "b-1")

	deleted, err := s.store.Delete(resigning.RuleFilter{SignWith: "b-1"})
	c.Assert(err, IsNil)
	c.Check(ids(deleted), DeepEquals, []string{a2.ID, b1.ID})
	rules, err := s.store.List(resigning.RuleFilter{})
	c.Assert(err, IsNil)
	c.Check(ids(rules), DeepEquals, []string{a1.ID})

	deleted, err = s.store.Delete(resigning.RuleFilter{ID: "missing"})
	c.Assert(err, IsNil)
	c.Check(deleted, HasLen, 0)

	deleted, err = s.store.Delete(resigning.RuleFilter{})
	c.Assert(err, IsNil)
	c.Check(ids(deleted), DeepEquals, []string{a1.ID})
}

func (s *RuleStoreSuite) TestExpiry(c *C) {
	short := s.create(c, "alice", time.Minute, "a-1")
	long := s.create(c, "alice", time.Hour, "a-1")

	s.now = s.now.Add(time.Minute)
	rules, err := s.store.List(resigning.RuleFilter{})
	c.Assert(err, IsNil)
	c.Check(ids(rules), DeepEquals, []string{long.ID})
	got, err := s.store.Get(short.ID)
	c.Assert(err, IsNil)
	c.Check(got, IsNil)

	// Creating a rule prunes expired ones, so the expired rule's ID is free again.
	c.Check(s.store.Create(&resigning.Rule{ID: short.ID, Owner: "x", SignWith: []string{"a-1"}, Created: s.now}), IsNil)

	// Expired rules aren't reported as deleted, but are pruned.
	s.now = s.now.Add(time.Hour)
	deleted, err := s.store.Delete(resigning.RuleFilter{ID: long.ID})
	c.Assert(err, IsNil)
	c.Check(deleted, HasLen, 0)
	s.now = s.now.Add(-2 * time.Hour)
	rules, err = s.store.List(resigning.RuleFilter{Owner: "alice"})
	c.Assert(err, IsNil)
	c.Check(rules, HasLen, 0)
}
