package serve_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"time"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// fakeBasic accepts any user whose password is "pw".
type fakeBasic struct{}

func (fakeBasic) Name() string { return "fake" }

func (fakeBasic) Authenticate(_ context.Context, _, password string) (httpauth.Result, error) {
	return lo.Ternary(password == "pw", httpauth.Allowed, httpauth.Denied), nil
}

var testRuleACL = serve.RuleACLFile{
	Admins: serve.ACLSubjects{Users: []string{"admin"}},
	Grants: []serve.ACLGrant{
		{ACLSubjects: serve.ACLSubjects{Users: []string{"ci", "ci2"}}, Keys: []string{"release-1"}},
	},
}

type RulesSuite struct {
	release  nixtypes.NamedPrivateKey
	other    nixtypes.NamedPrivateKey
	upstream nixtypes.NamedPrivateKey

	store   *resigning.RuleStore
	manager *serve.RuleManager
	handler *serve.NixHandler
	now     time.Time
}

var _ = Suite(&RulesSuite{})

func (s *RulesSuite) SetUpSuite(c *C) {
	var err error
	s.release, err = nixtypes.GeneratePrivateKey("release-1")
	c.Assert(err, IsNil)
	s.other, err = nixtypes.GeneratePrivateKey("other-1")
	c.Assert(err, IsNil)
	s.upstream, err = nixtypes.GeneratePrivateKey("upstream-1")
	c.Assert(err, IsNil)
}

func (s *RulesSuite) SetUpTest(c *C) {
	var err error
	s.store, err = resigning.OpenRuleStore(filepath.Join(c.MkDir(), "rules.sqlite"))
	c.Assert(err, IsNil)
	s.now = time.Now()
	s.setUpManager(c, testRuleACL, 0, s.release, s.other)
}

// setUpManager replaces the rule manager, keeping the rule store.
func (s *RulesSuite) setUpManager(c *C, file serve.RuleACLFile, maxTTL time.Duration, keys ...nixtypes.NamedPrivateKey) {
	acl, err := serve.NewRuleACL(file, lo.Map(keys, func(k nixtypes.NamedPrivateKey, _ int) string { return k.KeyName }), nil, 0)
	c.Assert(err, IsNil)
	s.manager = serve.NewRuleManager(zap.NewNop(), s.store, acl, keys,
		[]nixtypes.NamedPublicKey{s.upstream.PublicKey()}, maxTTL)
	s.manager.SetClock(func() time.Time { return s.now })
	auth := httpauth.NewMiddleware(zap.NewNop(), "test", 0, nil, fakeBasic{})
	s.handler = &serve.NixHandler{
		Logger:    zap.NewNop(),
		StorePath: nixstore.DefaultStorePath,
		StartTime: time.Now(),
		Store:     &fakeStore{registrationTime: time.Now()},
		Rules:     auth.Wrap(s.manager),
	}
}

func (s *RulesSuite) TearDownTest(c *C) {
	c.Check(s.store.Close(), IsNil)
}

// do makes a request as user (with no credentials if user is empty).
func (s *RulesSuite) do(user string, method string, target string, body any) *httptest.ResponseRecorder {
	var encoded []byte
	switch b := body.(type) {
	case nil:
	case string:
		encoded = []byte(b)
	default:
		encoded, _ = json.Marshal(b)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	if user != "" {
		req.SetBasicAuth(user, "pw")
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func decode[T any](c *C, rec *httptest.ResponseRecorder) T {
	var v T
	c.Assert(json.Unmarshal(rec.Body.Bytes(), &v), IsNil, Commentf("%s", rec.Body.String()))
	return v
}

type listResponse struct {
	Rules []resigning.Rule `json:"rules"`
}

type deleteResponse struct {
	Deleted int              `json:"deleted"`
	Rules   []resigning.Rule `json:"rules"`
}

func (s *RulesSuite) create(c *C, user string, body map[string]any) resigning.Rule {
	rec := s.do(user, http.MethodPost, serve.RulesAPIPath, body)
	c.Assert(rec.Code, Equals, http.StatusCreated, Commentf("%s", rec.Body.String()))
	rule := decode[resigning.Rule](c, rec)
	c.Check(rec.Header().Get("Location"), Equals, serve.RulesAPIPath+"/"+rule.ID)
	// Keep creation order distinct, since rules are listed oldest first.
	s.now = s.now.Add(time.Millisecond)
	return rule
}

func (s *RulesSuite) list(c *C, user string, query string) []resigning.Rule {
	rec := s.do(user, http.MethodGet, serve.RulesAPIPath+query, nil)
	c.Assert(rec.Code, Equals, http.StatusOK, Commentf("%s", rec.Body.String()))
	return decode[listResponse](c, rec).Rules
}

func ruleIDs(rules []resigning.Rule) []string {
	return lo.Map(rules, func(r resigning.Rule, _ int) string { return r.ID })
}

func (s *RulesSuite) TestAuthentication(c *C) {
	c.Check(s.do("", http.MethodGet, serve.RulesAPIPath, nil).Code, Equals, http.StatusUnauthorized)
	req := httptest.NewRequest(http.MethodGet, serve.RulesAPIPath, nil)
	req.SetBasicAuth("ci", "wrong")
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	c.Check(rec.Code, Equals, http.StatusUnauthorized)
	// Users with no grants can't use the API at all.
	c.Check(s.do("nobody", http.MethodGet, serve.RulesAPIPath, nil).Code, Equals, http.StatusForbidden)

	// Without an identity (e.g. the manager mounted without auth) requests are refused.
	rec = httptest.NewRecorder()
	s.manager.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, serve.RulesAPIPath, nil))
	c.Check(rec.Code, Equals, http.StatusUnauthorized)

	// The API is only served when enabled.
	s.handler.Rules = nil
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath, nil).Code, Equals, http.StatusNotFound)
}

func (s *RulesSuite) TestCreateGetDelete(c *C) {
	rule := s.create(c, "ci", map[string]any{
		"description": "release builds",
		"condition":   map[string]any{"name": "bash-*"},
		"sign_with":   []string{"release-1"},
	})
	c.Check(rule.Owner, Equals, "ci")
	c.Check(rule.Description, Equals, "release builds")
	c.Check(rule.Condition, DeepEquals, &resigning.Condition{Name: "bash-*"})
	c.Check(rule.SignWith, DeepEquals, []string{"release-1"})
	c.Check(rule.Expires, IsNil)

	c.Check(ruleIDs(s.list(c, "ci", "")), DeepEquals, []string{rule.ID})

	rec := s.do("ci", http.MethodGet, serve.RulesAPIPath+"/"+rule.ID, nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(decode[resigning.Rule](c, rec).ID, Equals, rule.ID)

	rec = s.do("ci", http.MethodDelete, serve.RulesAPIPath+"/"+rule.ID+"/", nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(decode[deleteResponse](c, rec).Deleted, Equals, 1)
	c.Check(s.list(c, "ci", ""), HasLen, 0)
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath+"/"+rule.ID, nil).Code, Equals, http.StatusNotFound)
	c.Check(s.do("ci", http.MethodDelete, serve.RulesAPIPath+"/"+rule.ID, nil).Code, Equals, http.StatusNotFound)
}

func (s *RulesSuite) TestCreateValidation(c *C) {
	for _, tc := range []struct {
		body any
		code int
	}{
		{"{", http.StatusBadRequest},
		{`{"sign_with":["release-1"],"owner":"admin"}`, http.StatusBadRequest},
		{map[string]any{}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"missing-1"}}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"other-1"}}, http.StatusForbidden},
		{map[string]any{"sign_with": []string{"release-1", "other-1"}}, http.StatusForbidden},
		{map[string]any{"sign_with": []string{"release-1"}, "condition": map[string]any{}}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"release-1"}, "condition": map[string]any{"signed_by": "missing-1"}}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"release-1"}, "expires_in": "soon"}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"release-1"}, "expires_in": "-1h"}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"release-1"}, "expires_at": s.now.Add(-time.Minute)}, http.StatusBadRequest},
		{map[string]any{"sign_with": []string{"release-1"}, "expires_in": "1h", "expires_at": s.now.Add(time.Hour)}, http.StatusBadRequest},
	} {
		rec := s.do("ci", http.MethodPost, serve.RulesAPIPath, tc.body)
		c.Check(rec.Code, Equals, tc.code, Commentf("%v: %s", tc.body, rec.Body.String()))
	}
	c.Check(s.list(c, "ci", ""), HasLen, 0)

	// Conditions can refer to the public halves of our own keys.
	s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"},
		"condition": map[string]any{"not": map[string]any{"signed_by": "other-1"}}})
}

func (s *RulesSuite) TestExpiry(c *C) {
	rule := s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}, "expires_in": "1m"})
	c.Assert(rule.Expires, NotNil)
	c.Check(rule.Expires.Equal(rule.Created.Add(time.Minute)), Equals, true)
	at := s.now.Add(time.Hour).Truncate(time.Second)
	rule = s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}, "expires_at": at})
	c.Check(rule.Expires.Equal(at), Equals, true)

	s.now = s.now.Add(2 * time.Minute)
	c.Check(ruleIDs(s.list(c, "ci", "")), DeepEquals, []string{rule.ID})
	s.now = s.now.Add(time.Hour)
	c.Check(s.list(c, "ci", ""), HasLen, 0)
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath+"/"+rule.ID, nil).Code, Equals, http.StatusNotFound)
}

func (s *RulesSuite) TestMaxTTL(c *C) {
	s.setUpManager(c, testRuleACL, time.Hour, s.release, s.other)
	// Rules get the maximum lifetime by default.
	rule := s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}})
	c.Assert(rule.Expires, NotNil)
	c.Check(rule.Expires.Equal(rule.Created.Add(time.Hour)), Equals, true)
	s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}, "expires_in": "30m"})

	for _, body := range []map[string]any{
		{"sign_with": []string{"release-1"}, "expires_in": "2h"},
		{"sign_with": []string{"release-1"}, "expires_at": s.now.Add(2 * time.Hour)},
	} {
		rec := s.do("ci", http.MethodPost, serve.RulesAPIPath, body)
		c.Check(rec.Code, Equals, http.StatusBadRequest, Commentf("%v", body))
	}
}

func (s *RulesSuite) TestOwnership(c *C) {
	mine := s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}})
	theirs := s.create(c, "ci2", map[string]any{"sign_with": []string{"release-1"}})

	// Users only see and delete their own rules.
	c.Check(ruleIDs(s.list(c, "ci", "")), DeepEquals, []string{mine.ID})
	c.Check(ruleIDs(s.list(c, "ci", "?owner=ci")), DeepEquals, []string{mine.ID})
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath+"?owner=ci2", nil).Code, Equals, http.StatusForbidden)
	c.Check(s.do("ci", http.MethodDelete, serve.RulesAPIPath+"?owner=ci2", nil).Code, Equals, http.StatusForbidden)
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath+"/"+theirs.ID, nil).Code, Equals, http.StatusNotFound)
	c.Check(s.do("ci", http.MethodDelete, serve.RulesAPIPath+"/"+theirs.ID, nil).Code, Equals, http.StatusNotFound)

	// A user's bulk delete only touches their own rules.
	rec := s.do("ci", http.MethodDelete, serve.RulesAPIPath, nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(ruleIDs(decode[deleteResponse](c, rec).Rules), DeepEquals, []string{mine.ID})
	c.Check(ruleIDs(s.list(c, "ci2", "")), DeepEquals, []string{theirs.ID})

	// Admins see and manage everyone's rules, but can't create rules without grants.
	c.Check(ruleIDs(s.list(c, "admin", "")), DeepEquals, []string{theirs.ID})
	c.Check(s.do("admin", http.MethodGet, serve.RulesAPIPath+"/"+theirs.ID, nil).Code, Equals, http.StatusOK)
	c.Check(s.do("admin", http.MethodPost, serve.RulesAPIPath,
		map[string]any{"sign_with": []string{"release-1"}}).Code, Equals, http.StatusForbidden)
	c.Check(s.do("admin", http.MethodDelete, serve.RulesAPIPath+"/"+theirs.ID, nil).Code, Equals, http.StatusOK)
	c.Check(s.list(c, "ci2", ""), HasLen, 0)
}

func (s *RulesSuite) TestBulkDelete(c *C) {
	file := serve.RuleACLFile{
		Admins: testRuleACL.Admins,
		Grants: []serve.ACLGrant{{ACLSubjects: serve.ACLSubjects{Users: []string{"ci*"}}, Keys: []string{"*"}}},
	}
	s.setUpManager(c, file, 0, s.release, s.other)
	a := s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}})
	b := s.create(c, "ci", map[string]any{"sign_with": []string{"other-1", "release-1"}})
	other := s.create(c, "ci", map[string]any{"sign_with": []string{"other-1"}})
	d := s.create(c, "ci2", map[string]any{"sign_with": []string{"release-1"}})

	// Admins have to say what to delete.
	c.Check(s.do("admin", http.MethodDelete, serve.RulesAPIPath, nil).Code, Equals, http.StatusBadRequest)

	rec := s.do("admin", http.MethodDelete, serve.RulesAPIPath+"?sign_with=release-1&owner=ci", nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(ruleIDs(decode[deleteResponse](c, rec).Rules), DeepEquals, []string{a.ID, b.ID})

	rec = s.do("admin", http.MethodDelete, serve.RulesAPIPath+"?sign_with=release-1", nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(ruleIDs(decode[deleteResponse](c, rec).Rules), DeepEquals, []string{d.ID})
	c.Check(ruleIDs(s.list(c, "admin", "")), DeepEquals, []string{other.ID})

	rec = s.do("admin", http.MethodDelete, serve.RulesAPIPath+"?all=true", nil)
	c.Assert(rec.Code, Equals, http.StatusOK)
	c.Check(decode[deleteResponse](c, rec).Deleted, Equals, 1)
}

func (s *RulesSuite) TestMethods(c *C) {
	rec := s.do("ci", http.MethodPut, serve.RulesAPIPath, nil)
	c.Check(rec.Code, Equals, http.StatusMethodNotAllowed)
	c.Check(rec.Header().Get("Allow"), Equals, "GET, POST, DELETE")
	rec = s.do("ci", http.MethodPost, serve.RulesAPIPath+"/abc", nil)
	c.Check(rec.Code, Equals, http.StatusMethodNotAllowed)
	c.Check(rec.Header().Get("Allow"), Equals, "GET, DELETE")
	c.Check(s.do("ci", http.MethodGet, serve.RulesAPIPath+"/abc/def", nil).Code, Equals, http.StatusMethodNotAllowed)
}

// pushedNarInfo is a narinfo for the path the push tests upload.
func pushedNarInfo(c *C) *nixtypes.NarInfo {
	ninfo := new(nixtypes.NarInfo)
	c.Assert(ninfo.UnmarshalText(narInfo(c, "nar/upload.nar", "none", []byte("nar!"), []byte("nar!"))), IsNil)
	return ninfo
}

func (s *RulesSuite) TestSignPushed(c *C) {
	s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"},
		"condition": map[string]any{"name": "bash-*"}})
	ctx := context.Background()

	ninfo := pushedNarInfo(c)
	signed, err := s.manager.SignPushed(ctx, "ci", ninfo)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, true)
	valid, _ := ninfo.Verify(s.release.PublicKey())
	c.Check(valid, Equals, true)
	c.Check(ninfo.Sig, HasLen, 1)

	// Signing again adds nothing.
	signed, err = s.manager.SignPushed(ctx, "ci", ninfo)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)

	// Rules only apply to their owner's pushes, and to paths matching the condition.
	for _, owner := range []string{"ci2", "admin", ""} {
		ninfo = pushedNarInfo(c)
		signed, err = s.manager.SignPushed(ctx, owner, ninfo)
		c.Assert(err, IsNil)
		c.Check(signed, Equals, false, Commentf(owner))
		c.Check(ninfo.Sig, HasLen, 0)
	}
	ninfo = pushedNarInfo(c)
	ninfo.StorePath = nixstore.DefaultStorePath + "/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-zsh-5.9"
	signed, err = s.manager.SignPushed(ctx, "ci", ninfo)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)
}

func (s *RulesSuite) TestSignPushedRechecksGrants(c *C) {
	s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}})
	ctx := context.Background()

	// The owner's grant was revoked after the rule was created.
	s.setUpManager(c, serve.RuleACLFile{Grants: []serve.ACLGrant{
		{ACLSubjects: serve.ACLSubjects{Users: []string{"ci"}}, Keys: []string{"other-1"}},
	}}, 0, s.release, s.other)
	ninfo := pushedNarInfo(c)
	signed, err := s.manager.SignPushed(ctx, "ci", ninfo)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)

	// The key is no longer loaded.
	s.setUpManager(c, serve.RuleACLFile{Grants: []serve.ACLGrant{
		{ACLSubjects: serve.ACLSubjects{Users: []string{"ci"}}, Keys: []string{"*"}},
	}}, 0, s.other)
	signed, err = s.manager.SignPushed(ctx, "ci", ninfo)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)
	c.Check(ninfo.Sig, HasLen, 0)
}

func (s *RulesSuite) TestSignPushedIgnoresExpiredRules(c *C) {
	s.create(c, "ci", map[string]any{"sign_with": []string{"release-1"}, "expires_in": "1m"})
	s.now = s.now.Add(time.Minute)
	signed, err := s.manager.SignPushed(context.Background(), "ci", pushedNarInfo(c))
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)
}

func basicAuth(user string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":pw"))
}
