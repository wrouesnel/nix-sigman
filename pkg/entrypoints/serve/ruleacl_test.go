package serve_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	. "gopkg.in/check.v1"
)

// fakeGroups answers group membership from a map of username to group DNs.
type fakeGroups struct {
	mtx     sync.Mutex
	members map[string][]string
	lookups []string
	err     error
}

func (f *fakeGroups) IsMemberOfAny(_ context.Context, username string, groupDNs []string) (bool, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.lookups = append(f.lookups, username)
	if f.err != nil {
		return false, f.err
	}
	return lo.SomeBy(groupDNs, func(dn string) bool { return slices.Contains(f.members[username], dn) }), nil
}

const (
	releaseGroupDN = "cn=release,ou=groups,dc=example,dc=com"
	adminGroupDN   = "cn=admins,ou=groups,dc=example,dc=com"
)

var testKeyNames = []string{"release-1", "release-2", "ops-1"}

type RuleACLSuite struct {
	groups *fakeGroups
}

var _ = Suite(&RuleACLSuite{})

func (s *RuleACLSuite) SetUpTest(c *C) {
	s.groups = &fakeGroups{members: map[string][]string{
		"carol": {releaseGroupDN},
		"dave":  {adminGroupDN},
	}}
}

func (s *RuleACLSuite) aclFile() serve.RuleACLFile {
	return serve.RuleACLFile{
		Admins: serve.ACLSubjects{Users: []string{"root"}, LDAPGroups: []string{adminGroupDN}},
		Grants: []serve.ACLGrant{
			{ACLSubjects: serve.ACLSubjects{Users: []string{"ci-*"}}, Keys: []string{"release-*"}},
			{ACLSubjects: serve.ACLSubjects{LDAPGroups: []string{releaseGroupDN}}, Keys: []string{"release-1"}},
			{ACLSubjects: serve.ACLSubjects{Users: []string{"ci-ops"}}, Keys: []string{"ops-1"}},
		},
	}
}

func (s *RuleACLSuite) TestAccess(c *C) {
	acl, err := serve.NewRuleACL(s.aclFile(), testKeyNames, s.groups, 0)
	c.Assert(err, IsNil)
	for username, expected := range map[string]serve.Access{
		"root":   {Admin: true, Keys: map[string]bool{}},
		"dave":   {Admin: true, Keys: map[string]bool{}},
		"ci-web": {Keys: map[string]bool{"release-1": true, "release-2": true}},
		"ci-ops": {Keys: map[string]bool{"release-1": true, "release-2": true, "ops-1": true}},
		// Kerberos principals are looked up in LDAP by their primary name.
		"carol@EXAMPLE.COM":       {Keys: map[string]bool{"release-1": true}},
		"carol/admin@EXAMPLE.COM": {Keys: map[string]bool{"release-1": true}},
		"mallory":                 {Keys: map[string]bool{}},
	} {
		access, err := acl.Access(context.Background(), username)
		c.Assert(err, IsNil)
		c.Check(access, DeepEquals, expected, Commentf(username))
		c.Check(access.CanManageRules(), Equals, expected.Admin || len(expected.Keys) > 0, Commentf(username))
	}
	c.Check(slices.Contains(s.groups.lookups, "carol"), Equals, true)
	c.Check(slices.Contains(s.groups.lookups, "carol@EXAMPLE.COM"), Equals, false)

	s.groups.err = errors.New("ldap down")
	_, err = acl.Access(context.Background(), "mallory")
	c.Check(err, ErrorMatches, "ldap down")
}

func (s *RuleACLSuite) TestAccessIsCached(c *C) {
	acl, err := serve.NewRuleACL(s.aclFile(), testKeyNames, s.groups, time.Hour)
	c.Assert(err, IsNil)
	access, err := acl.Access(context.Background(), "carol")
	c.Assert(err, IsNil)
	lookups := len(s.groups.lookups)
	c.Assert(lookups > 0, Equals, true)

	// Group membership changes aren't seen until the cache expires.
	s.groups.members["carol"] = nil
	cached, err := acl.Access(context.Background(), "carol")
	c.Assert(err, IsNil)
	c.Check(cached, DeepEquals, access)
	c.Check(s.groups.lookups, HasLen, lookups)
}

func (s *RuleACLSuite) TestValidation(c *C) {
	file := s.aclFile()
	_, err := serve.NewRuleACL(file, testKeyNames, nil, 0)
	c.Check(err, ErrorMatches, "(?s)admins: ldap_groups requires LDAP.*grant 2: ldap_groups requires LDAP.*")

	file = serve.RuleACLFile{
		Admins: serve.ACLSubjects{Users: []string{"[x"}},
		Grants: []serve.ACLGrant{
			{ACLSubjects: serve.ACLSubjects{Users: []string{"a"}}},
			{ACLSubjects: serve.ACLSubjects{Users: []string{"b"}}, Keys: []string{"missing-*"}},
			{ACLSubjects: serve.ACLSubjects{Users: []string{"c"}}, Keys: []string{"[x"}},
		},
	}
	_, err = serve.NewRuleACL(file, testKeyNames, nil, 0)
	c.Assert(err, NotNil)
	for _, msg := range []string{
		`admins: invalid user pattern "[x"`,
		`grant 1: no keys`,
		`grant 2: no loaded private key matches "missing-*"`,
		`grant 3: invalid key pattern "[x"`,
	} {
		c.Check(err.Error(), Matches, `(?s).*`+regexp.QuoteMeta(msg)+`.*`)
	}
}

func (s *RuleACLSuite) TestLoadRuleACL(c *C) {
	dir := c.MkDir()
	path := filepath.Join(dir, "acl.yml")
	c.Assert(os.WriteFile(path, []byte(`admins:
  users: [root]
grants:
  - users: [ci]
    ldap_groups: ["`+releaseGroupDN+`"]
    keys: [release-1]
`), 0o600), IsNil)
	acl, err := serve.LoadRuleACL(path, testKeyNames, s.groups, 0)
	c.Assert(err, IsNil)
	access, err := acl.Access(context.Background(), "carol")
	c.Assert(err, IsNil)
	c.Check(access.Keys, DeepEquals, map[string]bool{"release-1": true})

	// Unknown fields are rejected, so typos don't silently grant nothing.
	c.Assert(os.WriteFile(path, []byte("grants:\n  - user: [ci]\n    keys: [release-1]\n"), 0o600), IsNil)
	_, err = serve.LoadRuleACL(path, testKeyNames, s.groups, 0)
	c.Check(err, ErrorMatches, "(?s)could not parse rule ACL.*user.*")

	_, err = serve.LoadRuleACL(filepath.Join(dir, "missing.yml"), testKeyNames, s.groups, 0)
	c.Check(err, NotNil)
}
