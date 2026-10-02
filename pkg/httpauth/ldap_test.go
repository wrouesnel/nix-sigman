package httpauth_test

import (
	"context"
	"errors"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

type bindCall struct {
	dn, password string
}

// fakeLDAP is an in-memory ldapConn. Users are keyed by DN with their password;
// groups are keyed by DN with the set of filters which match a member.
type fakeLDAP struct {
	users      map[string]string // dn -> password
	userSearch map[string]string // filter -> dn
	groups     map[string][]string
	searchErr  error
	bindErr    error

	binds    []bindCall
	searches []*ldap.SearchRequest
	closed   int
}

func (f *fakeLDAP) Bind(dn, password string) error {
	f.binds = append(f.binds, bindCall{dn, password})
	if f.bindErr != nil {
		return f.bindErr
	}
	if expected, ok := f.users[dn]; !ok || expected != password {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	}
	return nil
}

func (f *fakeLDAP) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches = append(f.searches, req)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	result := &ldap.SearchResult{}
	if req.Scope == ldap.ScopeWholeSubtree {
		if dn, ok := f.userSearch[req.Filter]; ok {
			result.Entries = append(result.Entries, &ldap.Entry{DN: dn})
		}
		return result, nil
	}
	members, ok := f.groups[req.BaseDN]
	if !ok {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	for _, m := range members {
		if m == req.Filter {
			result.Entries = append(result.Entries, &ldap.Entry{DN: req.BaseDN})
		}
	}
	return result, nil
}

func (f *fakeLDAP) Close() error {
	f.closed++
	return nil
}

const (
	aliceDN       = "uid=alice,ou=people,dc=example,dc=com"
	serviceDN     = "cn=svc,dc=example,dc=com"
	pushGroupDN   = "cn=push,ou=groups,dc=example,dc=com"
	otherGroupDN  = "cn=other,ou=groups,dc=example,dc=com"
	missingGroup  = "cn=gone,ou=groups,dc=example,dc=com"
	defaultFilter = "(|(member={dn})(uniqueMember={dn})(memberUid={username}))"
)

func memberFilter(dn, username string) string {
	return strings.NewReplacer("{dn}", ldap.EscapeFilter(dn), "{username}", ldap.EscapeFilter(username)).
		Replace(defaultFilter)
}

type LDAPSuite struct {
	fake  *fakeLDAP
	dials int
}

var _ = Suite(&LDAPSuite{})

func (s *LDAPSuite) SetUpTest(c *C) {
	s.dials = 0
	s.fake = &fakeLDAP{
		users:      map[string]string{aliceDN: "alice-pw", serviceDN: "svc-pw", "uid=bob,dc=example,dc=com": "bob-pw"},
		userSearch: map[string]string{"(uid=alice)": aliceDN, "(uid=bob)": "uid=bob,dc=example,dc=com"},
		groups: map[string][]string{
			pushGroupDN:  {memberFilter(aliceDN, "alice")},
			otherGroupDN: {},
		},
	}
}

func (s *LDAPSuite) baseConfig() httpauth.LDAPConfig {
	return httpauth.LDAPConfig{
		URL:         "ldap://127.0.0.1:1",
		UserBaseDN:  "ou=people,dc=example,dc=com",
		UserFilter:  "(uid={username})",
		GroupDN:     []string{pushGroupDN},
		GroupFilter: defaultFilter,
		Timeout:     10 * time.Second,
	}
}

func (s *LDAPSuite) newAuth(c *C, cfg httpauth.LDAPConfig) *httpauth.LDAPAuthenticator {
	a, err := httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Assert(err, IsNil)
	a.SetDial(func() (httpauth.LDAPConn, error) {
		s.dials++
		return s.fake, nil
	})
	return a
}

func (s *LDAPSuite) TestConfigValidation(c *C) {
	cfg := s.baseConfig()
	cfg.UserBaseDN = ""
	_, err := httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Check(err, ErrorMatches, ".*base DN.*")

	cfg = s.baseConfig()
	cfg.GroupDN = nil
	_, err = httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Check(err, ErrorMatches, ".*group DN.*")

	cfg = s.baseConfig()
	cfg.UserFilter = "(uid=alice)"
	_, err = httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Check(err, ErrorMatches, ".*must contain \\{username\\}.*")

	cfg = s.baseConfig()
	cfg.BindPasswordFile = filepath.Join(c.MkDir(), "missing")
	_, err = httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Check(err, NotNil)

	cfg = s.baseConfig()
	cfg.CACertFile = writeFile(c, c.MkDir(), "ca.pem", "not a certificate\n")
	_, err = httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Check(err, ErrorMatches, "no certificates found in .*")

	a, err := httpauth.NewLDAPAuthenticator(zap.NewNop(), s.baseConfig())
	c.Assert(err, IsNil)
	c.Check(a.Name(), Equals, "ldap")
}

func (s *LDAPSuite) TestBindPasswordFile(c *C) {
	cfg := s.baseConfig()
	cfg.BindPassword = "ignored"
	cfg.BindPasswordFile = writeFile(c, c.MkDir(), "pw", "svc-pw\r\n")
	a, err := httpauth.NewLDAPAuthenticator(zap.NewNop(), cfg)
	c.Assert(err, IsNil)
	c.Check(a.BindPassword(), Equals, "svc-pw")

	cfg.BindPasswordFile = writeFile(c, c.MkDir(), "pw", "svc-pw\n")
	cfg.BindDN = serviceDN
	a = s.newAuth(c, cfg)
	c.Check(a.BindPassword(), Equals, "svc-pw")
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Check(s.fake.binds[0], Equals, bindCall{serviceDN, "svc-pw"})
}

func (s *LDAPSuite) TestEmptyCredentialsDeniedWithoutDialing(c *C) {
	a := s.newAuth(c, s.baseConfig())
	for _, creds := range [][2]string{{"alice", ""}, {"", "alice-pw"}, {"", ""}} {
		result, err := a.Authenticate(context.Background(), creds[0], creds[1])
		c.Check(err, IsNil)
		c.Check(result, Equals, httpauth.Denied)
	}
	c.Check(s.dials, Equals, 0)
}

func (s *LDAPSuite) TestUserNotFound(c *C) {
	a := s.newAuth(c, s.baseConfig())
	result, err := a.Authenticate(context.Background(), "nobody", "pw")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
	c.Check(s.fake.binds, HasLen, 0)
	c.Check(s.fake.closed, Equals, 1)
}

func (s *LDAPSuite) TestAmbiguousUserDenied(c *C) {
	s.fake.searchErr = nil
	a := s.newAuth(c, s.baseConfig())
	a.SetDial(func() (httpauth.LDAPConn, error) {
		return &multiUserConn{s.fake}, nil
	})
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
	c.Check(s.fake.binds, HasLen, 0)
}

// multiUserConn returns two entries for every user search.
type multiUserConn struct{ *fakeLDAP }

func (m *multiUserConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	m.searches = append(m.searches, req)
	return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "uid=a,dc=x"}, {DN: "uid=b,dc=x"}}}, nil
}

func (s *LDAPSuite) TestWrongPassword(c *C) {
	a := s.newAuth(c, s.baseConfig())
	result, err := a.Authenticate(context.Background(), "alice", "wrong")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
	c.Check(s.fake.binds, DeepEquals, []bindCall{{aliceDN, "wrong"}})
	c.Check(s.fake.closed, Equals, 1)
}

func (s *LDAPSuite) TestBindOtherErrorIsReturned(c *C) {
	a := s.newAuth(c, s.baseConfig())
	s.fake.bindErr = ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable"))
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, NotNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *LDAPSuite) TestSizeLimitExceededDenied(c *C) {
	a := s.newAuth(c, s.baseConfig())
	s.fake.searchErr = ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit exceeded"))
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *LDAPSuite) TestSearchErrorIsReturned(c *C) {
	a := s.newAuth(c, s.baseConfig())
	s.fake.searchErr = errors.New("connection reset")
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, ErrorMatches, "connection reset")
	c.Check(result, Equals, httpauth.Denied)
}

func (s *LDAPSuite) TestAllowedMember(c *C) {
	a := s.newAuth(c, s.baseConfig())
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Check(s.dials, Equals, 1)
	c.Check(s.fake.closed, Equals, 1)
	c.Assert(s.fake.searches, HasLen, 2)
	user := s.fake.searches[0]
	c.Check(user.BaseDN, Equals, "ou=people,dc=example,dc=com")
	c.Check(user.Filter, Equals, "(uid=alice)")
	c.Check(user.Scope, Equals, ldap.ScopeWholeSubtree)
	c.Check(user.TimeLimit, Equals, 10)
	group := s.fake.searches[1]
	c.Check(group.BaseDN, Equals, pushGroupDN)
	c.Check(group.Scope, Equals, ldap.ScopeBaseObject)
}

func (s *LDAPSuite) TestNotMemberForbidden(c *C) {
	a := s.newAuth(c, s.baseConfig())
	result, err := a.Authenticate(context.Background(), "bob", "bob-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Forbidden)
}

func (s *LDAPSuite) TestMissingGroupSkipped(c *C) {
	cfg := s.baseConfig()
	cfg.GroupDN = []string{missingGroup, otherGroupDN, pushGroupDN}
	a := s.newAuth(c, cfg)
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Assert(s.fake.searches, HasLen, 4)
	c.Check(s.fake.searches[1].BaseDN, Equals, missingGroup)
	c.Check(s.fake.searches[2].BaseDN, Equals, otherGroupDN)
	c.Check(s.fake.searches[3].BaseDN, Equals, pushGroupDN)

	// Only missing groups: forbidden, not an error.
	cfg.GroupDN = []string{missingGroup}
	a = s.newAuth(c, cfg)
	result, err = a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Forbidden)
}

func (s *LDAPSuite) TestGroupSearchOtherErrorReturned(c *C) {
	a := s.newAuth(c, s.baseConfig())
	a.SetDial(func() (httpauth.LDAPConn, error) { return &groupErrConn{s.fake}, nil })
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, ErrorMatches, ".*busy.*")
	c.Check(result, Equals, httpauth.Denied)
}

// groupErrConn fails group searches with a non-NoSuchObject error.
type groupErrConn struct{ *fakeLDAP }

func (g *groupErrConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if req.Scope == ldap.ScopeBaseObject {
		return nil, ldap.NewError(ldap.LDAPResultBusy, errors.New("busy"))
	}
	return g.fakeLDAP.Search(req)
}

func (s *LDAPSuite) TestFilterEscaping(c *C) {
	a := s.newAuth(c, s.baseConfig())
	username := "a*)(uid=*"
	result, err := a.Authenticate(context.Background(), username, "pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
	c.Assert(s.fake.searches, HasLen, 1)
	c.Check(s.fake.searches[0].Filter, Equals, `(uid=a\2a\29\28uid=\2a)`)
}

func (s *LDAPSuite) TestServiceAccountRebind(c *C) {
	cfg := s.baseConfig()
	cfg.BindDN = serviceDN
	cfg.BindPassword = "svc-pw"
	a := s.newAuth(c, cfg)
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Check(s.fake.binds, DeepEquals, []bindCall{
		{serviceDN, "svc-pw"},
		{aliceDN, "alice-pw"},
		{serviceDN, "svc-pw"},
	})
}

func (s *LDAPSuite) TestServiceAccountBindFailure(c *C) {
	cfg := s.baseConfig()
	cfg.BindDN = serviceDN
	cfg.BindPassword = "wrong"
	a := s.newAuth(c, cfg)
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, NotNil)
	c.Check(result, Equals, httpauth.Denied)
	c.Check(s.fake.searches, HasLen, 0)
	c.Check(s.fake.closed, Equals, 1)
}

func (s *LDAPSuite) TestAnonymousSearchDoesNotRebind(c *C) {
	a := s.newAuth(c, s.baseConfig())
	_, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Assert(err, IsNil)
	c.Check(s.fake.binds, DeepEquals, []bindCall{{aliceDN, "alice-pw"}})
}

func (s *LDAPSuite) TestGroupFilterSubstitution(c *C) {
	cfg := s.baseConfig()
	cfg.GroupFilter = "(&(member={dn})(memberUid={username})(cn={username}))"
	dn := `uid=we*ird,ou=people,dc=example,dc=com`
	user := "we*ird"
	s.fake.users[dn] = "pw"
	s.fake.userSearch[`(uid=we\2aird)`] = dn
	a := s.newAuth(c, cfg)
	result, err := a.Authenticate(context.Background(), user, "pw")
	c.Assert(err, IsNil)
	c.Check(result, Equals, httpauth.Forbidden)
	c.Assert(s.fake.searches, HasLen, 2)
	c.Check(s.fake.searches[1].Filter, Equals,
		`(&(member=uid=we\2aird,ou=people,dc=example,dc=com)(memberUid=we\2aird)(cn=we\2aird))`)
}

func (s *LDAPSuite) TestIsAuthorized(c *C) {
	a := s.newAuth(c, s.baseConfig())
	ok, err := a.IsAuthorized(context.Background(), "alice")
	c.Check(err, IsNil)
	c.Check(ok, Equals, true)

	ok, err = a.IsAuthorized(context.Background(), "bob")
	c.Check(err, IsNil)
	c.Check(ok, Equals, false)

	ok, err = a.IsAuthorized(context.Background(), "nobody")
	c.Check(err, IsNil)
	c.Check(ok, Equals, false)

	// No user bind happens for authorization only.
	c.Check(s.fake.binds, HasLen, 0)
	c.Check(s.fake.closed, Equals, 3)

	s.fake.searchErr = errors.New("down")
	ok, err = a.IsAuthorized(context.Background(), "alice")
	c.Check(err, ErrorMatches, "down")
	c.Check(ok, Equals, false)
}

func (s *LDAPSuite) TestDialError(c *C) {
	a := s.newAuth(c, s.baseConfig())
	a.SetDial(func() (httpauth.LDAPConn, error) { return nil, errors.New("connection refused") })
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, ErrorMatches, "connection refused")
	c.Check(result, Equals, httpauth.Denied)

	ok, err := a.IsAuthorized(context.Background(), "alice")
	c.Check(err, ErrorMatches, "connection refused")
	c.Check(ok, Equals, false)
}

func (s *LDAPSuite) TestRealDialError(c *C) {
	// The default dialer against a closed port returns an error rather than panicking.
	a, err := httpauth.NewLDAPAuthenticator(zap.NewNop(), s.baseConfig())
	c.Assert(err, IsNil)
	result, err := a.Authenticate(context.Background(), "alice", "alice-pw")
	c.Check(err, NotNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *LDAPSuite) TestIsMemberOfAny(c *C) {
	a := s.newAuth(c, s.baseConfig())
	// The groups asked about are checked, not the configured push groups.
	ok, err := a.IsMemberOfAny(context.Background(), "alice", []string{missingGroup, otherGroupDN})
	c.Check(err, IsNil)
	c.Check(ok, Equals, false)
	ok, err = a.IsMemberOfAny(context.Background(), "alice", []string{otherGroupDN, pushGroupDN})
	c.Check(err, IsNil)
	c.Check(ok, Equals, true)
	ok, err = a.IsMemberOfAny(context.Background(), "nobody", []string{pushGroupDN})
	c.Check(err, IsNil)
	c.Check(ok, Equals, false)

	// No groups means no lookup.
	dials := s.dials
	ok, err = a.IsMemberOfAny(context.Background(), "alice", nil)
	c.Check(err, IsNil)
	c.Check(ok, Equals, false)
	c.Check(s.dials, Equals, dials)
}
