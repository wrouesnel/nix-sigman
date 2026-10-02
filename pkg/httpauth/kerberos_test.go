package httpauth_test

import (
	"context"
	"errors"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"os"
	"path/filepath"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// writeKeytab writes a keytab for HTTP/cache.example.com@EXAMPLE.COM.
func writeKeytab(c *C) string {
	kt := keytab.New()
	c.Assert(kt.AddEntry("HTTP/cache.example.com", "EXAMPLE.COM", "password", time.Now(), 1,
		etypeID.AES256_CTS_HMAC_SHA1_96), IsNil)
	data, err := kt.Marshal()
	c.Assert(err, IsNil)
	p := filepath.Join(c.MkDir(), "http.keytab")
	c.Assert(os.WriteFile(p, data, 0o600), IsNil)
	return p
}

type fakeAuthorizer struct {
	allowed map[string]bool
	err     error
	calls   []string
}

func (f *fakeAuthorizer) IsAuthorized(_ context.Context, username string) (bool, error) {
	f.calls = append(f.calls, username)
	if f.err != nil {
		return false, f.err
	}
	return f.allowed[username], nil
}

type KerberosSuite struct {
	keytab string
}

var _ = Suite(&KerberosSuite{})

func (s *KerberosSuite) SetUpSuite(c *C) {
	s.keytab = writeKeytab(c)
}

func (s *KerberosSuite) TestMissingKeytab(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           filepath.Join(c.MkDir(), "missing.keytab"),
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
	}, nil)
	c.Check(err, ErrorMatches, "could not load keytab: .*")
}

func (s *KerberosSuite) TestInvalidKeytab(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           writeFile(c, c.MkDir(), "bad.keytab", "garbage"),
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
	}, nil)
	c.Check(err, ErrorMatches, "could not load keytab: .*")
}

func (s *KerberosSuite) TestRequiresAuthorization(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{Keytab: s.keytab}, nil)
	c.Check(err, ErrorMatches, ".*requires allowed principals or LDAP authorization")

	// An authorizer passed without LDAPAuthorization doesn't count.
	_, err = httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{Keytab: s.keytab}, &fakeAuthorizer{})
	c.Check(err, ErrorMatches, ".*requires allowed principals or LDAP authorization")
}

func (s *KerberosSuite) TestLDAPAuthorizationRequiresAuthorizer(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{Keytab: s.keytab, LDAPAuthorization: true}, nil)
	c.Check(err, ErrorMatches, ".*requires LDAP to be configured")

	a, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{Keytab: s.keytab, LDAPAuthorization: true},
		&fakeAuthorizer{})
	c.Assert(err, IsNil)
	c.Check(a.Name(), Equals, "kerberos")
}

func (s *KerberosSuite) TestBasicAuthRequiresServicePrincipal(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           s.keytab,
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
		BasicAuth:        true,
	}, nil)
	c.Check(err, ErrorMatches, ".*requires a service principal")
}

func (s *KerberosSuite) TestBasicAuthLoadsKrb5Conf(c *C) {
	cfg := httpauth.KerberosConfig{
		Keytab:           s.keytab,
		ServicePrincipal: "HTTP/cache.example.com",
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
		BasicAuth:        true,
		Krb5Conf:         filepath.Join(c.MkDir(), "missing.conf"),
	}
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), cfg, nil)
	c.Check(err, ErrorMatches, "could not load .*missing.conf: .*")

	cfg.Krb5Conf = writeFile(c, c.MkDir(), "krb5.conf", `[libdefaults]
  default_realm = EXAMPLE.COM
[realms]
  EXAMPLE.COM = {
    kdc = 127.0.0.1:1
  }
`)
	a, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), cfg, nil)
	c.Assert(err, IsNil)
	c.Check(a.DefaultRealm(), Equals, "EXAMPLE.COM")
	c.Check(a.ServiceName(), Equals, "HTTP/cache.example.com")

	// Empty credentials are rejected without contacting the KDC.
	result, err := a.Authenticate(context.Background(), "alice", "")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
	result, err = a.Authenticate(context.Background(), "", "pw")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *KerberosSuite) TestInvalidPattern(c *C) {
	_, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           s.keytab,
		AllowedPrincipal: []string{"*@EXAMPLE.COM", "[@EXAMPLE.COM"},
	}, nil)
	c.Check(err, ErrorMatches, `invalid principal pattern "\[@EXAMPLE.COM": .*`)
}

func (s *KerberosSuite) TestAuthenticateBasicDisabled(c *C) {
	a, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           s.keytab,
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
	}, nil)
	c.Assert(err, IsNil)
	result, err := a.Authenticate(context.Background(), "alice@EXAMPLE.COM", "password")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Denied)
}

func (s *KerberosSuite) TestAuthorizeGlob(c *C) {
	a, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           s.keytab,
		AllowedPrincipal: []string{"*@EXAMPLE.COM", "bob@OTHER.COM"},
	}, nil)
	c.Assert(err, IsNil)
	ctx := context.Background()
	cases := []struct {
		user, realm string
		expected    httpauth.Result
	}{
		{"alice", "EXAMPLE.COM", httpauth.Allowed},
		{"alice", "OTHER.COM", httpauth.Forbidden},
		{"bob", "OTHER.COM", httpauth.Allowed},
		{"alice", "EXAMPLE.COM.EVIL", httpauth.Forbidden},
		{"alice", "example.com", httpauth.Forbidden},
	}
	for _, tc := range cases {
		result, err := a.Authorize(ctx, tc.user, tc.realm)
		c.Check(err, IsNil)
		c.Check(result, Equals, tc.expected, Commentf("%s@%s", tc.user, tc.realm))
	}
}

func (s *KerberosSuite) TestAuthorizeWithAuthorizer(c *C) {
	authz := &fakeAuthorizer{allowed: map[string]bool{"alice": true}}
	a, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:            s.keytab,
		AllowedPrincipal:  []string{"svc@EXAMPLE.COM"},
		LDAPAuthorization: true,
	}, authz)
	c.Assert(err, IsNil)
	ctx := context.Background()

	// Pattern matches don't consult the authorizer.
	result, err := a.Authorize(ctx, "svc", "EXAMPLE.COM")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Check(authz.calls, HasLen, 0)

	result, err = a.Authorize(ctx, "alice/admin", "EXAMPLE.COM")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)
	c.Check(authz.calls, DeepEquals, []string{"alice"})

	result, err = a.Authorize(ctx, "alice", "EXAMPLE.COM")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Allowed)

	result, err = a.Authorize(ctx, "bob", "EXAMPLE.COM")
	c.Check(err, IsNil)
	c.Check(result, Equals, httpauth.Forbidden)
	c.Check(authz.calls, DeepEquals, []string{"alice", "alice", "bob"})

	authz.err = errors.New("ldap down")
	result, err = a.Authorize(ctx, "alice", "EXAMPLE.COM")
	c.Check(err, ErrorMatches, "ldap down")
	c.Check(result, Equals, httpauth.Denied)
}
