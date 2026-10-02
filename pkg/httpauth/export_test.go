package httpauth

import "context"

// Test-only access to unexported internals for the external httpauth_test package
// (which can't be an internal package because gocheck's dot-import exports Result).

type LDAPConn = ldapConn

const (
	Argon2SaltLen = argon2SaltLen
	Argon2KeyLen  = argon2KeyLen
)

func (a *LDAPAuthenticator) SetDial(dial func() (LDAPConn, error)) { a.dial = dial }

func (a *LDAPAuthenticator) BindPassword() string { return a.bindPassword }

func (a *KerberosAuthenticator) Authorize(ctx context.Context, username, realm string) (Result, error) {
	return a.authorize(ctx, username, realm)
}

func (a *KerberosAuthenticator) DefaultRealm() string { return a.krb5Conf.LibDefaults.DefaultRealm }

func (a *KerberosAuthenticator) ServiceName() string { return a.sname.PrincipalNameString() }
