package httpauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// LDAPConfig configures authentication against an LDAP directory, with authorization
// by membership of one of a set of groups.
type LDAPConfig struct {
	URL                string        `help:"LDAP server URL (ldap:// or ldaps://) - enables LDAP authentication"`
	StartTLS           bool          `help:"Use StartTLS on ldap:// connections" default:"false"`
	CACertFile         string        `help:"CA certificate file for verifying the LDAP server" type:"existingfile"`
	InsecureSkipVerify bool          `help:"Don't verify the LDAP server certificate" default:"false"`
	BindDN             string        `help:"DN to bind as when searching (default: anonymous)"`
	BindPassword       string        `help:"Password for the bind DN"`
	BindPasswordFile   string        `help:"File containing the password for the bind DN" type:"existingfile"`
	UserBaseDN         string        `help:"Base DN to search for users"`
	UserFilter         string        `help:"Filter to find a user - {username} is replaced with the username" default:"(uid={username})"`
	GroupDN            []string      `help:"DNs of groups whose members are allowed to push (repeat, or separate with ;)" sep:";"`
	GroupFilter        string        `help:"Filter applied to each group to check membership - {dn} and {username} are replaced" default:"(|(member={dn})(uniqueMember={dn})(memberUid={username}))"`
	Timeout            time.Duration `help:"LDAP operation timeout" default:"10s"`
}

// ldapConn is the subset of *ldap.Conn used, to allow testing without a server.
type ldapConn interface {
	Bind(username, password string) error
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPAuthenticator authenticates users by binding as them, and authorizes them by
// group membership.
type LDAPAuthenticator struct {
	cfg          LDAPConfig
	bindPassword string
	logger       *zap.Logger
	dial         func() (ldapConn, error)
}

// NewLDAPAuthenticator validates the configuration and prepares the connection settings.
func NewLDAPAuthenticator(logger *zap.Logger, cfg LDAPConfig) (*LDAPAuthenticator, error) {
	if cfg.UserBaseDN == "" {
		return nil, errors.New("an LDAP user base DN is required")
	}
	if len(cfg.GroupDN) == 0 {
		return nil, errors.New("at least one LDAP group DN is required to authorize pushes")
	}
	if !strings.Contains(cfg.UserFilter, "{username}") {
		return nil, errors.New("the LDAP user filter must contain {username}")
	}

	a := &LDAPAuthenticator{cfg: cfg, bindPassword: cfg.BindPassword, logger: logger}
	if cfg.BindPasswordFile != "" {
		password, err := os.ReadFile(cfg.BindPasswordFile)
		if err != nil {
			return nil, err
		}
		a.bindPassword = strings.TrimRight(string(password), "\r\n")
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CACertFile)
		}
		tlsConfig.RootCAs = pool
	}

	a.dial = func() (ldapConn, error) {
		conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, err
		}
		conn.SetTimeout(cfg.Timeout)
		if cfg.StartTLS {
			if err := conn.StartTLS(tlsConfig); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	return a, nil
}

func (a *LDAPAuthenticator) Name() string {
	return "ldap"
}

// connect dials and binds as the search account.
func (a *LDAPAuthenticator) connect() (ldapConn, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	if err := a.bindSearch(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (a *LDAPAuthenticator) bindSearch(conn ldapConn) error {
	if a.cfg.BindDN == "" {
		return nil
	}
	return conn.Bind(a.cfg.BindDN, a.bindPassword)
}

// findUser returns the DN of the user, or "" if there isn't exactly one match.
func (a *LDAPAuthenticator) findUser(conn ldapConn, username string) (string, error) {
	result, err := conn.Search(ldap.NewSearchRequest(a.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(a.cfg.Timeout.Seconds()), false,
		strings.ReplaceAll(a.cfg.UserFilter, "{username}", ldap.EscapeFilter(username)),
		[]string{"dn"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		// More than one match: ambiguous, so not a valid user.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(result.Entries) != 1 {
		return "", nil
	}
	return result.Entries[0].DN, nil
}

// isGroupMember checks whether the user DN is a member of any of the push groups.
func (a *LDAPAuthenticator) isGroupMember(conn ldapConn, username string, userDN string) (bool, error) {
	filter := strings.NewReplacer("{dn}", ldap.EscapeFilter(userDN), "{username}", ldap.EscapeFilter(username)).
		Replace(a.cfg.GroupFilter)
	for _, groupDN := range a.cfg.GroupDN {
		result, err := conn.Search(ldap.NewSearchRequest(groupDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(a.cfg.Timeout.Seconds()), false,
			filter, []string{"dn"}, nil))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				a.logger.Warn("Configured LDAP push group does not exist", zap.String("group_dn", groupDN))
				continue
			}
			return false, err
		}
		if len(result.Entries) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// Authenticate binds as the user to check their password, then checks group membership.
func (a *LDAPAuthenticator) Authenticate(_ context.Context, username, password string) (Result, error) {
	// An empty password is an unauthenticated bind, which many servers accept.
	if username == "" || password == "" {
		return Denied, nil
	}
	conn, err := a.connect()
	if err != nil {
		return Denied, err
	}
	defer conn.Close()

	userDN, err := a.findUser(conn, username)
	if err != nil || userDN == "" {
		return Denied, err
	}
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Denied, nil
		}
		return Denied, err
	}
	// Group searches may need the search account's privileges.
	if err := a.bindSearch(conn); err != nil {
		return Denied, err
	}
	member, err := a.isGroupMember(conn, username, userDN)
	if err != nil {
		return Denied, err
	}
	if !member {
		a.logger.Info("LDAP user is not in a push group", zap.String("username", username))
		return Forbidden, nil
	}
	return Allowed, nil
}

// IsAuthorized checks group membership for a user authenticated by another method.
func (a *LDAPAuthenticator) IsAuthorized(_ context.Context, username string) (bool, error) {
	conn, err := a.connect()
	if err != nil {
		return false, err
	}
	defer conn.Close()
	userDN, err := a.findUser(conn, username)
	if err != nil || userDN == "" {
		return false, err
	}
	return a.isGroupMember(conn, username, userDN)
}
