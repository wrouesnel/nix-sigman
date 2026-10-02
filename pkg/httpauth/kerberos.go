package httpauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"go.uber.org/zap"
)

// KerberosConfig configures Kerberos authentication, either with SPNEGO (Negotiate) or by
// validating Basic auth credentials against the KDC.
type KerberosConfig struct {
	Keytab            string   `help:"Keytab for the HTTP service principal - enables Kerberos authentication" type:"existingfile"`
	ServicePrincipal  string   `help:"Service principal to authenticate as (e.g. HTTP/cache.example.com). Required for Basic auth, otherwise any key in the keytab is accepted"`
	Krb5Conf          string   `help:"Kerberos configuration file (used for Basic auth)" name:"krb5-conf" default:"/etc/krb5.conf"`
	BasicAuth         bool     `help:"Validate Basic auth credentials against the KDC (Nix clients can only send Basic auth)" default:"false"`
	AllowedPrincipal  []string `help:"Glob patterns of principals allowed to push (e.g. *@EXAMPLE.COM - * does not match the / of an instance)"`
	LDAPAuthorization bool     `help:"Authorize Kerberos principals by LDAP push group membership, matching the principal's primary name" default:"false"`
}

// KerberosAuthenticator authenticates Kerberos principals and authorizes them by
// principal pattern or with an external Authorizer.
type KerberosAuthenticator struct {
	cfg        KerberosConfig
	logger     *zap.Logger
	keytab     *keytab.Keytab
	krb5Conf   *config.Config
	sname      types.PrincipalName
	authorizer Authorizer
}

// NewKerberosAuthenticator loads the keytab (and krb5.conf if Basic auth is enabled).
// authorizer is used if LDAPAuthorization is set.
func NewKerberosAuthenticator(logger *zap.Logger, cfg KerberosConfig, authorizer Authorizer) (*KerberosAuthenticator, error) {
	kt, err := keytab.Load(cfg.Keytab)
	if err != nil {
		return nil, fmt.Errorf("could not load keytab: %w", err)
	}
	a := &KerberosAuthenticator{cfg: cfg, logger: logger, keytab: kt}

	if cfg.LDAPAuthorization {
		if authorizer == nil {
			return nil, errors.New("Kerberos LDAP authorization requires LDAP to be configured")
		}
		a.authorizer = authorizer
	} else if len(cfg.AllowedPrincipal) == 0 {
		return nil, errors.New("Kerberos authentication requires allowed principals or LDAP authorization")
	}
	for _, pattern := range cfg.AllowedPrincipal {
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("invalid principal pattern %q: %w", pattern, err)
		}
	}

	if cfg.ServicePrincipal != "" {
		a.sname, _ = types.ParseSPNString(cfg.ServicePrincipal)
	}

	if cfg.BasicAuth {
		if cfg.ServicePrincipal == "" {
			return nil, errors.New("Kerberos Basic auth requires a service principal")
		}
		a.krb5Conf, err = config.Load(cfg.Krb5Conf)
		if err != nil {
			return nil, fmt.Errorf("could not load %s: %w", cfg.Krb5Conf, err)
		}
	}
	return a, nil
}

func (a *KerberosAuthenticator) Name() string {
	return "kerberos"
}

// authorize checks whether an authenticated principal may push.
func (a *KerberosAuthenticator) authorize(ctx context.Context, username, realm string) (Result, error) {
	principal := username + "@" + realm
	for _, pattern := range a.cfg.AllowedPrincipal {
		if matched, _ := path.Match(pattern, principal); matched {
			return Allowed, nil
		}
	}
	if a.authorizer != nil {
		// Directory usernames don't include instances (user/admin) or realms.
		primary, _, _ := strings.Cut(username, "/")
		ok, err := a.authorizer.IsAuthorized(ctx, primary)
		if err != nil {
			return Denied, err
		}
		if ok {
			return Allowed, nil
		}
	}
	a.logger.Info("Kerberos principal is not allowed to push", zap.String("principal", principal))
	return Forbidden, nil
}

// Authenticate validates Basic auth credentials against the KDC. The username may
// include a realm, otherwise the default realm is used.
func (a *KerberosAuthenticator) Authenticate(ctx context.Context, username, password string) (Result, error) {
	if !a.cfg.BasicAuth || username == "" || password == "" {
		return Denied, nil
	}
	username, realm, found := strings.Cut(username, "@")
	if !found {
		realm = a.krb5Conf.LibDefaults.DefaultRealm
	}
	cl := client.NewWithPassword(username, realm, password, a.krb5Conf, client.DisablePAFXFAST(true))
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		a.logger.Info("Kerberos login failed", zap.String("username", username), zap.Error(err))
		return Denied, nil
	}
	// A successful AS exchange alone could come from a spoofed KDC: only one that knows
	// our service key can issue a ticket we can decrypt.
	ticket, _, err := cl.GetServiceTicket(a.cfg.ServicePrincipal)
	if err != nil {
		return Denied, fmt.Errorf("could not get service ticket for %s: %w", a.cfg.ServicePrincipal, err)
	}
	if err := ticket.DecryptEncPart(a.keytab, &a.sname); err != nil {
		return Denied, fmt.Errorf("could not verify service ticket: %w", err)
	}
	return a.authorize(ctx, username, realm)
}

// negotiate returns a handler performing SPNEGO authentication. Failures are answered by the SPNEGO
// handler; authenticated principals are authorized and the outcome passed to onResult.
func (a *KerberosAuthenticator) negotiate(onResult func(w http.ResponseWriter, r *http.Request, id Identity, result Result, err error)) http.Handler {
	settings := []func(*service.Settings){service.DecodePAC(false)}
	if a.cfg.ServicePrincipal != "" {
		settings = append(settings, service.KeytabPrincipal(a.cfg.ServicePrincipal))
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		krbId := goidentity.FromHTTPRequestContext(r)
		if krbId == nil || !krbId.Authenticated() {
			onResult(w, r, Identity{}, Denied, nil)
			return
		}
		result, err := a.authorize(r.Context(), krbId.UserName(), krbId.Domain())
		onResult(w, r, Identity{Username: krbId.UserName() + "@" + krbId.Domain(), Method: a.Name()}, result, err)
	})
	return spnego.SPNEGOKRB5Authenticate(inner, a.keytab, settings...)
}
