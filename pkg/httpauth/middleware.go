// Package httpauth implements HTTP authentication for pushing to the binary cache, with
// argon2 password files, LDAP and Kerberos backends.
package httpauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Result is the outcome of an authentication attempt.
type Result int

const (
	// Denied means the credentials were not valid.
	Denied Result = iota
	// Forbidden means the credentials were valid but the user isn't allowed access.
	Forbidden
	// Allowed means the user is authenticated and authorized.
	Allowed
)

// BasicAuthenticator validates a username and password.
type BasicAuthenticator interface {
	Name() string
	Authenticate(ctx context.Context, username, password string) (Result, error)
}

// Authorizer checks whether a user authenticated by some other means is allowed access.
type Authorizer interface {
	IsAuthorized(ctx context.Context, username string) (bool, error)
}

// Identity is an authenticated user.
type Identity struct {
	Username string
	// Method is the name of the authenticator which accepted the user.
	Method string
}

type identityKey struct{}

// IdentityFromContext returns the identity added by the Middleware.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

type cacheEntry struct {
	identity Identity
	expires  time.Time
}

// Middleware requires requests to be authenticated by one of its backends.
type Middleware struct {
	logger   *zap.Logger
	realm    string
	basic    []BasicAuthenticator
	kerberos *KerberosAuthenticator
	cacheTTL time.Duration

	cacheMtx sync.Mutex
	cache    map[[sha256.Size]byte]cacheEntry
}

// NewMiddleware creates authentication middleware. Basic auth credentials are tried
// against each backend in order. kerberos may be nil, otherwise it also accepts SPNEGO.
// Successful Basic logins are cached for cacheTTL, since the backends are expensive.
func NewMiddleware(logger *zap.Logger, realm string, cacheTTL time.Duration,
	kerberos *KerberosAuthenticator, basic ...BasicAuthenticator) *Middleware {
	return &Middleware{
		logger:   logger,
		realm:    realm,
		basic:    basic,
		kerberos: kerberos,
		cacheTTL: cacheTTL,
		cache:    map[[sha256.Size]byte]cacheEntry{},
	}
}

func (m *Middleware) challenge(w http.ResponseWriter) {
	if len(m.basic) > 0 {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", m.realm))
	}
	if m.kerberos != nil {
		w.Header().Add("WWW-Authenticate", "Negotiate")
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// respond serves next for allowed users, or the appropriate error.
func (m *Middleware) respond(next http.Handler, w http.ResponseWriter, r *http.Request, id Identity, result Result, err error) {
	switch {
	case err != nil:
		m.logger.Error("Authentication backend failed", zap.String("username", id.Username), zap.Error(err))
		http.Error(w, "Authentication backend unavailable", http.StatusServiceUnavailable)
	case result == Allowed:
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	case result == Forbidden:
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		m.challenge(w)
	}
}

func (m *Middleware) cacheKey(username, password string) [sha256.Size]byte {
	return sha256.Sum256([]byte(username + "\x00" + password))
}

func (m *Middleware) cached(key [sha256.Size]byte) (Identity, bool) {
	m.cacheMtx.Lock()
	defer m.cacheMtx.Unlock()
	entry, ok := m.cache[key]
	if !ok || time.Now().After(entry.expires) {
		return Identity{}, false
	}
	return entry.identity, true
}

func (m *Middleware) store(key [sha256.Size]byte, id Identity) {
	if m.cacheTTL <= 0 {
		return
	}
	now := time.Now()
	m.cacheMtx.Lock()
	defer m.cacheMtx.Unlock()
	for k, entry := range m.cache {
		if now.After(entry.expires) {
			delete(m.cache, k)
		}
	}
	m.cache[key] = cacheEntry{identity: id, expires: now.Add(m.cacheTTL)}
}

// authenticateBasic tries each backend in turn. Backend errors are only reported if no
// other backend accepted the user.
func (m *Middleware) authenticateBasic(ctx context.Context, username, password string) (Identity, Result, error) {
	key := m.cacheKey(username, password)
	if id, ok := m.cached(key); ok {
		return id, Allowed, nil
	}

	best := Denied
	var lastErr error
	for _, backend := range m.basic {
		result, err := backend.Authenticate(ctx, username, password)
		if err != nil {
			m.logger.Warn("Authentication backend error", zap.String("backend", backend.Name()),
				zap.String("username", username), zap.Error(err))
			lastErr = err
			continue
		}
		if result == Allowed {
			id := Identity{Username: username, Method: backend.Name()}
			m.store(key, id)
			return id, Allowed, nil
		}
		best = max(best, result)
	}
	if best == Forbidden {
		return Identity{Username: username}, Forbidden, nil
	}
	return Identity{Username: username}, Denied, lastErr
}

// Wrap requires requests to next to be authenticated and authorized.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	var negotiate http.Handler
	if m.kerberos != nil {
		negotiate = m.kerberos.negotiate(func(w http.ResponseWriter, r *http.Request, id Identity, result Result, err error) {
			m.respond(next, w, r, id, result, err)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		switch {
		case negotiate != nil && strings.EqualFold(scheme, "Negotiate"):
			negotiate.ServeHTTP(w, r)
		case len(m.basic) > 0 && strings.EqualFold(scheme, "Basic"):
			username, password, ok := r.BasicAuth()
			if !ok {
				m.challenge(w)
				return
			}
			id, result, err := m.authenticateBasic(r.Context(), username, password)
			if result != Allowed {
				m.logger.Info("Push authentication failed", zap.String("username", username),
					zap.String("remote_addr", r.RemoteAddr))
			}
			m.respond(next, w, r, id, result, err)
		default:
			m.challenge(w)
		}
	})
}
