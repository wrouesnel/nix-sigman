package httpauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// fakeBackend accepts password per user, and returns result/err for everything else.
type fakeBackend struct {
	name      string
	passwords map[string]string
	result    httpauth.Result
	err       error

	mtx   sync.Mutex
	calls int
}

func (f *fakeBackend) Name() string { return f.name }

func (f *fakeBackend) Authenticate(_ context.Context, username, password string) (httpauth.Result, error) {
	f.mtx.Lock()
	f.calls++
	f.mtx.Unlock()
	if expected, ok := f.passwords[username]; ok && expected == password {
		return httpauth.Allowed, nil
	}
	return f.result, f.err
}

func (f *fakeBackend) Calls() int {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.calls
}

type MiddlewareSuite struct{}

var _ = Suite(&MiddlewareSuite{})

type recordingHandler struct {
	calls    int
	identity httpauth.Identity
	found    bool
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls++
	h.identity, h.found = httpauth.IdentityFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func do(handler http.Handler, configure func(r *http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/nar/foo.nar", nil)
	if configure != nil {
		configure(r)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func basic(username, password string) func(r *http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(username, password) }
}

func header(value string) func(r *http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", value) }
}

func (s *MiddlewareSuite) newBackend() *fakeBackend {
	return &fakeBackend{name: "fake", passwords: map[string]string{"alice": "pw"}, result: httpauth.Denied}
}

func (s *MiddlewareSuite) TestNoCredentials(c *C) {
	next := &recordingHandler{}
	m := httpauth.NewMiddleware(zap.NewNop(), "nix cache", time.Minute, nil, s.newBackend())
	w := do(m.Wrap(next), nil)
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(w.Header().Values("WWW-Authenticate"), DeepEquals, []string{`Basic realm="nix cache", charset="UTF-8"`})
	c.Check(next.calls, Equals, 0)

	// Unknown schemes get the challenge too.
	w = do(m.Wrap(next), header("Bearer abc"))
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(next.calls, Equals, 0)

	// Negotiate isn't accepted without a Kerberos authenticator.
	w = do(m.Wrap(next), header("Negotiate abc"))
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(next.calls, Equals, 0)
}

func (s *MiddlewareSuite) newKerberos(c *C) *httpauth.KerberosAuthenticator {
	k, err := httpauth.NewKerberosAuthenticator(zap.NewNop(), httpauth.KerberosConfig{
		Keytab:           writeKeytab(c),
		AllowedPrincipal: []string{"*@EXAMPLE.COM"},
	}, nil)
	c.Assert(err, IsNil)
	return k
}

func (s *MiddlewareSuite) TestNegotiateChallenge(c *C) {
	next := &recordingHandler{}
	m := httpauth.NewMiddleware(zap.NewNop(), "nix cache", time.Minute, s.newKerberos(c), s.newBackend())
	w := do(m.Wrap(next), nil)
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(w.Header().Values("WWW-Authenticate"), DeepEquals,
		[]string{`Basic realm="nix cache", charset="UTF-8"`, "Negotiate"})

	// Kerberos only: no Basic challenge, and Basic credentials aren't tried.
	m = httpauth.NewMiddleware(zap.NewNop(), "nix cache", time.Minute, s.newKerberos(c))
	w = do(m.Wrap(next), nil)
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(w.Header().Values("WWW-Authenticate"), DeepEquals, []string{"Negotiate"})
	w = do(m.Wrap(next), basic("alice", "pw"))
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(next.calls, Equals, 0)
}

func (s *MiddlewareSuite) TestNegotiateGarbageToken(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "nix cache", time.Minute, s.newKerberos(c), backend)
	for _, value := range []string{"Negotiate garbage!!", "Negotiate Z2FyYmFnZQ==", "negotiate", "Negotiate "} {
		w := do(m.Wrap(next), header(value))
		c.Check(w.Code, Not(Equals), http.StatusOK, Commentf(value))
		c.Check(w.Code >= 400, Equals, true, Commentf("%s: %d", value, w.Code))
	}
	c.Check(next.calls, Equals, 0)
	c.Check(backend.Calls(), Equals, 0)
}

func (s *MiddlewareSuite) TestWrongCredentials(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, backend)
	w := do(m.Wrap(next), basic("alice", "wrong"))
	c.Check(w.Code, Equals, http.StatusUnauthorized)
	c.Check(w.Header().Get("WWW-Authenticate"), Matches, `Basic realm="realm".*`)
	c.Check(next.calls, Equals, 0)
	c.Check(backend.Calls(), Equals, 1)

	// Failures aren't cached.
	do(m.Wrap(next), basic("alice", "wrong"))
	c.Check(backend.Calls(), Equals, 2)
}

func (s *MiddlewareSuite) TestMalformedBasic(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, backend)
	for _, value := range []string{"Basic !!!notbase64", "Basic", "Basic bm9jb2xvbg=="} {
		w := do(m.Wrap(next), header(value))
		c.Check(w.Code, Equals, http.StatusUnauthorized, Commentf(value))
		c.Check(w.Header().Get("WWW-Authenticate"), Not(Equals), "")
	}
	c.Check(next.calls, Equals, 0)
	c.Check(backend.Calls(), Equals, 0)
}

func (s *MiddlewareSuite) TestForbidden(c *C) {
	next := &recordingHandler{}
	denied := &fakeBackend{name: "denied", result: httpauth.Denied}
	forbidden := &fakeBackend{name: "forbidden", result: httpauth.Forbidden}
	// Forbidden from any backend wins over Denied regardless of order.
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, forbidden, denied)
	w := do(m.Wrap(next), basic("alice", "pw"))
	c.Check(w.Code, Equals, http.StatusForbidden)
	c.Check(w.Header().Get("WWW-Authenticate"), Equals, "")
	c.Check(next.calls, Equals, 0)
	c.Check(denied.Calls(), Equals, 1)
	c.Check(forbidden.Calls(), Equals, 1)
}

func (s *MiddlewareSuite) TestBackendError(c *C) {
	next := &recordingHandler{}
	broken := &fakeBackend{name: "broken", err: errors.New("down")}
	denied := &fakeBackend{name: "denied", result: httpauth.Denied}
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, broken, denied)
	w := do(m.Wrap(next), basic("alice", "pw"))
	c.Check(w.Code, Equals, http.StatusServiceUnavailable)
	c.Check(next.calls, Equals, 0)
	c.Check(denied.Calls(), Equals, 1)
}

func (s *MiddlewareSuite) TestBackendErrorThenAllowed(c *C) {
	next := &recordingHandler{}
	broken := &fakeBackend{name: "broken", err: errors.New("down")}
	good := &fakeBackend{name: "good", passwords: map[string]string{"alice": "pw"}}
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, broken, good)
	w := do(m.Wrap(next), basic("alice", "pw"))
	c.Check(w.Code, Equals, http.StatusOK)
	c.Check(next.calls, Equals, 1)
	c.Check(next.identity, Equals, httpauth.Identity{Username: "alice", Method: "good"})
}

func (s *MiddlewareSuite) TestAllowed(c *C) {
	next := &recordingHandler{}
	first := &fakeBackend{name: "first", result: httpauth.Denied}
	second := &fakeBackend{name: "second", passwords: map[string]string{"alice": "pw"}}
	third := &fakeBackend{name: "third", passwords: map[string]string{"alice": "pw"}}
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, first, second, third)
	w := do(m.Wrap(next), basic("alice", "pw"))
	c.Check(w.Code, Equals, http.StatusOK)
	c.Check(next.calls, Equals, 1)
	c.Check(next.found, Equals, true)
	c.Check(next.identity, Equals, httpauth.Identity{Username: "alice", Method: "second"})
	// Stops at the first backend which accepts.
	c.Check(third.Calls(), Equals, 0)

	_, found := httpauth.IdentityFromContext(context.Background())
	c.Check(found, Equals, false)
}

func (s *MiddlewareSuite) TestCaching(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Minute, nil, backend)
	h := m.Wrap(next)

	c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusOK)
	c.Check(backend.Calls(), Equals, 1)
	c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusOK)
	c.Check(backend.Calls(), Equals, 1)
	c.Check(next.calls, Equals, 2)
	c.Check(next.identity, Equals, httpauth.Identity{Username: "alice", Method: "fake"})

	// A different password isn't served from the cache.
	c.Check(do(h, basic("alice", "other")).Code, Equals, http.StatusUnauthorized)
	c.Check(backend.Calls(), Equals, 2)

	// The username/password boundary is part of the key.
	backend.passwords["alic"] = "epw"
	c.Check(do(h, basic("alic", "epw")).Code, Equals, http.StatusOK)
	c.Check(backend.Calls(), Equals, 3)
}

func (s *MiddlewareSuite) TestCacheDisabled(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", 0, nil, backend)
	h := m.Wrap(next)
	for i := 1; i <= 3; i++ {
		c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusOK)
		c.Check(backend.Calls(), Equals, i)
	}
}

func (s *MiddlewareSuite) TestCacheExpiry(c *C) {
	next := &recordingHandler{}
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", 20*time.Millisecond, nil, backend)
	h := m.Wrap(next)
	c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusOK)
	c.Check(backend.Calls(), Equals, 1)
	time.Sleep(50 * time.Millisecond)
	c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusOK)
	c.Check(backend.Calls(), Equals, 2)

	// Revoked credentials stop working once the entry expires.
	delete(backend.passwords, "alice")
	time.Sleep(50 * time.Millisecond)
	c.Check(do(h, basic("alice", "pw")).Code, Equals, http.StatusUnauthorized)
	c.Check(backend.Calls(), Equals, 3)
}

func (s *MiddlewareSuite) TestConcurrentRequests(c *C) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	backend := s.newBackend()
	m := httpauth.NewMiddleware(zap.NewNop(), "realm", time.Millisecond, nil, backend)
	h := m.Wrap(next)
	var wg sync.WaitGroup
	codes := make([]int, 32)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = do(h, basic("alice", "pw")).Code
		}(i)
	}
	wg.Wait()
	for _, code := range codes {
		c.Check(code, Equals, http.StatusOK)
	}
}
