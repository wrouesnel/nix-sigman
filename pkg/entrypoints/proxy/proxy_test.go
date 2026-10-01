package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ProxySuite struct {
	baseDir string
	rootDir *pathlib.Path
}

var _ = Suite(&ProxySuite{})

func (s *ProxySuite) SetUpTest(c *C) {
	s.baseDir = c.MkDir()
	root := filepath.Join(s.baseDir, "root")
	c.Assert(os.Mkdir(root, os.FileMode(0755)), IsNil)
	c.Assert(os.WriteFile(filepath.Join(s.baseDir, "outside.txt"), []byte("SECRET"), os.FileMode(0644)), IsNil)
	c.Assert(os.WriteFile(filepath.Join(root, "nix-cache-info"), []byte("StoreDir: /nix/store\n"), os.FileMode(0644)), IsNil)
	s.rootDir = pathlib.NewPath(root, pathlib.PathWithAfero(afero.NewOsFs()))
}

func (s *ProxySuite) router(cfg *ProxyConfig) http.Handler {
	return newRouter(zap.NewNop(), cfg, s.rootDir, nil, nil)
}

func (s *ProxySuite) do(h http.Handler, method string, target string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (s *ProxySuite) TestGetCannotEscapeRoot(c *C) {
	h := s.router(&ProxyConfig{})
	for _, target := range []string{"/../outside.txt", "/%2e%2e/outside.txt", "/nar/../../outside.txt"} {
		rec := s.do(h, http.MethodGet, target, "")
		c.Check(rec.Code, Equals, http.StatusNotFound, Commentf("target %s", target))
		c.Check(strings.Contains(rec.Body.String(), "SECRET"), Equals, false, Commentf("target %s", target))
	}
}

func (s *ProxySuite) TestPutCannotEscapeRoot(c *C) {
	h := s.router(&ProxyConfig{AllowPush: true})
	rec := s.do(h, http.MethodPut, "/../pwned.txt", "written")
	c.Check(rec.Code, Equals, http.StatusCreated)

	_, err := os.Stat(filepath.Join(s.baseDir, "pwned.txt"))
	c.Check(os.IsNotExist(err), Equals, true, Commentf("file was written outside the root"))
	_, err = os.Stat(filepath.Join(s.rootDir.String(), "pwned.txt"))
	c.Check(err, IsNil, Commentf("file should be confined to the root"))
}

func (s *ProxySuite) TestNixCacheInfoIsServedAndProtected(c *C) {
	h := s.router(&ProxyConfig{AllowPush: true})
	rec := s.do(h, http.MethodGet, "/nix-cache-info", "")
	c.Check(rec.Code, Equals, http.StatusOK)
	c.Check(rec.Header().Get("Content-Type"), Equals, "text/x-nix-cache-info")

	rec = s.do(h, http.MethodPut, "/nix-cache-info", "StoreDir: /evil\n")
	c.Check(rec.Code, Equals, http.StatusForbidden)
}
