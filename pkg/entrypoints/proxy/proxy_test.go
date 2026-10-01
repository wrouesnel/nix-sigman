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

const existingNarInfo = `StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar
Compression: none
FileHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
FileSize: 1640
NarHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
NarSize: 1640
References: 58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37 8ranqggwk67p5mii3vimljcb9jr0nliq-nixexprs.tar.xz
Deriver: 8ranqggwk67p5mii3vimljcb9jr0nliq-bash-5.2p37.drv
`

const conflictingNarInfo = `StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar
Compression: none
FileHash: sha256:0ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
FileSize: 16
NarHash: sha256:0ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
NarSize: 16
References: 
`

const narInfoName = "58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo"

func (s *ProxySuite) writeNarInfo(c *C, content string) string {
	path := filepath.Join(s.rootDir.String(), narInfoName)
	c.Assert(os.WriteFile(path, []byte(content), os.FileMode(0644)), IsNil)
	return path
}

func (s *ProxySuite) TestPushConflictIsRejected(c *C) {
	path := s.writeNarInfo(c, existingNarInfo)
	h := s.router(&ProxyConfig{AllowPush: true})
	rec := s.do(h, http.MethodPut, "/"+narInfoName, conflictingNarInfo)
	c.Check(rec.Code, Equals, http.StatusConflict)

	content, err := os.ReadFile(path)
	c.Assert(err, IsNil)
	c.Check(string(content), Equals, existingNarInfo)
}

func (s *ProxySuite) TestPushOverwriteReplacesWholeFile(c *C) {
	path := s.writeNarInfo(c, existingNarInfo)
	h := s.router(&ProxyConfig{AllowPush: true, PushOverwrite: true})
	rec := s.do(h, http.MethodPut, "/"+narInfoName, conflictingNarInfo)
	c.Check(rec.Code, Equals, http.StatusOK)

	content, err := os.ReadFile(path)
	c.Assert(err, IsNil)
	c.Check(string(content), Equals, rec.Body.String())
	c.Check(strings.Contains(string(content), "Deriver"), Equals, false)
}
