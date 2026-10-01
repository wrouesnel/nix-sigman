package serve_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&ServeSuite{})

type ServeSuite struct {
}

// fakeStore serves a single narinfo registered at a fixed time.
type fakeStore struct {
	registrationTime time.Time
}

func (f *fakeStore) GetNixCacheInfo() *nixstore.NixCacheInfo { return &nixstore.NixCacheInfo{} }

func (f *fakeStore) GetNarInfo(path string) (nixtypes.NarInfo, time.Time, error) {
	ninfo := nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(`StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar
Compression: none
FileHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
FileSize: 4
NarHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
NarSize: 4
References: 
`))
	return ninfo, f.registrationTime, err
}

func (f *fakeStore) GetNar(w io.Writer, ninfo *nixtypes.NarInfo) error {
	_, err := w.Write([]byte("nar!"))
	return err
}

func (f *fakeStore) GetStorePathByURL(urlPath string) (string, error) {
	return "/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37", nil
}

func (f *fakeStore) GetStorePathByFileHash(fileHash string) (string, error) {
	return f.GetStorePathByURL(fileHash)
}

func (n *ServeSuite) TestIfModifiedSince(c *C) {
	modified := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := &serve.NixHandler{
		Logger:    zap.NewNop(),
		StorePath: nixstore.DefaultStorePath,
		StartTime: modified.Add(-time.Hour),
		Store:     &fakeStore{registrationTime: modified},
	}

	for _, target := range []string{"/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo", "/nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar"} {
		for _, tc := range []struct {
			since    time.Time
			expected int
		}{
			{modified.Add(-time.Second), http.StatusOK},
			{modified, http.StatusNotModified},
			{modified.Add(time.Second), http.StatusNotModified},
		} {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("If-Modified-Since", tc.since.Format(http.TimeFormat))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			c.Check(rec.Code, Equals, tc.expected, Commentf("%s since %s", target, tc.since))
		}
	}
}
