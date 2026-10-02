package serve_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mholt/archives"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

// pushStorePath is the path the fakeStore serves, so pushed paths can be read back.
const pushStorePath = "/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37"

// fakeWriter records imports instead of writing to a store.
type fakeWriter struct {
	mtx      sync.Mutex
	valid    map[string]bool
	imported map[string][]byte
	stored   map[string]*nixtypes.NarInfo
	err      error
}

func (f *fakeWriter) IsValidPath(storePath string) (bool, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.valid[storePath], nil
}

func (f *fakeWriter) ImportNar(_ context.Context, ninfo *nixtypes.NarInfo, narReader io.Reader) (bool, error) {
	data, err := io.ReadAll(narReader)
	if err != nil {
		return false, err
	}
	if f.err != nil {
		return false, f.err
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.valid[ninfo.StorePath] = true
	f.imported[ninfo.StorePath] = data
	stored := *ninfo
	f.stored[ninfo.StorePath] = &stored
	return true, nil
}

func (f *fakeWriter) SignPath(storePath string, sign func(ninfo *nixtypes.NarInfo) (bool, error)) (bool, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if !f.valid[storePath] {
		return false, &nixstore.ErrNotFound{}
	}
	ninfo := f.stored[storePath]
	if ninfo == nil {
		ninfo = &nixtypes.NarInfo{StorePath: storePath, Extra: map[string]string{}}
	}
	signed, err := sign(ninfo)
	if signed {
		f.stored[storePath] = ninfo
	}
	return signed, err
}

func (f *fakeWriter) Close() error { return nil }

type PushSuite struct {
	writer     *fakeWriter
	index      serve.PushIndex
	stagingDir string
	push       *serve.PushHandler
	handler    *serve.NixHandler
}

var _ = Suite(&PushSuite{})

func (s *PushSuite) SetUpTest(c *C) {
	s.setUp(c, time.Hour, 0)
}

func (s *PushSuite) setUp(c *C, ttl time.Duration, maxNarSize int64) {
	var err error
	s.writer = &fakeWriter{valid: map[string]bool{}, imported: map[string][]byte{}, stored: map[string]*nixtypes.NarInfo{}}
	s.index, err = serve.OpenPushIndex(filepath.Join(c.MkDir(), "state", "push-index.sqlite"), true)
	c.Assert(err, IsNil)
	s.stagingDir = c.MkDir()
	s.push, err = serve.NewPushHandler(zap.NewNop(), s.writer, s.index, s.stagingDir, ttl, maxNarSize)
	c.Assert(err, IsNil)
	s.handler = &serve.NixHandler{
		Logger:    zap.NewNop(),
		StorePath: nixstore.DefaultStorePath,
		StartTime: time.Now(),
		Store:     &fakeStore{registrationTime: time.Now()},
		Push:      s.push,
		PushIndex: s.index,
	}
}

func (s *PushSuite) TearDownTest(c *C) {
	c.Check(s.push.Close(), IsNil)
	c.Check(s.index.Close(), IsNil)
}

// stagedFiles returns the NARs waiting in the staging directory.
func (s *PushSuite) stagedFiles(c *C) []string {
	files, err := filepath.Glob(filepath.Join(s.stagingDir, "*", "nar-*"))
	c.Assert(err, IsNil)
	return files
}

func (s *PushSuite) do(method string, target string, body []byte, headers ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func compress(c *C, compressor archives.Compressor, data []byte) []byte {
	buf := new(bytes.Buffer)
	w, err := compressor.OpenWriter(buf)
	c.Assert(err, IsNil)
	_, err = w.Write(data)
	c.Assert(err, IsNil)
	c.Assert(w.Close(), IsNil)
	return buf.Bytes()
}

// narInfo describes narData uploaded as fileData at url.
func narInfo(c *C, url string, compression string, narData []byte, fileData []byte) []byte {
	narHash := sha256.Sum256(narData)
	fileHash := sha256.Sum256(fileData)
	ninfo := nixtypes.NarInfo{
		StorePath:   pushStorePath,
		URL:         url,
		Compression: compression,
		FileHash:    nixtypes.TypedNixHash{HashName: "sha256", Hash: fileHash[:]},
		FileSize:    uint64(len(fileData)),
		NarHash:     nixtypes.TypedNixHash{HashName: "sha256", Hash: narHash[:]},
		NarSize:     uint64(len(narData)),
		References:  []string{},
		Extra:       map[string]string{},
	}
	text, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	return text
}

const narinfoTarget = "/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo"

func (s *PushSuite) TestPushAndFetch(c *C) {
	// The fakeStore serves "nar!" as the NAR content for the path.
	narData := []byte("nar!")
	for _, tc := range []struct {
		compression string
		ext         string
		compressor  archives.Compressor
	}{
		{"xz", ".xz", archives.Xz{}},
		{"zstd", ".zst", archives.Zstd{}},
		{"bzip2", ".bz2", archives.Bz2{}},
		{"br", ".br", archives.Brotli{}},
		{"gzip", ".gz", archives.Gz{}},
		{"none", "", nil},
	} {
		s.writer.valid = map[string]bool{}
		fileData := narData
		if tc.compressor != nil {
			fileData = compress(c, tc.compressor, narData)
		}
		fileHash := sha256.Sum256(fileData)
		url := fmt.Sprintf("nar/%s.nar%s", nixtypes.NixBase32Field(fileHash[:]).String(), tc.ext)

		rec := s.do(http.MethodPut, "/"+url, fileData)
		c.Assert(rec.Code, Equals, http.StatusOK, Commentf("%s: %s", tc.compression, rec.Body.String()))
		c.Check(s.stagedFiles(c), HasLen, 1)

		rec = s.do(http.MethodPut, narinfoTarget, narInfo(c, url, tc.compression, narData, fileData))
		c.Assert(rec.Code, Equals, http.StatusOK, Commentf("%s: %s", tc.compression, rec.Body.String()))
		c.Check(s.writer.imported[pushStorePath], DeepEquals, narData, Commentf(tc.compression))
		c.Check(s.stagedFiles(c), HasLen, 0)

		// A client with the uploaded narinfo cached fetches from the upload URL, and
		// gets the NAR recompressed the same way.
		rec = s.do(http.MethodGet, "/"+url, nil)
		c.Assert(rec.Code, Equals, http.StatusOK, Commentf(tc.compression))
		body := io.NopCloser(rec.Body)
		if tc.compressor != nil {
			var err error
			body, err = tc.compressor.(archives.Decompressor).OpenReader(rec.Body)
			c.Assert(err, IsNil)
		}
		fetched, err := io.ReadAll(body)
		c.Assert(err, IsNil)
		c.Check(fetched, DeepEquals, narData, Commentf(tc.compression))

		rec = s.do(http.MethodHead, "/"+url, nil)
		c.Check(rec.Code, Equals, http.StatusOK)
		c.Check(rec.Body.Len(), Equals, 0)
	}
}

func (s *PushSuite) TestNarInfoContentEncoding(c *C) {
	narData := []byte("nar!")
	url := "nar/upload.nar"
	c.Assert(s.do(http.MethodPut, "/"+url, narData).Code, Equals, http.StatusOK)

	buf := new(bytes.Buffer)
	gz := gzip.NewWriter(buf)
	_, _ = gz.Write(narInfo(c, url, "none", narData, narData))
	c.Assert(gz.Close(), IsNil)
	rec := s.do(http.MethodPut, narinfoTarget, buf.Bytes(), "Content-Encoding", "gzip")
	c.Assert(rec.Code, Equals, http.StatusOK, Commentf(rec.Body.String()))
	c.Check(s.writer.imported[pushStorePath], DeepEquals, narData)

	rec = s.do(http.MethodPut, narinfoTarget, []byte("x"), "Content-Encoding", "compress")
	c.Check(rec.Code, Equals, http.StatusUnsupportedMediaType)
}

func (s *PushSuite) TestNarInfoWithoutNar(c *C) {
	rec := s.do(http.MethodPut, narinfoTarget, narInfo(c, "nar/missing.nar", "none", []byte("nar!"), []byte("nar!")))
	c.Check(rec.Code, Equals, http.StatusBadRequest)
	c.Check(s.writer.imported, HasLen, 0)
}

func (s *PushSuite) TestNarInfoMismatches(c *C) {
	narData := []byte("nar!")
	for name, tc := range map[string]struct {
		target   string
		fileData []byte
	}{
		"file hash": {narinfoTarget, []byte("different")},
		"file size": {narinfoTarget, []byte("nar!!")},
		"name":      {"/00000000000000000000000000000000.narinfo", narData},
	} {
		c.Assert(s.do(http.MethodPut, "/nar/upload.nar", narData).Code, Equals, http.StatusOK)
		rec := s.do(http.MethodPut, tc.target, narInfo(c, "nar/upload.nar", "none", narData, tc.fileData))
		c.Check(rec.Code, Equals, http.StatusBadRequest, Commentf(name))
	}
	c.Check(s.writer.imported, HasLen, 0)

	rec := s.do(http.MethodPut, narinfoTarget, []byte("not a narinfo"))
	c.Check(rec.Code, Equals, http.StatusBadRequest)
}

func (s *PushSuite) TestImportErrors(c *C) {
	narData := []byte("nar!")
	for _, tc := range []struct {
		err  error
		code int
	}{
		{&nixstore.ErrRejected{Reason: "bad"}, http.StatusBadRequest},
		{errors.New("disk on fire"), http.StatusInternalServerError},
	} {
		s.writer.err = tc.err
		c.Assert(s.do(http.MethodPut, "/nar/upload.nar", narData).Code, Equals, http.StatusOK)
		rec := s.do(http.MethodPut, narinfoTarget, narInfo(c, "nar/upload.nar", "none", narData, narData))
		c.Check(rec.Code, Equals, tc.code)
		c.Check(s.stagedFiles(c), HasLen, 0)
	}
	_, found, _ := lookup(s.index, "nar/upload.nar")
	c.Check(found, Equals, false)
}

func lookup(index serve.PushIndex, url string) (string, bool, error) {
	storePath, _, found, err := index.Lookup(url)
	return storePath, found, err
}

func (s *PushSuite) TestAlreadyValid(c *C) {
	s.writer.valid[pushStorePath] = true
	narData := []byte("nar!")
	c.Assert(s.do(http.MethodPut, "/nar/upload.nar", narData).Code, Equals, http.StatusOK)
	rec := s.do(http.MethodPut, narinfoTarget, narInfo(c, "nar/upload.nar", "none", narData, narData))
	c.Check(rec.Code, Equals, http.StatusOK)
	c.Check(s.writer.imported, HasLen, 0)
	c.Check(s.stagedFiles(c), HasLen, 0)
	// The client will still cache the narinfo, so its URL must be servable.
	storePath, found, err := lookup(s.index, "nar/upload.nar")
	c.Assert(err, IsNil)
	c.Check(found, Equals, true)
	c.Check(storePath, Equals, pushStorePath)
}

func (s *PushSuite) TestReuploadReplacesStagedNar(c *C) {
	c.Assert(s.do(http.MethodPut, "/nar/upload.nar", []byte("first")).Code, Equals, http.StatusOK)
	c.Assert(s.do(http.MethodPut, "/nar/upload.nar", []byte("nar!")).Code, Equals, http.StatusOK)
	c.Check(s.stagedFiles(c), HasLen, 1)
	rec := s.do(http.MethodPut, narinfoTarget, narInfo(c, "nar/upload.nar", "none", []byte("nar!"), []byte("nar!")))
	c.Check(rec.Code, Equals, http.StatusOK)
}

func (s *PushSuite) TestUploadPaths(c *C) {
	for target, code := range map[string]int{
		"/nix-cache-info":                                http.StatusForbidden,
		"/58br4vk3q5akf4g8lx0pqzfhn47k3j8d.ls":           http.StatusOK,
		"/log/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash.drv": http.StatusOK,
		"/realisations/sha256:abc!out.doi":               http.StatusOK,
		"/debug-info/0123456789abcdef.debug":             http.StatusOK,
		"/nar/../etc/passwd":                             http.StatusNotFound,
		"/nar/.hidden":                                   http.StatusNotFound,
		"/nar/a/b.nar":                                   http.StatusNotFound,
		"/elsewhere/file":                                http.StatusNotFound,
		"/sub/x.narinfo":                                 http.StatusNotFound,
	} {
		rec := s.do(http.MethodPut, target, []byte("data"))
		c.Check(rec.Code, Equals, code, Commentf(target))
	}
	c.Check(s.stagedFiles(c), HasLen, 0)
}

func (s *PushSuite) TestMaxNarSize(c *C) {
	c.Assert(s.push.Close(), IsNil)
	c.Assert(s.index.Close(), IsNil)
	s.setUp(c, time.Hour, 4)

	c.Check(s.do(http.MethodPut, "/nar/small.nar", []byte("nar!")).Code, Equals, http.StatusOK)
	c.Check(s.do(http.MethodPut, "/nar/large.nar", []byte("nar!!")).Code, Equals, http.StatusRequestEntityTooLarge)
	c.Check(s.stagedFiles(c), HasLen, 1)
}

func (s *PushSuite) TestStagedNarsExpire(c *C) {
	c.Assert(s.push.Close(), IsNil)
	c.Assert(s.index.Close(), IsNil)
	s.setUp(c, 20*time.Millisecond, 0)

	c.Assert(s.do(http.MethodPut, "/nar/upload.nar", []byte("nar!")).Code, Equals, http.StatusOK)
	deadline := time.Now().Add(5 * time.Second)
	for len(s.stagedFiles(c)) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	c.Check(s.stagedFiles(c), HasLen, 0)
	rec := s.do(http.MethodPut, narinfoTarget, narInfo(c, "nar/upload.nar", "none", []byte("nar!"), []byte("nar!")))
	c.Check(rec.Code, Equals, http.StatusBadRequest)
}

func (s *PushSuite) TestCloseRemovesStagingDir(c *C) {
	c.Assert(s.do(http.MethodPut, "/nar/upload.nar", []byte("nar!")).Code, Equals, http.StatusOK)
	c.Assert(s.push.Close(), IsNil)
	entries, err := os.ReadDir(s.stagingDir)
	c.Assert(err, IsNil)
	c.Check(entries, HasLen, 0)
	// TearDownTest closes again: recreate so that's harmless.
	s.push, err = serve.NewPushHandler(zap.NewNop(), s.writer, s.index, s.stagingDir, time.Hour, 0)
	c.Assert(err, IsNil)
}

func (s *PushSuite) TestMethods(c *C) {
	c.Check(s.do(http.MethodDelete, narinfoTarget, nil).Code, Equals, http.StatusMethodNotAllowed)

	readOnly := &serve.NixHandler{Logger: zap.NewNop(), Store: &fakeStore{}}
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		rec := httptest.NewRecorder()
		readOnly.ServeHTTP(rec, httptest.NewRequest(method, narinfoTarget, nil))
		c.Check(rec.Code, Equals, http.StatusMethodNotAllowed, Commentf(method))
		c.Check(rec.Header().Get("Allow"), Equals, "GET, HEAD")
	}
}

func (s *PushSuite) TestPushIndexReadOnly(c *C) {
	path := filepath.Join(c.MkDir(), "index.sqlite")
	_, err := serve.OpenPushIndex(path, false)
	c.Check(err, NotNil)

	rw, err := serve.OpenPushIndex(path, true)
	c.Assert(err, IsNil)
	c.Assert(rw.Record("nar/a.nar.xz", pushStorePath, "xz"), IsNil)
	c.Assert(rw.Record("nar/a.nar.xz", pushStorePath, "zstd"), IsNil)
	c.Assert(rw.Close(), IsNil)

	ro, err := serve.OpenPushIndex(path, false)
	c.Assert(err, IsNil)
	defer ro.Close()
	storePath, compression, found, err := ro.Lookup("nar/a.nar.xz")
	c.Assert(err, IsNil)
	c.Check(found, Equals, true)
	c.Check(storePath, Equals, pushStorePath)
	c.Check(compression, Equals, "zstd")
	c.Check(ro.Record("nar/b.nar", pushStorePath, "none"), NotNil)
}
