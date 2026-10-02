package serve

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mholt/archives"
	"github.com/wrouesnel/nix-sigman/pkg/httpauth"
	"github.com/wrouesnel/nix-sigman/pkg/nixconsts"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
)

// PushConfig configures accepting uploads from `nix copy --to http://...`.
type PushConfig struct {
	Enabled      bool          `help:"Allow authenticated clients to push paths into the store (the store and database must be writable)" default:"false"`
	StagingDir   string        `help:"Directory to hold uploaded NARs until their narinfo arrives (default: system temporary directory)"`
	StagingTTL   time.Duration `help:"How long an uploaded NAR waits for its narinfo before being discarded" default:"1h"`
	MaxNarSize   int64         `help:"Maximum size in bytes of an uploaded NAR file (0 for unlimited)" default:"0"`
	AuthRealm    string        `help:"Realm for Basic authentication challenges" default:"nix-sigman"`
	AuthCacheTTL time.Duration `help:"How long to cache successful Basic authentications (0 to disable)" default:"5m"`
	PasswordFile []string      `help:"Files of username:argon2-hash lines (see debug hash-password)" type:"existingfile"`
	Index        string        `help:"Database of the URLs paths were uploaded under, so clients can fetch them by those URLs (relative to the root)" default:"nix/var/nix-sigman/push-index.sqlite"`

	LDAP     httpauth.LDAPConfig     `embed:"" prefix:"ldap-"`
	Kerberos httpauth.KerberosConfig `embed:"" prefix:"kerberos-"`
}

// maxNarInfoSize bounds narinfo uploads, which are small text files.
const maxNarInfoSize = 1 << 20

var narUploadRegex = regexp.MustCompile(`^nar/[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// newAuthMiddleware builds the push authentication middleware from the configured backends.
func (p *PushConfig) newAuthMiddleware(l *zap.Logger) (*httpauth.Middleware, error) {
	basic := []httpauth.BasicAuthenticator{}

	if len(p.PasswordFile) > 0 {
		passwords, err := httpauth.LoadPasswordFiles(p.PasswordFile...)
		if err != nil {
			return nil, fmt.Errorf("could not load password files: %w", err)
		}
		l.Info("Loaded push password files", zap.Int("users", passwords.Users()))
		basic = append(basic, passwords)
	}

	var authorizer httpauth.Authorizer
	if p.LDAP.URL != "" {
		ldapAuth, err := httpauth.NewLDAPAuthenticator(l, p.LDAP)
		if err != nil {
			return nil, fmt.Errorf("could not configure LDAP: %w", err)
		}
		l.Info("LDAP push authentication enabled", zap.String("url", p.LDAP.URL))
		basic = append(basic, ldapAuth)
		authorizer = ldapAuth
	}

	var krb *httpauth.KerberosAuthenticator
	if p.Kerberos.Keytab != "" {
		var err error
		krb, err = httpauth.NewKerberosAuthenticator(l, p.Kerberos, authorizer)
		if err != nil {
			return nil, fmt.Errorf("could not configure Kerberos: %w", err)
		}
		l.Info("Kerberos push authentication enabled", zap.Bool("basic_auth", p.Kerberos.BasicAuth))
		if p.Kerberos.BasicAuth {
			basic = append(basic, krb)
		}
	}

	if len(basic) == 0 && krb == nil {
		return nil, errors.New("push requires at least one authentication method " +
			"(password files, LDAP or Kerberos)")
	}
	return httpauth.NewMiddleware(l, p.AuthRealm, p.AuthCacheTTL, krb, basic...), nil
}

type stagedNar struct {
	path     string
	fileHash []byte
	fileSize uint64
	created  time.Time
}

// PushHandler accepts uploads in the layout of a Nix HTTP binary cache. NARs are held
// in a staging directory until the narinfo describing them is uploaded, at which point
// they are unpacked into the store and registered.
type PushHandler struct {
	logger     *zap.Logger
	writer     nixstore.NixStoreWriter
	index      PushIndex
	stagingDir string
	stagingTTL time.Duration
	maxNarSize int64

	mtx    sync.Mutex
	staged map[string]stagedNar

	cancel context.CancelFunc
	done   chan struct{}
}

// NewPushHandler creates a push handler staging uploads in a new directory under
// stagingDir. Close removes the staging directory.
func NewPushHandler(l *zap.Logger, writer nixstore.NixStoreWriter, index PushIndex,
	stagingDir string, stagingTTL time.Duration, maxNarSize int64) (*PushHandler, error) {
	dir, err := os.MkdirTemp(stagingDir, "nix-sigman-push-")
	if err != nil {
		return nil, fmt.Errorf("could not create staging directory: %w", err)
	}
	p := &PushHandler{
		logger:     l,
		writer:     writer,
		index:      index,
		stagingDir: dir,
		stagingTTL: stagingTTL,
		maxNarSize: maxNarSize,
		staged:     map[string]stagedNar{},
		done:       make(chan struct{}),
	}
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	go p.expireStaged(ctx)
	return p, nil
}

// Close stops expiring staged uploads and removes the staging directory.
func (p *PushHandler) Close() error {
	p.cancel()
	<-p.done
	return os.RemoveAll(p.stagingDir)
}

// expireStaged removes NARs whose narinfo never arrived.
func (p *PushHandler) expireStaged(ctx context.Context) {
	defer close(p.done)
	ticker := time.NewTicker(min(p.stagingTTL, time.Minute))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.mtx.Lock()
			for url, nar := range p.staged {
				if now.Sub(nar.created) > p.stagingTTL {
					p.logger.Info("Discarding uploaded NAR which never received a narinfo", zap.String("url", url))
					_ = os.Remove(nar.path)
					delete(p.staged, url)
				}
			}
			p.mtx.Unlock()
		}
	}
}

func (p *PushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")

	body, err := decodeContentEncoding(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	defer body.Close()

	switch {
	case name == nixconsts.NixCacheInfoName:
		http.Error(w, "the cache info is determined by the server", http.StatusForbidden)
	case strings.HasSuffix(name, ".narinfo") && !strings.Contains(name, "/"):
		p.putNarInfo(w, r, name, body)
	case narUploadRegex.MatchString(name):
		p.putNar(w, r, name, body)
	case strings.HasSuffix(name, ".ls") && !strings.Contains(name, "/"),
		strings.HasPrefix(name, "log/"),
		strings.HasPrefix(name, "realisations/"),
		strings.HasPrefix(name, "debug-info/"):
		// Metadata the store doesn't keep. Accept it so clients don't fail.
		_, _ = io.Copy(io.Discard, io.LimitReader(body, maxNarInfoSize))
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unsupported upload path", http.StatusNotFound)
	}
}

// putNar stages an uploaded (possibly compressed) NAR file.
func (p *PushHandler) putNar(w http.ResponseWriter, r *http.Request, name string, body io.Reader) {
	if p.maxNarSize > 0 {
		body = http.MaxBytesReader(w, io.NopCloser(body), p.maxNarSize)
	}
	fh, err := os.CreateTemp(p.stagingDir, "nar-")
	if err != nil {
		p.logger.Error("Could not create staging file", zap.Error(err))
		http.Error(w, "could not stage NAR", http.StatusInternalServerError)
		return
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(fh, hasher), body)
	if closeErr := fh.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(fh.Name())
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, "NAR too large", http.StatusRequestEntityTooLarge)
			return
		}
		p.logger.Warn("NAR upload failed", zap.String("url", name), zap.Error(err))
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}

	p.mtx.Lock()
	if previous, found := p.staged[name]; found {
		_ = os.Remove(previous.path)
	}
	p.staged[name] = stagedNar{path: fh.Name(), fileHash: hasher.Sum(nil), fileSize: uint64(size), created: time.Now()}
	p.mtx.Unlock()

	p.logger.Debug("Staged NAR", zap.String("url", name), zap.Int64("size", size),
		zap.String("remote_user", remoteUser(r)))
	w.WriteHeader(http.StatusOK)
}

// claimStaged removes a staged NAR from the index so only one import uses it.
func (p *PushHandler) claimStaged(url string) (stagedNar, bool) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	nar, found := p.staged[url]
	delete(p.staged, url)
	return nar, found
}

// putNarInfo imports the staged NAR a narinfo describes into the store.
func (p *PushHandler) putNarInfo(w http.ResponseWriter, r *http.Request, name string, body io.Reader) {
	content, err := io.ReadAll(io.LimitReader(body, maxNarInfoSize+1))
	if err != nil {
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}
	if len(content) > maxNarInfoSize {
		http.Error(w, "narinfo too large", http.StatusRequestEntityTooLarge)
		return
	}

	var ninfo nixtypes.NarInfo
	if err := ninfo.UnmarshalText(content); err != nil {
		http.Error(w, fmt.Sprintf("invalid narinfo: %v", err), http.StatusBadRequest)
		return
	}
	if ninfo.StorePath == "" || ninfo.NixHash()+".narinfo" != name {
		http.Error(w, "narinfo store path does not match the upload path", http.StatusBadRequest)
		return
	}

	l := p.logger.With(zap.String("store_path", ninfo.StorePath), zap.String("remote_user", remoteUser(r)))

	if valid, err := p.writer.IsValidPath(ninfo.StorePath); err != nil {
		l.Error("Could not query store", zap.Error(err))
		http.Error(w, "could not query store", http.StatusInternalServerError)
		return
	} else if valid {
		if nar, found := p.claimStaged(ninfo.URL); found {
			_ = os.Remove(nar.path)
		}
		p.recordURL(w, l, &ninfo)
		return
	}

	nar, found := p.claimStaged(ninfo.URL)
	if !found {
		http.Error(w, fmt.Sprintf("NAR %s must be uploaded before its narinfo", ninfo.URL), http.StatusBadRequest)
		return
	}
	defer os.Remove(nar.path)

	if ninfo.FileHash.HashName != "" {
		if ninfo.FileHash.HashName != "sha256" || !slices.Equal(ninfo.FileHash.Hash, nar.fileHash) {
			http.Error(w, "uploaded NAR does not match the narinfo FileHash", http.StatusBadRequest)
			return
		}
	}
	if ninfo.FileSize != 0 && ninfo.FileSize != nar.fileSize {
		http.Error(w, "uploaded NAR does not match the narinfo FileSize", http.StatusBadRequest)
		return
	}

	fh, err := os.Open(nar.path)
	if err != nil {
		l.Error("Could not open staged NAR", zap.Error(err))
		http.Error(w, "could not open staged NAR", http.StatusInternalServerError)
		return
	}
	defer fh.Close()

	narReader, err := decompressor(ninfo.Compression, fh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer narReader.Close()

	imported, err := p.writer.ImportNar(r.Context(), &ninfo, narReader)
	if err != nil {
		if rejected, ok := errors.AsType[*nixstore.ErrRejected](err); ok {
			l.Warn("Rejected pushed path", zap.String("reason", rejected.Reason))
			http.Error(w, rejected.Error(), http.StatusBadRequest)
			return
		}
		l.Error("Could not import pushed path", zap.Error(err))
		http.Error(w, "could not import path", http.StatusInternalServerError)
		return
	}
	if imported {
		l.Info("Imported pushed path", zap.Uint64("nar_size", ninfo.NarSize))
	}
	p.recordURL(w, l, &ninfo)
}

// recordURL completes a narinfo upload by recording the URL the client will expect
// to fetch the NAR from.
func (p *PushHandler) recordURL(w http.ResponseWriter, l *zap.Logger, ninfo *nixtypes.NarInfo) {
	if _, err := compressionCodec(ninfo.Compression); err != nil {
		// Can only happen for already valid paths: there's no NAR to serve it from.
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := p.index.Record(ninfo.URL, ninfo.StorePath, ninfo.Compression); err != nil {
		l.Error("Could not record pushed NAR URL", zap.Error(err))
		http.Error(w, "could not record NAR URL", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func remoteUser(r *http.Request) string {
	id, _ := httpauth.IdentityFromContext(r.Context())
	return id.Username
}

// codec compresses and decompresses one of the Nix compression methods.
type codec interface {
	archives.Compressor
	archives.Decompressor
}

// compressionCodec returns the codec for a narinfo Compression value, or nil for none.
func compressionCodec(compression string) (codec, error) {
	switch compression {
	case "", "none":
		return nil, nil
	case "xz":
		return archives.Xz{}, nil
	case "bzip2":
		return archives.Bz2{}, nil
	case "gzip":
		return archives.Gz{}, nil
	case "zstd":
		return archives.Zstd{}, nil
	case "br":
		return archives.Brotli{}, nil
	case "lz4":
		return archives.Lz4{}, nil
	case "lzip":
		return archives.Lzip{}, nil
	default:
		return nil, fmt.Errorf("unsupported compression %q", compression)
	}
}

// decompressor returns a reader for a NAR compressed as named in a narinfo.
func decompressor(compression string, r io.Reader) (io.ReadCloser, error) {
	c, err := compressionCodec(compression)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return io.NopCloser(r), nil
	}
	return c.OpenReader(r)
}

// decodeContentEncoding returns the request body with any Content-Encoding removed
// (Nix sets this when narinfo-compression or ls-compression is used).
func decodeContentEncoding(r *http.Request) (io.ReadCloser, error) {
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
		return r.Body, nil
	case "x-gzip":
		encoding = "gzip"
	}
	return decompressor(encoding, r.Body)
}
