package entrypoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/MadAppGang/httplog"
	lzap "github.com/MadAppGang/httplog/zap"
	"github.com/chigopher/pathlib"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/multihttp"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
	_ "modernc.org/sqlite"
)

type ServeConfig struct {
	resigning.ResigningConfig `embed:""`
	Listen                    []string                        `help:"Listen addresses" default:"tcp://127.0.0.1:8081"`
	Root                      string                          `help:"Root to search for a nix store" default:"/"`
	NixDB                     *string                         `help:"Override the database location"`
	StoreRoot                 *string                         `help:"Override the store root (but not the store path)"`
	StorePath                 string                          `help:"Nix store path to advertise (usually should not be changed)" default:"/nix/store"`
	Priority                  int                             `help:"Nix store priority - lower means greater" default:"40"`
	WantMassQuery             bool                            `help:"Set the WantMassQuery flag" default:"true"`
	RequiredSignatures        []string                        `help:"Return 404 for narinfo if named signatures are not valid on the NARinfo file after resigning"`
	NarInfoFreshDuration      time.Duration                   `help:"Default cache-control to put on NARinfo file responses" default:"0s"`
	ExtendedMetadataSupport   bool                            `help:"Add support for query parameters to return additional metadata" default:"false"`
	NarPathFormat             nixstore.NarURLFormatConvention `help:"Format convention to use for the NAR URLs" default:"nixhash"`
	NoPerformanceCheck        bool                            `help:"Disable the filehash query performance check" default:"false"`
	//CacheEnabled              bool     `help:"Enable binary caching"`
	//CacheFsBackend            string   `help:"Filesystem backend for caching system" default:"os"`
	//CacheFsOpts               string   `help:"Filesystem backend optional config" default:""`
}

// Serve implements a Nix HTTP cache server by reading an extant `/nix` directory
// in flatfile format. It is possible, though not advised, to share this with a system
// nix-daemon.
func Serve(cmdCtx *CmdContext) error {
	l := cmdCtx.logger

	initialRoot := CLI.Serve.Root
	if initialRoot == "/" {
		initialRoot = ""
	}

	root := pathlib.NewPath(initialRoot, pathlib.PathWithAfero(afero.NewOsFs()))
	nixDb, nixStoreRoot := nixstore.DefaultNixStore(root)
	storePath := CLI.Serve.StorePath

	startTime := time.Now()

	if CLI.Serve.NixDB != nil {
		if filepath.IsAbs(*CLI.Serve.NixDB) {
			nixDb = pathlib.NewPath(*CLI.Serve.NixDB, pathlib.PathWithAfero(afero.NewOsFs()))
		} else {
			nixDb = root.Join(*CLI.Serve.NixDB)
		}
	}

	if CLI.Serve.StoreRoot != nil {
		if filepath.IsAbs(*CLI.Serve.StoreRoot) {
			nixStoreRoot = pathlib.NewPath(*CLI.Serve.StoreRoot, pathlib.PathWithAfero(afero.NewOsFs()))
		} else {
			nixStoreRoot = root.Join(*CLI.Serve.StoreRoot)
		}
	}

	l.Info("Server Initializing",
		zap.String("db_path", nixDb.String()),
		zap.String("store_root", nixStoreRoot.String()),
		zap.String("store_path", storePath))

	nixOpts := []nixstore.NixStoreOption{
		nixstore.WithNARURLFormatConvention(CLI.Serve.NarPathFormat),
		nixstore.WithNoPerformanceCheck(CLI.Serve.NoPerformanceCheck),
	}
	store, err := nixstore.NewNixStore(nixDb, nixStoreRoot, storePath, nixOpts...)
	if err != nil {
		l.Error("Error during server startup", zap.Error(err))
		return err
	}

	l.Debug("Loading private keys")
	privateKeys, err := loadPrivateKeys(cmdCtx.logger)
	if err != nil {
		cmdCtx.logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	l.Debug("Loading public keys")
	publicKeys, err := loadPublicKeys(cmdCtx.logger)
	if err != nil {
		cmdCtx.logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	l.Debug("Load signing map")
	signers, err := resigning.LoadSigningMap(l,
		&CLI.Serve.ResigningConfig,
		privateKeys,
		publicKeys,
	)
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	requiredSigs := mapset.NewSet[string](CLI.Serve.RequiredSignatures...)
	for _, sigName := range CLI.Serve.RequiredSignatures {
		if !requiredSigs.Contains(sigName) {
			l.Error("Required signature is not configured as a public key", zap.String("keyname", sigName))
			return errors.Join(&ErrCommand{}, errors.New("required signature not configured as public signature"))
		}
	}

	handlerConfig := &NixHandler{
		Logger:        l,
		StorePath:     storePath,
		WantMassQuery: CLI.Serve.WantMassQuery,
		Priority:      CLI.Serve.Priority,
		RequiredSignatures: lo.FilterSliceToMap(publicKeys, func(item nixtypes.NamedPublicKey) (string, nixtypes.NamedPublicKey, bool) {
			return item.KeyName, item, requiredSigs.Contains(item.KeyName)
		}),
		StartTime:               startTime,
		NarInfoFreshDuration:    CLI.Serve.NarInfoFreshDuration,
		ExtendedMetadataSupport: CLI.Serve.ExtendedMetadataSupport,
		Signers:                 signers,
		Store:                   store,
	}

	l.Info("Starting HTTP server")

	logger := httplog.LoggerWithConfig(
		httplog.LoggerConfig{
			Output:    io.Discard,
			Formatter: lzap.DefaultZapLogger(l, zap.InfoLevel, "Request"),
		},
	)

	webCtx, webCancel := context.WithCancel(cmdCtx.ctx)
	listeners, errCh, listenerErr := multihttp.Listen(CLI.Serve.Listen, logger(handlerConfig))
	if listenerErr != nil {
		l.Error("Error setting up listeners", zap.Error(listenerErr))
		webCancel()
	}
	for _, listener := range listeners {
		l.Info("Listening", zap.String("addr", listener.Addr().String()))
	}

	// Log errors from the listener
	go func() {
		listenerErrInfo := <-errCh
		// On the first error, cancel the webCtx to shutdown
		webCancel()
		for {
			l.Error("Error from listener",
				zap.Error(listenerErrInfo.Error),
				zap.String("listener_addr", listenerErrInfo.Listener.Addr().String()))
			// Keep receiving the rest of the errors so we can log them
			listenerErrInfo = <-errCh
		}
	}()
	<-webCtx.Done()
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			l.Warn("Error closing listener during shutdown", zap.Error(err))
		}
	}

	l.Info("Exiting")
	return nil
}

const NixCacheInfoTemplate = `StoreDir: %s
WantMassQuery: %s
Priority: %d
`

type NixHandler struct {
	Logger *zap.Logger
	// Nix Cache Info parameters
	StorePath     string
	WantMassQuery bool
	Priority      int

	RequiredSignatures map[string]nixtypes.NamedPublicKey

	StartTime time.Time

	NarInfoFreshDuration    time.Duration
	ExtendedMetadataSupport bool

	Signers resigning.ConditionalResigners
	Store   nixstore.NixStore
}

func (n *NixHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Handle both GET and HEAD.
	defer r.Body.Close()

	_, name, _ := strings.Cut(r.URL.Path, "/")

	// Handle the cache info response
	if name == NixCacheInfoName {
		cacheInfoResp := []byte(fmt.Sprintf(NixCacheInfoTemplate, n.StorePath, lo.Ternary(n.WantMassQuery, "1", "0"), n.Priority))

		w.Header().Set(httpheaders.ContentType, "text/x-nix-cache-info")
		w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(cacheInfoResp)))
		w.Header().Set(httpheaders.LastModified, n.StartTime.Format(http.TimeFormat))

		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			// HEAD - no body response
			return
		}
		io.Copy(w, bytes.NewReader(cacheInfoResp))
		return
	}

	if strings.HasSuffix(name, ".narinfo") {
		ninfo, registrationTime, err := n.Store.GetNarInfo(name)
		if err != nil {
			if _, found := errors.AsType[*nixstore.ErrNotFound](err); found {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("not found: %s\n", name)))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("error: %s\n", name)))
			return
		}
		// Return the NARinfo for this URL instead
		n.handleNARInfo(w, r, &ninfo, registrationTime)
		return
	}

	// Treat as a nar file request
	hashName, _, _ := strings.Cut(path.Base(name), ".")
	pathInStore, err := n.Store.GetStorePathByURL(hashName)
	if err != nil {
		if _, found := errors.AsType[*nixstore.ErrNotFound](err); found {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("not found: %s\n", name)))
			return
		} else if _, found := errors.AsType[*nixstore.ErrInvalid](err); found {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("not found: %s\n", name)))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("error: %s\n", name)))
		return
	}

	ninfo, registrationTime, err := n.Store.GetNarInfo(pathInStore)
	lastModified := registrationTime
	if err != nil {
		if _, found := errors.AsType[*nixstore.ErrNotFound](err); found {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("not found: %s\n", name)))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("error: %s\n", name)))
		return
	}

	if n.ExtendedMetadataSupport {
		if r.URL.Query().Get("lookup-narinfo") == "1" {
			// Return the NARinfo for this URL instead
			n.handleNARInfo(w, r, &ninfo, registrationTime)
			return
		}
	}

	w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", ninfo.FileSize))
	w.Header().Set(httpheaders.LastModified, registrationTime.Format(http.TimeFormat))
	w.Header().Set(httpheaders.Etag, ninfo.FileHash.String())
	if ifModifiedSinceHeader := r.Header.Get(httpheaders.IfModifiedSince); ifModifiedSinceHeader != "" {
		ifModifiedSince, err := time.Parse(http.TimeFormat, ifModifiedSinceHeader)
		if err == nil {
			if lastModified.Before(ifModifiedSince) {
				// File has not been modified (or program not restarted) compared to cache value.
				// Return not modified.
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		// Otherwise just proceed as normal
	}
	// When returning a response, set cache-control headers.
	// Binaries are immutable.
	w.Header().Set(httpheaders.CacheControl, "public, immutable")

	if r.Method == http.MethodHead {
		// HEAD - no bodyresponse
		w.WriteHeader(http.StatusOK)
		return
	}

	// GET request - need to write a NAR file
	err = n.Store.GetNar(w, &ninfo)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("internal server error: %s %s\n", name, err.Error())))
		return
	}
	return
}

// handleNARInfo formats a NARinfo file for serving too a client
func (n *NixHandler) handleNARInfo(w http.ResponseWriter, r *http.Request, ninfo *nixtypes.NarInfo, registrationTime time.Time) {
	if n.Signers != nil {
		if _, err := n.Signers.MaybeResign(n.Logger, ninfo); err != nil {
			n.Logger.Warn("Signing Error", zap.String("error", err.Error()))
		}
	}

	if n.RequiredSignatures != nil {
		if len(n.RequiredSignatures) > 0 {
			verified := false
			for _, publicKey := range n.RequiredSignatures {
				if verified, _ = ninfo.Verify(publicKey); verified {
					break
				}
			}
			if !verified {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("not found (invalid signatures): %s\n", ninfo.NixHash())))
				return
			}
		}
	}

	content, err := ninfo.MarshalText()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("error: %s\n", ninfo.NixHash())))
		return
	}
	w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(content)))

	lastModified := lo.Ternary(registrationTime.After(n.StartTime), registrationTime, n.StartTime)
	w.Header().Set(httpheaders.LastModified, lastModified.Format(http.TimeFormat))
	w.Header().Set(httpheaders.ContentType, "text/x-nix-narinfo")
	if ifModifiedSinceHeader := r.Header.Get(httpheaders.IfModifiedSince); ifModifiedSinceHeader != "" {
		ifModifiedSince, err := time.Parse(http.TimeFormat, ifModifiedSinceHeader)
		if err == nil {
			if lastModified.Before(ifModifiedSince) {
				// File has not been modified (or program not restarted) compared to cache value.
				// Return not modified.
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		// Otherwise just proceed as normal
	}
	// When returning a response, set cache-control headers.
	// NARinfo files can change due to resigning changes.
	cacheDirectives := []string{"public"}
	if n.NarInfoFreshDuration > 0 {
		cacheDirectives = append(cacheDirectives, "must-revalidate",
			fmt.Sprintf("max-age=%v", int(n.NarInfoFreshDuration.Seconds())))
	} else {
		cacheDirectives = append(cacheDirectives, "no-cache")
	}
	w.Header().Set(httpheaders.CacheControl, strings.Join(cacheDirectives, ", "))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		// HEAD - no body response
		return
	}
	w.Write(content)
	return
}
