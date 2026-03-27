package entrypoint

import (
	"bytes"
	"context"
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
	"github.com/julienschmidt/httprouter"
	"github.com/spf13/afero"
	"github.com/wrouesnel/multihttp"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
	_ "modernc.org/sqlite"
)

type ServeConfig struct {
	Listen    []string `help:"Listen addresses" default:"tcp://127.0.0.1:8081"`
	Root      string   `help:"Root to search for a nix store" default:"/"`
	NixDB     *string  `help:"Override the database location"`
	StoreRoot *string  `help:"Override the store root (but not the store path)"`
	StorePath string   `help:"Nix store path to advertise (usually should not be changed)" default:"/nix/store"`
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

	store, err := nixstore.NewNixStore(nixDb, nixStoreRoot, storePath)
	if err != nil {
		l.Error("Error during server startup", zap.Error(err))
		return err
	}

	handler := NixHandler(store, storePath, startTime)

	l.Info("Starting HTTP server")
	router := httprouter.New()
	router.GET("/*name", handler)
	router.HEAD("/*name", handler)

	logger := httplog.LoggerWithConfig(
		httplog.LoggerConfig{
			Output:    io.Discard,
			Formatter: lzap.DefaultZapLogger(l, zap.InfoLevel, "Request"),
		},
	)

	webCtx, webCancel := context.WithCancel(cmdCtx.ctx)
	listeners, errCh, listenerErr := multihttp.Listen(CLI.Serve.Listen, logger(router))
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
WantMassQuery: 1
Priority: 40
`

// NixHandler implements the Nix HTTP cache handler. nixStoreRoot is used to set a LastModifiedTime for files in the store
// corresponding to if the directory has been modified.
func NixHandler(store nixstore.NixStore, storePath string, startTime time.Time) httprouter.Handle {
	nixCacheInfoPath := fmt.Sprintf("/%s", NixCacheInfoName)
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// Handle both GET and HEAD.
		defer r.Body.Close()
		name := p.ByName("name")

		// Handle the cache info response
		if name == nixCacheInfoPath {
			cacheInfoResp := []byte(fmt.Sprintf(NixCacheInfoTemplate, storePath))

			w.Header().Set(httpheaders.ContentType, "text/x-nix-cache-info")
			w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(cacheInfoResp)))
			w.Header().Set(httpheaders.LastModified, startTime.Format(http.TimeFormat))

			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				// HEAD - no body response
				return
			}
			io.Copy(w, bytes.NewReader(cacheInfoResp))
			return
		}

		if strings.HasSuffix(name, ".narinfo") {
			ninfo, registrationTime, err := store.GetNarInfo(name)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("error: %s", name)))
				return
			}

			content, err := ninfo.MarshalText()
			w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(content)))
			w.Header().Set(httpheaders.LastModified, registrationTime.Format(http.TimeFormat))
			w.Header().Set(httpheaders.ContentType, "text/x-nix-narinfo")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				// HEAD - no body response
				return
			}
			w.Write(content)
			return
		}

		// Treat as a nar file request
		hashName, _, _ := strings.Cut(path.Base(name), ".")
		pathInStore, err := store.GetStorePathByFileHash(hashName)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("error: %s", name)))
			return
		}

		rdr, ninfo, registrationTime, err := store.GetNar(pathInStore)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("error: %s", name)))
			return
		}
		w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", ninfo.FileSize))
		w.Header().Set(httpheaders.LastModified, registrationTime.Format(http.TimeFormat))
		w.Header().Set(httpheaders.Etag, ninfo.FileHash.String())
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			// HEAD - no bodyresponse
			return
		}
		io.Copy(w, rdr)
		return
	}
}
