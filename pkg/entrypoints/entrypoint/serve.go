package entrypoint

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/MadAppGang/httplog"
	lzap "github.com/MadAppGang/httplog/zap"
	"github.com/chigopher/pathlib"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/julienschmidt/httprouter"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/multihttp"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
)

type ServeConfig struct {
	resigning.ResigningConfig `embed:""`
	Listen                    []string      `         help:"Listen addresses"                                                                             default:"tcp://127.0.0.1:8081"`
	Root                      string        `         help:"Root to search for a nix store"                                                               default:"/"`
	NixDB                     *string       `         help:"Override the database location"`
	StoreRoot                 *string       `         help:"Override the store root (but not the store path)"`
	StorePath                 string        `         help:"Nix store path to advertise (usually should not be changed)"                                  default:"/nix/store"`
	Priority                  int           `         help:"Nix store priority - lower means greater"                                                     default:"40"`
	WantMassQuery             bool          `         help:"Set the WantMassQuery flag"                                                                   default:"true"`
	RequiredSignatures        []string      `         help:"Return 404 for narinfo if named signatures are not valid on the NARinfo file after resigning"`
	NarInfoFreshDuration      time.Duration `         help:"Default cache-control to put on NARinfo file responses"                                       default:"0s"`
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
			nixStoreRoot = pathlib.NewPath(
				*CLI.Serve.StoreRoot,
				pathlib.PathWithAfero(afero.NewOsFs()),
			)
		} else {
			nixStoreRoot = root.Join(*CLI.Serve.StoreRoot)
		}
	}

	l.Info("Server Initializing",
		zap.String("db_path", nixDb.String()),
		zap.String("store_root", nixStoreRoot.String()),
		zap.String("store_path", storePath))

	store, err := nixstore.NewNixStore(cmdCtx.ctx, nixDb, nixStoreRoot, storePath)
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
			l.Error(
				"Required signature is not configured as a public key",
				zap.String("keyname", sigName),
			)
			return errors.Join(
				&ErrCommand{},
				errors.New("required signature not configured as public signature"),
			)
		}
	}

	handlerConfig := &serve.NixHandlerConfig{
		StorePath:     storePath,
		WantMassQuery: CLI.Serve.WantMassQuery,
		Priority:      CLI.Serve.Priority,
		RequiredSignatures: lo.FilterSliceToMap(
			publicKeys,
			func(item nixtypes.NamedPublicKey) (string, nixtypes.NamedPublicKey, bool) {
				return item.KeyName, item, requiredSigs.Contains(item.KeyName)
			},
		),
		StartTime:            startTime,
		NarInfoFreshDuration: CLI.Serve.NarInfoFreshDuration,
	}
	handler := serve.NixHandler(l, store, handlerConfig, signers)

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
