package entrypoint

import (
	"context"
	"errors"
	"fmt"
	"github.com/MadAppGang/httplog"
	lzap "github.com/MadAppGang/httplog/zap"
	"github.com/chigopher/pathlib"
	"github.com/julienschmidt/httprouter"
	"github.com/wrouesnel/multihttp"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
	"io"
	"net/http"
	"strings"
)

//nolint:gochecknoglobals
type ProxyConfig struct {
	SigningMap map[string]string `help:"Map of public key names to private key names to sign if present"`
	Listen     []string          `help:"Listen addresses" default:"tcp://127.0.0.1:8080"`
	Root       string            `arg:"" help:"Root path of the binary cache"`
}

// Proxy implements the dynamic resigning server
func Proxy(cmdCtx *CmdContext) error {
	l := cmdCtx.logger

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

	l.Info("Building resigning map")
	signers, err := buildSigningMap(publicKeys, privateKeys, CLI.Proxy.SigningMap)
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	rootDir := pathlib.NewPath(CLI.Proxy.Root, pathlib.PathWithAfero(cmdCtx.fs)).Clean()
	l.Info("Serving cache from", zap.String("output_dir", rootDir.String()))

	handle := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		defer r.Body.Close()
		name := p.ByName("name")
		requestName := rootDir.Join(name).Clean()

		if name == NixCacheInfoName {
			fh, err := requestName.Open()
			defer fh.Close()
			if err != nil {
				l.Warn("File Not Found", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
				return
			}

			w.Header().Set(httpheaders.ContentType, "text/x-nix-cache-info")
			w.WriteHeader(http.StatusOK)
			io.Copy(w, fh)
		}

		if strings.HasSuffix(name, ".narinfo") {
			ninfo, err := loadNarInfo(l, requestName)
			if err != nil {
				l.Warn("File Not Found", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
				return
			}

			didNewSignature := false
			for _, signer := range signers {
				didSign, err := signer(&ninfo)
				if err != nil {
					l.Warn("Signing Error", zap.String("error", err.Error()))
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Signing Error: %s", name)))
				}
				if didSign {
					didNewSignature = true
				}
			}
			if didNewSignature {
				l.Debug("Resigned narinfo file", zap.String("name", name))
			} else {
				l.Debug("No match narinfo file", zap.String("name", name))
			}

			content, err := ninfo.MarshalText()
			if err != nil {
				l.Warn("Marshalling Error", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Signing Error: %s", name)))
			}

			w.WriteHeader(http.StatusOK)
			w.Write(content)
			return
		}
		fh, err := requestName.Open()
		if err != nil {
			l.Warn("File Not Found", zap.String("error", err.Error()))
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
			return
		}
		defer fh.Close()
		w.WriteHeader(http.StatusOK)
		io.Copy(w, fh)
	}

	l.Info("Starting HTTP server")
	router := httprouter.New()
	router.GET("/*name", handle)

	logger := httplog.LoggerWithConfig(
		httplog.LoggerConfig{
			Output:    io.Discard,
			Formatter: lzap.DefaultZapLogger(l, zap.InfoLevel, "Request"),
		},
	)

	webCtx, webCancel := context.WithCancel(cmdCtx.ctx)
	listeners, errCh, listenerErr := multihttp.Listen(CLI.Proxy.Listen, logger(router))
	if listenerErr != nil {
		l.Error("Error setting up listeners", zap.Error(listenerErr))
		webCancel()
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
