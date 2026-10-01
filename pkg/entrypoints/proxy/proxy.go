package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/MadAppGang/httplog"
	lzap "github.com/MadAppGang/httplog/zap"
	"github.com/chigopher/pathlib"
	"github.com/julienschmidt/httprouter"
	"github.com/mailgun/multibuf"
	"github.com/wrouesnel/multihttp"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/cmdutil"
	"github.com/wrouesnel/nix-sigman/pkg/nixconsts"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
)

//nolint:gochecknoglobals
type ProxyConfig struct {
	resigning.ResigningConfig `embed:""`
	AllowPush                 bool                      `help:"Enable writing to the proxied store"`
	PushResigningConfig       resigning.ResigningConfig `embed:"" prefix:"push-"`
	PushRequiresResigning     bool                      `help:"Require pushed packages to match a resigning rule"`
	PushOverwrite             bool                      `help:"Try and overwrite conflicting store paths if they're non-identical'"`
	Listen                    []string                  `help:"Listen addresses" default:"tcp://127.0.0.1:8080"`
	Root                      string                    `arg:"" help:"Root path of the binary cache"`
}

// Proxy implements the dynamic resigning server
func Proxy(cmdCtx *cmdutil.CmdContext, cfg *ProxyConfig) error {
	l := cmdCtx.Logger

	l.Debug("Loading private keys")
	privateKeys, err := cmdCtx.Keys.LoadPrivateKeys(cmdCtx.Logger)
	if err != nil {
		cmdCtx.Logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	l.Debug("Loading public keys")
	publicKeys, err := cmdCtx.Keys.LoadPublicKeys(cmdCtx.Logger)
	if err != nil {
		cmdCtx.Logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	l.Debug("Load signing map")
	signers, err := resigning.LoadSigningMap(l,
		&cfg.ResigningConfig,
		privateKeys,
		publicKeys,
	)
	if err != nil {
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	l.Debug("Load push signing map")
	var pushSigners resigning.ConditionalResigners
	if cfg.AllowPush {
		pushSigners, err = resigning.LoadSigningMap(l,
			&cfg.PushResigningConfig,
			privateKeys,
			publicKeys)
		if err != nil {
			return errors.Join(&cmdutil.ErrCommand{}, err)
		}
	}

	rootDir := pathlib.NewPath(cfg.Root, pathlib.PathWithAfero(cmdCtx.Fs)).Clean()
	l.Info("Serving cache from", zap.String("output_dir", rootDir.String()))

	router := newRouter(l, cfg, rootDir, signers, pushSigners)

	l.Info("Starting HTTP server")
	logger := httplog.LoggerWithConfig(
		httplog.LoggerConfig{
			Output:    io.Discard,
			Formatter: lzap.DefaultZapLogger(l, zap.InfoLevel, "Request"),
		},
	)

	webCtx, webCancel := context.WithCancel(cmdCtx.Ctx)
	listeners, errCh, listenerErr := multihttp.Listen(cfg.Listen, logger(router))
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

// newRouter builds the HTTP handler which serves (and optionally accepts pushes to)
// the binary cache at rootDir.
func newRouter(l *zap.Logger, cfg *ProxyConfig, rootDir *pathlib.Path,
	signers resigning.ConditionalResigners, pushSigners resigning.ConditionalResigners) *httprouter.Router {
	handle := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// Handle both GET and HEAD.
		defer r.Body.Close()
		// Clean the request path as a rooted path first so ".." segments can never
		// escape the cache root, then make it relative. The router does not clean
		// paths for us, and the catch-all parameter includes the leading "/".
		name := strings.TrimPrefix(path.Clean("/"+p.ByName("name")), "/")
		requestName := rootDir.Join(name).Clean()
		// Stat the request path so HEAD requests can work
		st, err := requestName.Stat()
		if err != nil {
			st = nil
		}

		if name == nixconsts.NixCacheInfoName {
			if r.Method == http.MethodPut {
				// Push mode does not allow changing cache parameters
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Forbidden")))
				return
			}
			fh, err := requestName.Open()
			defer fh.Close()
			if err != nil {
				l.Warn("File Not Found", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusNotFound)
				if r.Method == http.MethodHead {
					// HEAD - no body response
					return
				}
				w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
				return
			}

			w.Header().Set(httpheaders.ContentType, "text/x-nix-cache-info")
			if st != nil {
				w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", st.Size()))
				w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
			}
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				// HEAD - no body response
				return
			}
			io.Copy(w, fh)
			return
		}

		// narinfo files
		if strings.HasSuffix(name, ".narinfo") {
			if r.Method == http.MethodPut {
				l.Debug("Receiving new NAR info file")
				ninfoReceiver, err := multibuf.NewWriterOnce()
				if err != nil {
					l.Info("Error setting up new buffer space", zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error: %s", name)))
					return
				}
				nBytes, err := io.Copy(ninfoReceiver, r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error: %s", name)))
					return
				}
				ninfoReader, err := ninfoReceiver.Reader()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error: %s", name)))
					return
				}
				ninfoBytes, err := io.ReadAll(ninfoReader)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error: %s", name)))
					return
				}

				receivedNinfo := nixtypes.NarInfo{}
				if err := receivedNinfo.UnmarshalText(ninfoBytes); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(fmt.Sprintf("Bad Request (could not parse NARinfo file): %s", name)))
					return
				}

				l.Debug("Received new NAR info file", zap.Int64("num_bytes", nBytes))
				if pushSigners != nil {
					if didSignature, err := pushSigners.MaybeResign(l, &receivedNinfo); err != nil {
						l.Warn("Signing Error", zap.String("error", err.Error()))
						w.WriteHeader(http.StatusBadRequest)
						w.Write([]byte(fmt.Sprintf("Signing Error: %s", name)))
						return
					} else if !didSignature && cfg.PushRequiresResigning {
						w.WriteHeader(http.StatusForbidden)
						w.Write([]byte(fmt.Sprintf("Forbidden (supplied path did not match any push resigning rules): %s", name)))
						return
					}
				} else if cfg.PushRequiresResigning && pushSigners == nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error (resigning required but no resigners configured): %s", name)))
					return
				}

				marshalledNinfo, err := receivedNinfo.MarshalText()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error (could not marshal resigned received NARinfo): %s", name)))
					return
				}

				// We now have a resigned NAR ready to go to the backend.
				// Check for an existing file. Note: resigning configs might change
				// what would be actually returned, but the upload system deals solely
				// in what's actually going to be stored.
				ninfo, err := cmdutil.LoadNarInfo(l, requestName)
				if err == nil {
					// Got an existing NAR info, is it equivalent to the one we currently have?
					if bytes.Equal(receivedNinfo.Fingerprint(), ninfo.Fingerprint()) {
						// Yes. Copy signatures to the existing file and resave it.
						// Note: this is based on key identity - clashing keys ignore the
						// incoming nar-info.
						existingSigs := map[string]nixtypes.NixSignature{}
						for _, sig := range ninfo.Sig {
							existingSigs[sig.KeyName] = sig
						}
						changed := false
						for _, sig := range receivedNinfo.Sig {
							if _, found := existingSigs[sig.KeyName]; !found {
								changed = true
								ninfo.Sig = append(ninfo.Sig, sig)
							}
						}
						marshalledNinfo, err = ninfo.MarshalText()
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							w.Write([]byte(fmt.Sprintf("Internal Server Error (could not marshal resigned received NARinfo): %s", name)))
							return
						}
						if !changed {
							// No changes - return immediately.
							w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(marshalledNinfo)))
							w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
							w.WriteHeader(http.StatusOK)
							io.Copy(w, bytes.NewReader(marshalledNinfo))
							return
						}
					} else {
						if !cfg.PushOverwrite {
							w.WriteHeader(http.StatusConflict)
							w.Write([]byte(fmt.Sprintf("Conflict: Remote path already exists and replacing is not allowed: %s", name)))
						} else {
							l.Info("Overwriting colliding store path with incoming one")
						}
					}
				}

				l.Debug("Uploading new NAR info file")
				f, err := requestName.OpenFile(os.O_CREATE | os.O_WRONLY)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error (could not create file): %s", name)))
					return
				}
				_, err = io.Copy(f, bytes.NewReader(marshalledNinfo))
				f.Close()
				if err != nil {
					l.Error("Error writing NARinfo file to backend", zap.Error(err))
					l.Debug("Attempting to remove partially written file")
					if err := requestName.Remove(); err != nil {
						l.Error("Could not remove partially written file", zap.Error(err))
					}
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error (could not write file): %s", name)))
					return
				}
				// Stat the result
				st, err = requestName.Stat()
				if err != nil {
					// If we can't stat the path after writing it, something has gone wrong.
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(fmt.Sprintf("Internal Server Error (could not stat new file): %s", name)))
					return
				}

				// Success uploading new NARinfo
				w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(marshalledNinfo)))
				w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
				w.WriteHeader(http.StatusOK)
				io.Copy(w, bytes.NewReader(marshalledNinfo))
				return
			}

			ninfo, err := cmdutil.LoadNarInfo(l, requestName)
			if err != nil {
				//l.Warn("File Not Found", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusNotFound)
				if r.Method == http.MethodHead {
					// HEAD - no body response
					return
				}
				w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
				return
			}

			if _, err := signers.MaybeResign(l, &ninfo); err != nil {
				l.Warn("Signing Error", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Signing Error: %s", name)))
				return
			}

			content, err := ninfo.MarshalText()
			if err != nil {
				l.Warn("Marshalling Error", zap.String("error", err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				if r.Method == http.MethodHead {
					// HEAD - no body response
					return
				}
				w.Write([]byte(fmt.Sprintf("Signing Error: %s", name)))
			}

			if st != nil {
				w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", len(content)))
				w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
			}
			w.Header().Set(httpheaders.ContentType, "text/x-nix-narinfo")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				// HEAD - no body response
				return
			}
			w.Write(content)
			return
		}
		// Everything else
		if st != nil {
			w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
		}
		switch r.Method {
		case http.MethodHead:
			if st != nil {
				w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", st.Size()))
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(fmt.Sprintf("Not Found: %s", name)))
			}
			return
		case http.MethodGet:
			if st != nil {
				w.Header().Set(httpheaders.ContentLength, fmt.Sprintf("%d", st.Size()))
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
			return
		case http.MethodPut:
			// PUT is only allowed to create files. I'm sure I'll get burned by this
			// in the near future, but I'm not sure how yet.
			if st != nil {
				// We include one exception here: 0-byte files are basically always going to be
				// errors. If the file (from above) is 0-bytes, then delete it and continue.
				if st.Size() == 0 {
					l.Debug("Removing 0-byte file and continuing")
					if err := requestName.Remove(); err != nil {
						l.Error("Could not remove partially written file", zap.Error(err))
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(fmt.Sprintf("Internal Server Error (could not remove 0-byte file): %s", name)))
						return
					}
				} else {
					l.Debug("Forbidding upload erasing existing file")
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Forbidden (overwriting existing files not allowed): %s", name)))
					return
				}
			}
			f, err := requestName.OpenFile(os.O_CREATE | os.O_WRONLY)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Internal Server Error (could not open file): %s", name)))
				return
			}
			nbytes, err := io.Copy(f, r.Body)
			f.Close()
			l.Info("Copied incoming file to backend", zap.Int64("nbytes", nbytes))
			if err != nil {
				l.Error("Error writing file", zap.Error(err))
				l.Debug("Attempting to remove partially written file")
				if err := requestName.Remove(); err != nil {
					l.Error("Could not remove partially written file", zap.Error(err))
				}
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Internal Server Error (could not write received file): %s", name)))
				return
			}

			st, err = requestName.Stat()
			if err != nil {
				// If we can't stat the path after writing it, something has gone wrong.
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("Internal Server Error (could not stat new file): %s", name)))
				return
			}
			w.Header().Set(httpheaders.LastModified, st.ModTime().Format(http.TimeFormat))
			w.WriteHeader(http.StatusCreated)
			return
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(fmt.Sprintf("Method Not Allowed: %s", r.Method)))
			return
		}
	}

	router := httprouter.New()
	router.GET("/*name", handle)
	router.HEAD("/*name", handle)

	if cfg.AllowPush {
		l.Info("Push to proxied store enabled!")
		router.PUT("/*name", handle)
	}

	return router
}
