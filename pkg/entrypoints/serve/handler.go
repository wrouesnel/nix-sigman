package serve

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixconsts"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
)

const NixCacheInfoTemplate = `StoreDir: %s
WantMassQuery: %s
Priority: %d
`

type NixHandlerConfig struct {
	// Nix Cache Info parameters
	StorePath     string
	WantMassQuery bool
	Priority      int

	RequiredSignatures map[string]nixtypes.NamedPublicKey

	StartTime time.Time

	NarInfoFreshDuration time.Duration
}

// NixHandler implements the Nix HTTP cache handler. nixStoreRoot is used to set a LastModifiedTime for files in the store
// corresponding to if the directory has been modified.
func NixHandler(
	l *zap.Logger,
	store nixstore.NixStore,
	config *NixHandlerConfig,
	signers resigning.ConditionalResigners,
) httprouter.Handle {

	nixCacheInfoPath := fmt.Sprintf("/%s", nixconsts.NixCacheInfoName)

	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// Handle both GET and HEAD.
		defer r.Body.Close()
		name := p.ByName("name")

		// Handle the cache info response
		if name == nixCacheInfoPath {
			cacheInfoResp := []byte(
				fmt.Sprintf(
					NixCacheInfoTemplate,
					config.StorePath,
					lo.Ternary(config.WantMassQuery, "1", "0"),
					config.Priority,
				),
			)

			w.Header().Set(httpheaders.ContentType, nixconsts.NixCacheInfoMimeType)
			w.Header().Set(httpheaders.ContentLength, strconv.Itoa(len(cacheInfoResp)))
			w.Header().Set(httpheaders.LastModified, config.StartTime.Format(http.TimeFormat))

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
				if _, found := errors.AsType[*nixstore.ErrNotFound](err); found {
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(fmt.Sprintf("not found: %s\n", name)))
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("error: %s\n", name)))
				return
			}

			if signers != nil {
				if _, err := signers.MaybeResign(l, &ninfo); err != nil {
					l.Warn("Signing Error", zap.String("error", err.Error()))
				}
			}

			if config.RequiredSignatures != nil {
				if len(config.RequiredSignatures) > 0 {
					verified := false
					for _, publicKey := range config.RequiredSignatures {
						if verified, _ = ninfo.Verify(publicKey); verified {
							break
						}
					}
					if !verified {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(fmt.Sprintf("not found (invalid signatures): %s\n", name)))
						return
					}
				}
			}

			content, err := ninfo.MarshalText()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("error (%s): %s\n", err.Error(), name)))
				return
			}
			w.Header().Set(httpheaders.ContentLength, strconv.Itoa(len(content)))

			lastModified := lo.Ternary(
				registrationTime.After(config.StartTime),
				registrationTime,
				config.StartTime,
			)
			w.Header().Set(httpheaders.LastModified, lastModified.Format(http.TimeFormat))
			w.Header().Set(httpheaders.ContentType, nixconsts.NixCacheNarInfoMimeType)
			if ifModifiedSinceHeader := r.Header.Get(
				httpheaders.IfModifiedSince,
			); ifModifiedSinceHeader != "" {
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
			if config.NarInfoFreshDuration > 0 {
				cacheDirectives = append(cacheDirectives, "must-revalidate",
					fmt.Sprintf("max-age=%v", int(config.NarInfoFreshDuration.Seconds())))
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

		// Treat as a nar file request
		hashName, _, _ := strings.Cut(path.Base(name), ".")
		pathInStore, err := store.GetStorePathByFileHash(hashName)
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

		rdr, ninfo, registrationTime, err := store.GetNar(pathInStore)
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
		w.Header().Set(httpheaders.ContentLength, strconv.FormatUint(ninfo.FileSize, 10))
		w.Header().Set(httpheaders.LastModified, registrationTime.Format(http.TimeFormat))
		w.Header().Set(httpheaders.Etag, ninfo.FileHash.String())
		if ifModifiedSinceHeader := r.Header.Get(
			httpheaders.IfModifiedSince,
		); ifModifiedSinceHeader != "" {
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

		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			// HEAD - no bodyresponse
			return
		}
		io.Copy(w, rdr)
		return
	}
}
