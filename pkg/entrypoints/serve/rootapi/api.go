package rootapi

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
	logutil "github.com/wrouesnel/go.logutil"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/context"
)

type Empty struct{}

func NewAPI(ctx context.Context, store nixstore.NixStore) (api ServerInterface, apiVersion string) {
	apiVersion = ""

	return &apiImpl{
		logger: logutil.FromCtx(ctx).With(logutil.SubsysLogger("nix-binary-cache server")),
		store:  store,
	}, apiVersion
}

// apiImpl links the OpenAPI generated spec to the actual code.
type apiImpl struct {
	logger *zap.Logger
	store  nixstore.NixStore
}

func (a *apiImpl) GetNixCacheInfo(ctx *echo.Context) error {
	cacheInfo, err := a.store.GetNixCacheInfo().MarshalText()
	if err != nil {
		return ctx.Blob(http.StatusInternalServerError,
			"text/plain", fmt.Appendf([]byte{}, "internal server error: %v", err.Error()))
	}
	return ctx.Blob(http.StatusOK, nixstore.MimeTypeNixCacheInfo, cacheInfo)
}

func (a *apiImpl) GetNixhashNarinfo(ctx *echo.Context, nixhash string) error {
	ninfo, registrationTime, err := a.store.GetNarInfo(nixhash)
	if _, found := errors.AsType[*nixstore.ErrNotFound](err); found {
		return ctx.Blob(http.StatusNotFound,
			"text/plain", fmt.Appendf([]byte{}, "not found: %v", err.Error()))
	} else if err != nil {
		return ctx.Blob(http.StatusInternalServerError,
			"text/plain", fmt.Appendf([]byte{}, "internal server error: %v", err.Error()))
	}
	return a.handleNARInfo(ctx, &ninfo, registrationTime)
}

func (a *apiImpl) handleNARInfo(ctx *echo.Context, ninfo *nixtypes.NarInfo, registrationTime time.Time) error {

}

func (a *apiImpl) GetNarPathNar(ctx *echo.Context, path string) error {
	//TODO implement me
	panic("implement me")
}
