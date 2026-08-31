package api

import (
	"context"
	"reflect"
	"strings"

	"github.com/labstack/echo/v5"
	logutil "github.com/wrouesnel/go.logutil"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/serve"
	"go.uber.org/zap"
)

type Empty struct{}

func NewAPI(ctx context.Context, server serve.CacheServer) (api ServerInterface, apiVersion string) {
	packagePath := strings.Split(reflect.TypeFor[Empty]().PkgPath(), "/")
	apiVersion = packagePath[len(packagePath)-2]

	return &apiImpl{
		logger: logutil.FromCtx(ctx).With(zap.String("api_version", apiVersion)),
		server: server,
	}, apiVersion
}

// apiImpl links the OpenAPI generated spec to the actual code.
type apiImpl struct {
	logger *zap.Logger
	server serve.CacheServer
}

func (a *apiImpl) PostAuthKerberos(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) PostAuthPassword(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) GetKeysAvailable(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) PostKeysAvailable(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) PostKeysGenerate(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) GetPing(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) GetServeResigning(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) PostServeResigning(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) GetUploadAcceptedKeys(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}

func (a *apiImpl) PostUploadAcceptedKeys(ctx *echo.Context) error {
	//TODO implement me
	panic("implement me")
}
