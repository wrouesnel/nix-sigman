package entrypoint

import (
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/labstack/gommon/log"
	"github.com/wrouesnel/kongutil"
	"os/signal"
	"syscall"

	//gap "github.com/muesli/go-app-paths"
	//"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/version"
	"go.uber.org/zap"
	"io"
	"os"
	"strings"
)

//nolint:gochecknoglobals
var CLI struct {
	Version kong.VersionFlag `help:"Show version number"`

	Logging struct {
		Level  string `help:"logging level" default:"info"`
		Format string `help:"logging format (${enum})" enum:"console,json" default:"console"`
	} `embed:"" prefix:"log-"`
}

// Entrypoint is the real application entrypoint. This structure allows test packages to E2E-style tests invoking commmands
// as though they are on the command line, but using built-in coverage tools. Stub-main under the `cmd` package calls this
// function.
func Entrypoint(stdOut io.Writer, stdErr io.Writer) int {
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	var configDirs []string
	deferredLogs := []string{}

	configfileEnvVar := fmt.Sprintf("%s_%s", strings.ToUpper(version.Name), "CONFIGFILE")
	if os.Getenv(configfileEnvVar) != "" {
		configDirs = []string{os.Getenv(configfileEnvVar)}
	} else {
		configDirs, deferredLogs = configDirListGet()
	}

	// Command line parsing can now happen
	vars := kong.Vars{"version": version.Version}
	ctx := kong.Parse(&CLI,
		kong.Description(version.Description),
		kong.Configuration(kongutil.Hybrid, configDirs...), vars)

	// Initialize logging as soon as possible
	logConfig := zap.NewProductionConfig()
	if err := logConfig.Level.UnmarshalText([]byte(CLI.Logging.Level)); err != nil {
		deferredLogs = append(deferredLogs, err.Error())
	}
	logConfig.Encoding = CLI.Logging.Format

	logger, err := logConfig.Build()
	if err != nil {
		// Error unhandled since this is a very early failure
		_, _ = io.WriteString(stdErr, "Failure while building logger")
		return 1
	}

	logger.Debug("Configuring signal handling")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sigCtx, cancelFn := context.WithCancel(appCtx)
	go func() {
		sig := <-sigCh
		log.Info("Caught signal - exiting", zap.String("signal", sig.String()))
		cancelFn()
	}()

	// Install as the global logger
	zap.ReplaceGlobals(logger)

	// Emit deferred logs
	logger.Info("Using config paths", zap.Strings("configDirs", configDirs))
	for _, line := range deferredLogs {
		logger.Error(line)
	}

	//logger.Info("Configuring asset handling", zap.Bool("use-filesystem", CLI.Assets.UseFilesystem))
	//assets.UseFilesystem(CLI.Assets.UseFilesystem)

	if err := dispatchCommands(ctx, sigCtx, stdOut); err != nil {
		logger.Error("Error from command", zap.Error(err))
	}

	logger.Info("Exiting normally")
	return 0
}
