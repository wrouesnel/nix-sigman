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

	PrivateKeyFiles []string `help:"Private Key Files" type:"existingfile"`
	PublicKeyFiles  []string `help:"Public Key Files" type:"existingfile"`

	PrivateKeys []string `help:"Private Keys"`
	PublicKeys  []string `help:"Public Keys"`

	Debug struct {
		ConvertHash struct {
			Hash string "Hash"
		} `cmd:"" help:"Convert between hex and Nix hash encodings"`
		Fingerprint struct {
			Paths []string `arg:"" help:"NARInfo files" type:"existingfile" `
		} `cmd:"" help:"Generate the fingerprint for a NARInfo files"`
		Sign struct {
			Paths []string `arg:"" help:"NARInfo files" type:"existingfile" `
		} `cmd:"" help:"Generate signatures for NARInfo files"`
		GenerateKey struct {
			Name string `arg:"" help:"Name of the key"`
		} `cmd:"" help:"Generate a new key to stdout"`
		PublicKey struct {
		} `cmd:"" help:"Get public key from supplied key on stdin"`
	} `cmd:""`

	Bundle      BundleConfig      `cmd:"" help:"Copy a NAR/NARInfo from the nix store"`
	Sign        SignConfig        `cmd:"" help:"Sign a Nix archive"`
	Verify      VerifyConfig      `cmd:"" help:"Verify a Nix archive signature"`
	Validate    ValidateConfig    `cmd:"" help:"Validate a NarInfo file format"`
	Derivations DerivationsConfig `cmd:"" help:"Manipulate derivations"`
}

// Entrypoint is the real application entrypoint. This structure allows test packages to E2E-style tests invoking commmands
// as though they are on the command line, but using built-in coverage tools. Stub-main under the `cmd` package calls this
// function.
func Entrypoint(stdIn io.ReadCloser, stdOut io.Writer, stdErr io.Writer) int {
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
		kong.DefaultEnvars(version.Name),
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
	logger.Debug("Using config paths", zap.Strings("configDirs", configDirs))
	for _, line := range deferredLogs {
		logger.Error(line)
	}

	//logger.Info("Configuring asset handling", zap.Bool("use-filesystem", CLI.Assets.UseFilesystem))
	//assets.UseFilesystem(CLI.Assets.UseFilesystem)

	if err := dispatchCommands(ctx, sigCtx, stdIn, stdOut); err != nil {
		logger.Error("Error from command", zap.Error(err))
	}

	logger.Debug("Exiting normally")
	return 0
}
