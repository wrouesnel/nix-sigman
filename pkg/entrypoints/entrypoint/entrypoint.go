package entrypoint

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/url"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	s3 "github.com/fclairamb/afero-s3"
	"github.com/labstack/gommon/log"
	"github.com/spf13/afero"
	"github.com/wrouesnel/kongutil"
	nix_http_cachefs "github.com/wrouesnel/nix-http-cachefs"
	"go.uber.org/zap/zapcore"

	"io"
	"os"
	"strings"

	//gap "github.com/muesli/go-app-paths"
	//"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/version"
	"go.uber.org/zap"
)

//nolint:gochecknoglobals
var CLI struct {
	Version kong.VersionFlag `help:"Show version number"`

	Logging struct {
		Level  string `help:"logging level" default:"info"`
		Format string `help:"logging format (${enum})" enum:"console,json" default:"console"`
	} `embed:"" prefix:"log-"`

	FsBackend string `help:"Filesystem backend for the binary cache" enum:"os,s3,nix-http-cache" default:"os"`
	FsOpts    string `help:"Additional options for the filesystem handler" default:""`

	PrivateKeyFiles []string `help:"Private Key Files" type:"existingfile"`
	PublicKeyFiles  []string `help:"Public Key Files" type:"existingfile"`

	PrivateKeys []string `help:"Private Keys"`
	PublicKeys  []string `help:"Public Keys"`

	Debug struct {
		FromBytes struct {
			Format string `arg:"" help:"Format to output as" enum:"nix32,base64,hex"`
		} `cmd:"" help:"Output the given bytes as a specific format"`
		ToBytes struct {
			Format string `arg:"" help:"Format of the input" enum:"nix32,base64,hex"`
		} `cmd:"" help:"Convert the given input bytes to a specific format"`
		ConvertHash struct {
			Hash string `arg:"" help:"Hash to convert (hex or nix)"`
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
		ExtractTar struct {
			Dryrun    bool   `help:"Don't actually extract anything'"`
			Prefix    string `help:"Path prefix to match and remove while extracting"`
			OutputDir string `arg:"" help:"Path to extract to" default:"."`
			InputFile string `arg:"" help:"tar file (blank or - for stdin)" optional:"" default:"-"`
		} `cmd:"" help:"Extract tarball containing a binary cache to the target"`
		List struct {
			Prefix string `help:"Prefix to list files under" default:"."`
		} `cmd:"" help:"List all narinfo files in target"`
	} `cmd:""`

	Bundle       BundleConfig       `cmd:"" help:"Copy a NAR/NARInfo from the nix store"`
	Sign         SignConfig         `cmd:"" help:"Sign a Nix archive"`
	Verify       VerifyConfig       `cmd:"" help:"Verify a Nix archive signature"`
	Validate     ValidateConfig     `cmd:"" help:"Validate a NarInfo file format"`
	Derivations  DerivationsConfig  `cmd:"" help:"Manipulate derivations"`
	Realizations RealizationsConfig `cmd:"" help:"Manipulate binary packages"`
	Proxy        ProxyConfig        `cmd:"" help:"Serve a binary cache with resigning"`
	NewKey       NewKeyConfig       `cmd:"" help:"Generate a new signing keypair for the current user"`
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
	logConfig.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
	if CLI.Logging.Format == "console" {
		logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

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

	cmdCtx := &CmdContext{
		logger: logger,
		ctx:    sigCtx,
		stdIn:  stdIn,
		stdOut: stdOut,
	}

	switch CLI.FsBackend {
	case "os":
		cmdCtx.fs = afero.NewOsFs()
		if CLI.FsOpts != "" {
			logger.Error("--fs-opts has no effect for the OS backend and must be blank")
			return 1
		}
	case "s3":
		// At debug level, print some logging about what which AWS environment variables are set
		// since this is *very* annoying to debug.
		for _, env := range os.Environ() {
			envname, envvalue, _ := strings.Cut(env, "=")
			if strings.HasPrefix(envname, "AWS_") {
				fields := []zap.Field{zap.String("name", envname)}
				if envname != "AWS_SECRET_ACCESS_KEY" {
					fields = append(fields, zap.String("value", envvalue))
				} else {
					fields = append(fields, zap.String("value", "**OMITTED**"),
						zap.Bool("ellided_value", true))
				}
				if envvalue != "" {
					logger.Debug("AWS Environment variable is set", fields...)
				} else {
					logger.Debug("AWS Environment variable is NOT set", fields...)
				}
			}
		}
		// In truly frustrating style, endpoint overrides aren't supported till V2,
		// which this library isn't based on. Hack them in here.
		endpointUrl := new(string)
		if os.Getenv("AWS_ENDPOINT_URL") != "" {
			*endpointUrl = os.Getenv("AWS_ENDPOINT_URL")
		}
		if os.Getenv("AWS_ENDPOINT_URL_S3") != "" {
			*endpointUrl = os.Getenv("AWS_ENDPOINT_URL_S3")
		}
		forcePathStyle := new(bool)
		if endpointUrl != nil {
			*forcePathStyle = true
		}
		sess, err := session.NewSessionWithOptions(session.Options{
			Config:            aws.Config{Endpoint: endpointUrl, S3ForcePathStyle: forcePathStyle},
			SharedConfigState: session.SharedConfigEnable,
		})
		if err != nil {
			logger.Error("Error creating S3 session", zap.Error(err))
			return 1
		}
		s3fs := s3.NewFs(CLI.FsOpts, sess)
		if s3fs == nil {
			logger.Error("Error initializing the S3 FS")
			return 1
		}
		cmdCtx.fs = s3fs
	case "nix-http-cache":
		rdr := csv.NewReader(strings.NewReader(CLI.FsOpts))
		rdr.LazyQuotes = true
		rdr.TrimLeadingSpace = true
		record, err := rdr.Read()
		if err != nil {
			logger.Error("Error parsing FS opts", zap.Error(err))
			return 1
		}
		if len(record) == 0 {
			logger.Error("Must specify at least an URL to an HTTP nix cache server")
			return 1
		}
		cacheUrls := []*url.URL{}
		urlsFinished := false
		opts := []nix_http_cachefs.Opt{}
		for _, field := range record {
			key, value, ok := strings.Cut(field, "=")
			if !urlsFinished && !ok {
				cacheUrl, err := url.Parse(field)
				if err != nil {
					logger.Error("Error parsing supplied URL for nix-http-cache type", zap.Error(err))
					return 1
				}
				cacheUrls = append(cacheUrls, cacheUrl)
				continue
			} else if !urlsFinished {
				urlsFinished = true
			}
			if !ok {
				logger.Error("Unparseable field option found", zap.String("field", field))
				return 1
			}
			switch key {
			case "netrc-file":
				opts = append(opts, nix_http_cachefs.NetrcFile(value))
			default:
				logger.Error("Unknown field key found", zap.String("field", field))
				return 1
			}
		}
		opts = append(opts, nix_http_cachefs.ErrorLogger(func(msg string) {
			logger.Error(msg, zap.String("fs-backend", "nix-http-cache"))
		}), nix_http_cachefs.DebugLogger(func(msg string) {
			logger.Debug(msg, zap.String("fs-backend", "nix-http-cache"))
		}))
		fs, err := nix_http_cachefs.NewNixHttpCacheFs(cacheUrls, opts...)
		if err != nil {
			logger.Error("Bad configuration for nix-cache-httpfs backend", zap.String("filesystem", CLI.FsBackend), zap.Error(err))
			return 1
		}
		cmdCtx.fs = fs
	default:
		logger.Error("Invalid filesystem backend", zap.String("filesystem", CLI.FsBackend))
		return 1
	}

	if err := dispatchCommands(ctx, cmdCtx); err != nil {
		logger.Error("Error from command", zap.Error(err))
	}

	logger.Debug("Exiting normally")
	return 0
}
