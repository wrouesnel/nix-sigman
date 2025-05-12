package entrypoint

import (
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/spf13/afero"
	"go.uber.org/zap"
	"io"
)

type ErrCommandNotImplemented struct {
	Command string
}

func (e ErrCommandNotImplemented) Error() string {
	return fmt.Sprintf("%s not implemented", e.Command)
}

type ErrCommand struct {
}

func (e ErrCommand) Error() string {
	return "command error"
}

// CmdContect packages common parameters for CLI commands
type CmdContext struct {
	logger *zap.Logger
	ctx    context.Context
	stdIn  io.ReadCloser
	stdOut io.Writer
	fs     afero.Fs
}

// Main command dispatcher for the program entrypoint. New commands should be added here, or they won't be
// invocable.
//
//nolint:revive
func dispatchCommands(ctx *kong.Context, cmdCtx *CmdContext) error {
	var err error
	logger := zap.L().With(zap.String("command", ctx.Command()))

	switch ctx.Command() {
	case "server":
		err = Server(cmdCtx)
	case "sign <nar-info-files>":
		err = Sign(cmdCtx)

	case "verify <nar-info-files>":
		err = Verify(cmdCtx)

	case "validate <nar-info-files>":
		err = Validate(cmdCtx)

	case "bundle <paths>":
		err = Bundle(cmdCtx)

	case "derivations show <paths>":
		err = DerivationShow(cmdCtx)

	case "debug extract-tar":
		err = DebugExtractTar(cmdCtx)

	case "debug generate-key <name>":
		err = DebugGenerateKey(cmdCtx)

	case "debug public-key":
		err = DebugPublicKey(cmdCtx)

	case "debug fingerprint <paths>":
		err = DebugFingerprint(cmdCtx)

	case "debug sign <paths>":
		err = DebugSign(cmdCtx)

	case "debug convert-hash <hash>":
		err = DebugConvertHash(cmdCtx)

	case "debug from-bytes <format>":
		err = DebugFromBytes(cmdCtx)

	case "debug to-bytes <format>":
		err = DebugToBytes(cmdCtx)

	case "debug extract-tar <output-dir>":
		err = DebugExtractTar(cmdCtx)

	case "debug extract-tar <output-dir> <input-file>":
		err = DebugExtractTar(cmdCtx)

	default:
		err = &ErrCommandNotImplemented{Command: ctx.Command()}
		logger.Error("Command not implemented")
	}

	if err != nil {
		logger.Error("Error from command", zap.Error(err))
		return err
	}
	return nil
}
