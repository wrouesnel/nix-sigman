package entrypoint

import (
	"context"
	"fmt"
	"github.com/alecthomas/kong"
	"go.uber.org/zap"
	"io"
)

type ErrCommandNotImplemented struct {
	Command string
}

func (e ErrCommandNotImplemented) Error() string {
	return fmt.Sprintf("%s not implemented", e.Command)
}

// Main command dispatcher for the program entrypoint. New commands should be added here, or they won't be
// invocable.
//
//nolint:revive
func dispatchCommands(ctx *kong.Context, cliCtx context.Context, stdOut io.Writer) error {
	var err error
	logger := zap.L().With(zap.String("command", ctx.Command()))

	switch ctx.Command() {
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
