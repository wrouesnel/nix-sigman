package entrypoint

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixsigman"
	"go.uber.org/zap"
	"io"
	"strings"
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
func dispatchCommands(ctx *kong.Context, cliCtx context.Context, stdIn io.ReadCloser, stdOut io.Writer) error {
	var err error
	logger := zap.L().With(zap.String("command", ctx.Command()))

	switch ctx.Command() {
	case "sign":
		err = &ErrCommandNotImplemented{Command: ctx.Command()}
		logger.Error("Command not implemented")

	case "verify":
		err = &ErrCommandNotImplemented{Command: ctx.Command()}
		logger.Error("Command not implemented")

	case "debug generate-key <name>":
		_, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", CLI.Debug.GenerateKey.Name, base64.StdEncoding.EncodeToString(privKey))))

	case "debug public-key":
		sc := bufio.NewScanner(stdIn)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			parts := strings.SplitN(line, ":", 2)
			publicPart := base64.StdEncoding.EncodeToString(ed25519.PrivateKey(lo.Must(base64.StdEncoding.DecodeString(parts[1]))).Public().(ed25519.PublicKey))
			stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", parts[0], publicPart)))
		}
		if sc.Err() != nil {
			return err
		}

	case "debug fingerprint <paths>":
		for _, ninfoPath := range CLI.Debug.Fingerprint.Paths {
			ninfo, err := nixsigman.NewNarInfoFromFile(ninfoPath)
			if err != nil {
				logger.Warn("Could not read supplied file", zap.String("path", ninfoPath), zap.Error(err))
			}
			fingerprint := string(ninfo.Fingerprint())
			stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(ninfoPath), fingerprint)))
		}

	case "debug sign <paths>":
		manager, err := initializeNixSigMan(logger)
		if err != nil {
			logger.Error("Could not initialize signature manager", zap.Error(err))
			return err
		}
		for _, ninfoPath := range CLI.Debug.Sign.Paths {
			ninfo, err := nixsigman.NewNarInfoFromFile(ninfoPath)
			if err != nil {
				logger.Warn("Could not read supplied file", zap.String("path", ninfoPath), zap.Error(err))
			}
			signingKeyNames := []string{}
			for _, kentry := range manager.ListPrivateKeys() {
				signingKeyNames = append(signingKeyNames, kentry.Name)
			}
			logger.Debug("Signing key keys", zap.Strings("keynames", signingKeyNames))
			signatures := manager.Sign(ninfo, signingKeyNames)
			stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(ninfoPath), strings.Join(signatures, " "))))
		}

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

func initializeNixSigMan(logger *zap.Logger) (*nixsigman.NixSigMan, error) {
	manager := nixsigman.NewNixSignatureManager()
	for _, path := range CLI.PrivateKeyFiles {
		if err := manager.LoadPrivateKeyFromFile(path); err != nil {
			logger.Error("Could not load private key file", zap.String("path", path), zap.Error(err))
			return nil, err
		}
		logger.Debug("Loaded private keys from file", zap.String("path", path))
	}
	for _, keyString := range CLI.PrivateKeys {
		if err := manager.LoadPrivateKeyFromString(keyString); err != nil {
			logger.Error("Could not load private key", zap.Error(err))
			return nil, err
		}
		logger.Debug("Loaded private key")
	}
	for _, path := range CLI.PublicKeysFiles {
		if err := manager.LoadPublicKeyFromFile(path); err != nil {
			logger.Error("Could not load private key file", zap.String("path", path), zap.Error(err))
			return nil, err
		}
		logger.Debug("Loaded public keys from file", zap.String("path", path))
	}
	for _, keyString := range CLI.PublicKeys {
		if err := manager.LoadPublicKeyFromString(keyString); err != nil {
			logger.Error("Could not load public key", zap.Error(err), zap.String("key", keyString))
			return nil, err
		}
		logger.Debug("Loaded public key")
	}
	logger.Debug("Signature Manager Loaded",
		zap.Int("private_keys", manager.PrivateKeysCount()),
		zap.Int("public_keys", manager.PublicKeysCount()),
	)
	return manager, nil
}
