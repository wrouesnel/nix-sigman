package entrypoint

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"io"
	"os"
)

func DebugGenerateKey(cmdCtx CmdContext) error {
	privateKey, err := nixtypes.GeneratePrivateKey(CLI.Debug.GenerateKey.Name)
	if err != nil {
		cmdCtx.logger.Error("Failed generating private key", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}
	cmdCtx.stdOut.Write([]byte(privateKey.String()))
	cmdCtx.stdOut.Write([]byte("\b"))
	return nil
}

func DebugPublicKey(cmdCtx CmdContext) error {
	privateKeys, err := nixtypes.ParsePrivateKeys(cmdCtx.stdIn)
	if err != nil {
		cmdCtx.logger.Error("Failed reading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}
	for _, key := range privateKeys {
		publicKey := key.PublicKey()
		cmdCtx.stdOut.Write([]byte(publicKey.String()))
		cmdCtx.stdOut.Write([]byte("\n"))
	}

	return nil
}

func DebugFingerprint(cmdCtx CmdContext) error {
	err := readNinfoFromPaths(cmdCtx, CLI.Debug.Fingerprint.Paths, func(path string, ninfo *nixtypes.NarInfo) {
		cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path), ninfo.Fingerprint())))
	})
	return err
}

func DebugSign(cmdCtx CmdContext) error {
	privateKeys := []nixtypes.NamedPrivateKey{}
	for _, path := range CLI.PrivateKeyFiles {
		fh, err := os.Open(path)
		if err != nil {
			return errors.Join(&ErrCommand{}, err)
		}
		keys, err := nixtypes.ParsePrivateKeys(fh)
		if err != nil {
			return errors.Join(&ErrCommand{}, err)
		}
		privateKeys = append(privateKeys, keys...)
	}
	for _, key := range CLI.PrivateKeys {
		r := nixtypes.NamedPrivateKey{}
		if err := r.UnmarshalText([]byte(key)); err != nil {
			return errors.Join(&ErrCommand{}, err)
		}
		privateKeys = append(privateKeys, r)
	}
	cmdCtx.logger.Debug("Loaded Private Keys", zap.Int("private_keys_count", len(privateKeys)))

	err := readNinfoFromPaths(cmdCtx, CLI.Debug.Sign.Paths, func(path string, ninfo *nixtypes.NarInfo) {
		for _, key := range privateKeys {
			value, err := ninfo.MakeSignature(key)
			if err != nil {
				cmdCtx.logger.Warn("Could not generate signature for file", zap.String("path", path))
			}
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path), value.String())))
		}
	})
	return err
}

func readNinfoFromPaths(cmdCtx CmdContext, paths []string, cb func(path string, ninfo *nixtypes.NarInfo)) error {
	var commandErr error
	readStdin := false
	if lo.Contains(paths, "-") {
		readStdin = true
	}

	for _, path := range paths {
		if path == "-" {
			continue
		}
		fileBytes, err := os.ReadFile(path)
		if err != nil {
			cmdCtx.logger.Warn("Could not read file", zap.String("path", path), zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			continue
		}
		ninfo := nixtypes.NarInfo{}
		if err := ninfo.UnmarshalText(fileBytes); err != nil {
			cmdCtx.logger.Warn("Could not parse file", zap.String("path", path), zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			continue
		}
		cb(path, &ninfo)
	}
	// Read stdin last
	if readStdin {
		fileBytes, err := io.ReadAll(cmdCtx.stdIn)
		if err != nil {
			cmdCtx.logger.Warn("Could not parse stdin input", zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
		} else {
			ninfo := nixtypes.NarInfo{}
			if err := ninfo.UnmarshalText(fileBytes); err != nil {
				cmdCtx.logger.Warn("Could not parse stdin", zap.Error(err))
				commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			} else {
				cb("-", &ninfo)
			}
		}
	}
	return commandErr
}
