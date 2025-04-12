package entrypoint

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"io"
	"strings"
)

func DebugAsNix32(cmdCtx CmdContext) error {
	b, err := io.ReadAll(cmdCtx.stdIn)
	if err != nil {
		cmdCtx.logger.Error("Error while reading input")
		return err
	}
	cmdCtx.stdOut.Write([]byte(nixtypes.NixBase32Field(b).String()))
	cmdCtx.stdOut.Write([]byte("\n"))
	return nil
}

func DebugConvertHash(cmdCtx CmdContext) error {
	hashStr := CLI.Debug.ConvertHash.Hash
	prefix, hash, found := strings.Cut(hashStr, ":")
	if !found {
		prefix = ""
		hash = hashStr
	}

	// Try and decode hex
	if decoded, err := hex.DecodeString(hash); err != nil {
		// Probably a nix hash and we're doing the opposite.
		decoded := nixtypes.NixBase32Field{}
		if err = decoded.UnmarshalText([]byte(hash)); err != nil {
			cmdCtx.logger.Error("Input was not usable as hex-bytes nor as a Nix Hash")
			return err
		}
		if prefix != "" {
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.stdOut.Write([]byte(hex.EncodeToString(decoded)))
		cmdCtx.stdOut.Write([]byte("\n"))
	} else {
		// Reformat as a nix hash
		nixenc := nixtypes.NixBase32Field(decoded)

		if prefix != "" {
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.stdOut.Write([]byte(nixenc.String()))
		cmdCtx.stdOut.Write([]byte("\n"))
	}
	return nil
}

func DebugGenerateKey(cmdCtx CmdContext) error {
	privateKey, err := nixtypes.GeneratePrivateKey(CLI.Debug.GenerateKey.Name)
	if err != nil {
		cmdCtx.logger.Error("Failed generating private key", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}
	cmdCtx.stdOut.Write([]byte(privateKey.String()))
	cmdCtx.stdOut.Write([]byte("\n"))
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
	err := readNinfoFromPaths(cmdCtx, CLI.Debug.Fingerprint.Paths, func(path string, ninfo *nixtypes.NarInfo) error {
		cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path), ninfo.Fingerprint())))
		return nil
	})
	return err
}

func DebugSign(cmdCtx CmdContext) error {
	privateKeys, err := loadPrivateKeys(cmdCtx)
	if err != nil {
		cmdCtx.logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	err = readNinfoFromPaths(cmdCtx, CLI.Debug.Sign.Paths, func(path string, ninfo *nixtypes.NarInfo) error {
		for _, key := range privateKeys {
			value, err := ninfo.MakeSignature(key)
			if err != nil {
				cmdCtx.logger.Warn("Could not generate signature for file", zap.String("path", path))
			}
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path), value.String())))
		}
		return nil
	})
	return err
}
