package entrypoint

import (
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/fatih/color"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"strings"
)

//nolint:gochecknoglobals
type SignConfig struct {
	BackupNARInfos bool     `help:"Make backups of NARinfo files" default:"false"`
	SigningKeys    []string `help:"Names of keys to sign with (default all)" default:"*"`
	NarInfoFiles   []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

// Sign implements (re)-signing a NARInfo file
func Sign(cmdCtx *CmdContext) error {
	privateKeys, err := loadPrivateKeys(cmdCtx.logger)
	if err != nil {
		cmdCtx.logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	signingKeys := []nixtypes.NamedPrivateKey{}
	if lo.Contains(CLI.Sign.SigningKeys, "*") {
		cmdCtx.logger.Debug("Sign with ALL private keys")
		signingKeys = privateKeys
	} else {
		desiredKeyNames := lo.SliceToMap(CLI.Sign.SigningKeys, func(item string) (string, struct{}) {
			return item, struct{}{}
		})
		signingKeys = lo.Filter(privateKeys, func(item nixtypes.NamedPrivateKey, index int) bool {
			return lo.HasKey(desiredKeyNames, item.KeyName)
		})
	}
	cmdCtx.logger.Debug("Signing Keys Set", zap.Int("num_signing_keys", len(signingKeys)))

	if len(signingKeys) == 0 {
		return errors.Join(&ErrCommand{}, errors.New("no private keys selected"))
	}

	err = readPaths(cmdCtx, CLI.Sign.NarInfoFiles, func(path *pathlib.Path) error {
		l := cmdCtx.logger.With(zap.String("path", path.String()))

		ninfo, err := loadNarInfo(l, path)
		if err != nil {
			l.Warn("Could not load narinfo file", zap.Error(err))
			return nil
		}

		// Sign the NARinfo with each key
		errDuringSigning := false
		didSign := false
		for _, key := range signingKeys {
			didNewSignature, _, err := ninfo.SignReplaceByName(key)
			if err != nil {
				l.Warn("Error during signing", zap.Error(err))
				errDuringSigning = true
				continue
			}
			if didNewSignature {
				didSign = true
			}
		}

		signatureStrings := lo.Map(ninfo.Sig, func(item nixtypes.NixSignature, index int) string {
			return item.String()
		})

		if errDuringSigning {
			l.Warn("Errors while signing - no changes made")
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.RedString("FAILSIGN"), strings.Join(signatureStrings, " "))))
			return nil
		}

		if !didSign {
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.WhiteString("NOCHANGE"), strings.Join(signatureStrings, " "))))
		} else {

			if CLI.Sign.BackupNARInfos {
				if err = backNinfo(l, path); err != nil {
					l.Warn("Failed to backup narinfo file - signing aborted", zap.Error(err))
					return nil
				}
			}

			// Ignore errors - write logs its own errors
			_ = writeNInfo(l, path, ninfo)

			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.YellowString("SIGNUPDT"), strings.Join(signatureStrings, " "))))
		}

		return nil
	})
	return err
}
