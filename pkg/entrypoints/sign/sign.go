package sign

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/fatih/color"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/cmdutil"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
)

type Cmd struct {
	resigning.ResigningConfig `embed:""`
	BackupNARInfos            bool     `help:"Make backups of NARinfo files" default:"false"`
	SigningKeys               []string `help:"Names of keys to sign with (default all)" default:"*"`
	NarInfoFiles              []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

// Run implements (re)-signing a NARInfo file
func (c *Cmd) Run(cmdCtx *cmdutil.CmdContext) error {
	l := cmdCtx.Logger

	privateKeys, err := cmdCtx.Keys.LoadPrivateKeys(l)
	if err != nil {
		cmdCtx.Logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	l.Debug("Loading public keys")
	publicKeys, err := cmdCtx.Keys.LoadPublicKeys(l)
	if err != nil {
		cmdCtx.Logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	signingKeys := []nixtypes.NamedPrivateKey{}
	if lo.Contains(c.SigningKeys, "*") {
		cmdCtx.Logger.Debug("Sign with ALL private keys")
		signingKeys = privateKeys
	} else {
		desiredKeyNames := lo.SliceToMap(c.SigningKeys, func(item string) (string, struct{}) {
			return item, struct{}{}
		})
		signingKeys = lo.Filter(privateKeys, func(item nixtypes.NamedPrivateKey, index int) bool {
			return lo.HasKey(desiredKeyNames, item.KeyName)
		})
	}
	l.Debug("Signing Keys Set", zap.Int("num_signing_keys", len(signingKeys)))

	if len(signingKeys) == 0 {
		return errors.Join(&cmdutil.ErrCommand{}, errors.New("no private keys selected"))
	}

	var signers resigning.ConditionalResigners
	if len(c.SigningMap) > 0 || c.SigningMapFile != "" {
		l.Info("Conditional resigning requested")
		signers, err = resigning.LoadSigningMap(l,
			&c.ResigningConfig,
			privateKeys,
			publicKeys,
		)
		if err != nil {
			return errors.Join(&cmdutil.ErrCommand{}, err)
		}
	} else {
		l.Info("Unconditional resigning requested")
		signers = append(signers, func(ninfo *nixtypes.NarInfo) (bool, error) {
			didSign := false
			for _, key := range signingKeys {
				didNewSignature, _, err := ninfo.SignReplaceByName(key)
				if err != nil {
					l.Warn("Error during signing", zap.Error(err))
					return didNewSignature, err
				}
				if didNewSignature {
					didSign = true
				}
			}
			return didSign, nil
		})
	}

	err = cmdutil.ReadPaths(cmdCtx, slices.Values(c.NarInfoFiles), func(path *pathlib.Path) error {
		l := cmdCtx.Logger.With(zap.String("path", path.String()))

		ninfo, err := cmdutil.LoadNarInfo(l, path)
		if err != nil {
			l.Warn("Could not load narinfo file", zap.Error(err))
			return nil
		}

		// Sign the NARinfo with each key
		errDuringSigning := false
		didNewSignature := false
		for _, signer := range signers {
			didSign, err := signer(&ninfo)
			if err != nil {
				l.Warn("Signing Error", zap.String("error", err.Error()))
				errDuringSigning = true
				continue
			}
			if didSign {
				didNewSignature = true
			}
		}
		if didNewSignature {
			l.Debug("Resigned narinfo file", zap.String("name", path.Name()))
		} else {
			l.Debug("No match narinfo file", zap.String("name", path.Name()))
		}

		signatureStrings := lo.Map(ninfo.Sig, func(item nixtypes.NixSignature, index int) string {
			return item.String()
		})

		if errDuringSigning {
			l.Warn("Errors while signing - no changes made")
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.RedString("FAILSIGN"), strings.Join(signatureStrings, " "))))
			return nil
		}

		if !didNewSignature {
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.WhiteString("NOCHANGE"), strings.Join(signatureStrings, " "))))
		} else {
			if c.BackupNARInfos {
				if err = cmdutil.BackupNarInfo(l, path); err != nil {
					l.Warn("Failed to backup narinfo file - signing aborted", zap.Error(err))
					return nil
				}
			}
			// Ignore errors - write logs its own errors
			_ = cmdCtx.WriteNarInfo(l, path, ninfo)
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:%s:%s\n", color.CyanString(path.String()), color.YellowString("SIGNUPDT"), strings.Join(signatureStrings, " "))))
		}

		return nil
	})
	return err
}
