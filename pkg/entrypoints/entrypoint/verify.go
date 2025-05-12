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
type VerifyConfig struct {
	ValidateHashes     bool     `help:"Validate file hashes of archive files" default:"false"`
	IncludePrivateKeys bool     `help:"Private Keys should also be used for trust" default:"false"`
	TrustedKeys        []string `help:"Names of keys to verify with (default all)" default:"*"`
	NarInfoFiles       []string `arg:"" help:"NARInfo files. - to read from stdin"`
}

// Verify implements NARInfo and archive verification
func Verify(cmdCtx *CmdContext) error {
	publicKeys, err := loadPublicKeys(cmdCtx.logger)
	if err != nil {
		cmdCtx.logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	if CLI.Verify.IncludePrivateKeys {
		cmdCtx.logger.Debug("Including private keys for verification")
		privateKeys, err := loadPrivateKeys(cmdCtx.logger)
		if err != nil {
			cmdCtx.logger.Error("Error loading private keys", zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
		for _, key := range privateKeys {
			publicKeys = append(publicKeys, key.PublicKey())
		}
	}

	verifyKeys := []nixtypes.NamedPublicKey{}
	if lo.Contains(CLI.Verify.TrustedKeys, "*") {
		cmdCtx.logger.Debug("Verify against ALL public keys")
		verifyKeys = publicKeys
	} else {
		desiredKeyNames := lo.SliceToMap(CLI.Verify.TrustedKeys, func(item string) (string, struct{}) {
			return item, struct{}{}
		})
		verifyKeys = lo.Filter(publicKeys, func(item nixtypes.NamedPublicKey, index int) bool {
			return lo.HasKey(desiredKeyNames, item.KeyName)
		})
	}
	cmdCtx.logger.Debug("Signing Keys Set", zap.Int("num_trusted_keys", len(verifyKeys)))

	if len(verifyKeys) == 0 {
		return errors.Join(&ErrCommand{}, errors.New("no public keys selected"))
	}

	err = readPaths(cmdCtx, CLI.Verify.NarInfoFiles, func(path *pathlib.Path) error {
		cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", color.CyanString(path.String()))))

		l := cmdCtx.logger.With(zap.String("path", path.String()))

		ninfo, err := loadNarInfo(l, path)
		if err != nil {
			l.Warn("Could not load narinfo file", zap.Error(err))
			return nil
		}

		// Sign the NARinfo with each key
		verifiedKeys := []nixtypes.NamedPublicKey{}
		for _, key := range verifyKeys {
			verified, _ := ninfo.Verify(key)
			if !verified {
				l.Debug("Failed verification", zap.String("keyname", key.KeyName))
				continue
			}
			l.Debug("Successful verification", zap.String("keyname", key.KeyName))
			verifiedKeys = append(verifiedKeys, key)
		}

		successfulKeyNames := lo.Map(verifiedKeys, func(item nixtypes.NamedPublicKey, index int) string {
			return item.KeyName
		})

		if len(verifiedKeys) > 0 {
			if CLI.Verify.ValidateHashes {
				hashValid, _, err := narHashCheck(l, path, ninfo)
				if hashValid {
					cmdCtx.stdOut.Write([]byte(color.GreenString("GOODHASH")))
				} else if err != nil || !hashValid {
					cmdCtx.stdOut.Write([]byte(color.RedString("FAILHASH")))
				}
			} else {
				// Just report signature falidity
				cmdCtx.stdOut.Write([]byte(color.GreenString("GOODSIGN")))
			}
			cmdCtx.stdOut.Write([]byte(":"))
			cmdCtx.stdOut.Write([]byte(color.WhiteString(strings.Join(successfulKeyNames, " "))))
		} else {
			cmdCtx.stdOut.Write([]byte(color.RedString("FAILSIGN")))
			cmdCtx.stdOut.Write([]byte(":"))
			// Check hash anyway but don't report anything positive
			if CLI.Verify.ValidateHashes {
				hashValid, _, err := narHashCheck(l, path, ninfo)
				if hashValid {
					cmdCtx.stdOut.Write([]byte(color.GreenString("Hash OK")))
				} else if err != nil || !hashValid {
					cmdCtx.stdOut.Write([]byte(color.RedString("Hash Fail")))
				}
			}
		}
		cmdCtx.stdOut.Write([]byte("\n"))
		return nil
	})
	return err
}
