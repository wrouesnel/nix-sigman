package entrypoint

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
	"go.uber.org/zap"
)

//nolint:gochecknoglobals
type VerifyConfig struct {
	ValidateHashes     bool     `help:"Validate file hashes of archive files" default:"false"`
	IncludePrivateKeys bool     `help:"Private Keys should also be used for trust" default:"false"`
	TrustedKeys        []string `help:"Names of keys to verify with (default all)" default:"*"`

	NarInfoFiles []string `arg:"" help:"NARInfo files. - to read from stdin"`
}

// Verify implements NARInfo and archive verification
func Verify(cmdCtx *CmdContext) error {
	publicKeys, err := cmdCtx.Keys.LoadPublicKeys(cmdCtx.Logger)
	if err != nil {
		cmdCtx.Logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	if CLI.Verify.IncludePrivateKeys {
		cmdCtx.Logger.Debug("Including private keys for verification")
		privateKeys, err := cmdCtx.Keys.LoadPrivateKeys(cmdCtx.Logger)
		if err != nil {
			cmdCtx.Logger.Error("Error loading private keys", zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
		for _, key := range privateKeys {
			publicKeys = append(publicKeys, key.PublicKey())
		}
	}

	verifyKeys := []nixtypes.NamedPublicKey{}
	if lo.Contains(CLI.Verify.TrustedKeys, "*") {
		cmdCtx.Logger.Debug("Verify against ALL public keys")
		verifyKeys = publicKeys
	} else {
		desiredKeyNames := lo.SliceToMap(CLI.Verify.TrustedKeys, func(item string) (string, struct{}) {
			return item, struct{}{}
		})
		verifyKeys = lo.Filter(publicKeys, func(item nixtypes.NamedPublicKey, index int) bool {
			return lo.HasKey(desiredKeyNames, item.KeyName)
		})
	}
	cmdCtx.Logger.Debug("Signing Keys Set", zap.Int("num_trusted_keys", len(verifyKeys)))

	if len(verifyKeys) == 0 {
		return errors.Join(&ErrCommand{}, errors.New("no public keys selected"))
	}

	err = readPaths(cmdCtx, slices.Values(CLI.Verify.NarInfoFiles), func(path *pathlib.Path) error {
		cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:", color.CyanString(path.String()))))

		l := cmdCtx.Logger.With(zap.String("path", path.String()))

		ninfo, err := cmdutil.LoadNarInfo(l, path)
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
					cmdCtx.StdOut.Write([]byte(color.GreenString("GOODHASH")))
				} else if err != nil || !hashValid {
					cmdCtx.StdOut.Write([]byte(color.RedString("FAILHASH")))
				}
			} else {
				// Just report signature falidity
				cmdCtx.StdOut.Write([]byte(color.GreenString("GOODSIGN")))
			}
			cmdCtx.StdOut.Write([]byte(":"))
			cmdCtx.StdOut.Write([]byte(color.WhiteString(strings.Join(successfulKeyNames, " "))))
		} else {
			cmdCtx.StdOut.Write([]byte(color.RedString("FAILSIGN")))
			cmdCtx.StdOut.Write([]byte(":"))
			// Check hash anyway but don't report anything positive
			if CLI.Verify.ValidateHashes {
				hashValid, _, err := narHashCheck(l, path, ninfo)
				if hashValid {
					cmdCtx.StdOut.Write([]byte(color.GreenString("Hash OK")))
				} else if err != nil || !hashValid {
					cmdCtx.StdOut.Write([]byte(color.RedString("Hash Fail")))
				}
			}
		}
		cmdCtx.StdOut.Write([]byte("\n"))
		return nil
	})
	return err
}
