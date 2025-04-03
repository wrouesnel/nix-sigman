package entrypoint

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"os"
	"strings"
)

//nolint:gochecknoglobals
type SignConfig struct {
	BackupNARInfos bool     `help:"Make backups of NARinfo files" default:"true"`
	SigningKeys    []string `help:"Names of keys to sign with (default all)" default:"*"`
	NarInfoFiles   []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

//nolint:gochecknoglobals
type VerifyConfig struct {
	ValidateHashes     bool     `help:"Validate file hashes of archive files" default:"false"`
	IncludePrivateKeys bool     `help:"Private Keys should also be used for trust" default:"false"`
	TrustedKeys        []string `help:"Names of keys to verify with (default all)" default:"*"`
	NarInfoFiles       []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

//nolint:gochecknoglobals
type ValidateConfig struct {
	BackupNARInfos bool     `help:"Make backups of NARinfo files" default:"true"`
	Fix            bool     `help:"Rewrite NARinfo files if they're not an exact match" default:"false"`
	NarInfoFiles   []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

// Validate checks the format of the NARinfo file against the serialization.
func Validate(cmdCtx CmdContext) error {
	err := readPaths(cmdCtx, CLI.Validate.NarInfoFiles, func(path string) error {
		l := cmdCtx.logger

		var err error

		fileBytes, err := os.ReadFile(path)
		if err != nil {
			l.Warn("Could not read file", zap.Error(err))
			return err
		}

		ninfo := nixtypes.NarInfo{}
		err = ninfo.UnmarshalText(fileBytes)
		if err != nil {
			cmdCtx.stdOut.Write([]byte(
				fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
					color.RedString("FAILREAD"), strings.ReplaceAll(err.Error(), "\n", "\\\\n"))))
			return nil
		}

		// Remarshal the file
		remarshalled, err := ninfo.MarshalText()
		if err != nil {
			cmdCtx.stdOut.Write([]byte(
				fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
					color.RedString("FAILMRSL"), strings.ReplaceAll(err.Error(), "\n", "\\\\n"))))
			return nil
		}

		// Compare
		if bytes.Equal(fileBytes, remarshalled) == false {
			if CLI.Validate.Fix {
				if CLI.Sign.BackupNARInfos {
					if err = backNinfo(l, path); err != nil {
						l.Warn("Failed to backup narinfo file - rewrite aborted", zap.Error(err))
						return nil
					}
				}

				// Ignore errors - write logs its own errors
				_ = writeNInfo(l, path, ninfo)

				cmdCtx.stdOut.Write([]byte(
					fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
						color.YellowString("FIXEDFRM"), "Updated On-Disk Format")))
			} else {
				cmdCtx.stdOut.Write([]byte(
					fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
						color.RedString("FAILFORM"), "On-Disk Does Not Match Reserialization")))
			}
			return nil
		}

		cmdCtx.stdOut.Write([]byte(
			fmt.Sprintf("%s:%s:\n",
				color.CyanString("%s", path), color.GreenString("GOODFORM"))))
		return nil
	})
	return err
}

// Sign implements (re)-signing a NARInfo file
func Sign(cmdCtx CmdContext) error {
	privateKeys, err := loadPrivateKeys(cmdCtx)
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

	err = readPaths(cmdCtx, CLI.Sign.NarInfoFiles, func(path string) error {
		l := cmdCtx.logger.With(zap.String("path", path))

		ninfo, err := loadNarInfo(l, path)
		if err != nil {
			l.Warn("Could not load narinfo file", zap.Error(err))
			return nil
		}

		// Sign the NARinfo with each key
		errDuringSigning := false
		for _, key := range signingKeys {
			signature, err := ninfo.SignReplaceByName(key)
			if err != nil {
				l.Warn("Error during signing", zap.Error(err))
				errDuringSigning = true
				continue
			}
			l.Debug("Signed NARinfo with key", zap.String("keyname", key.KeyName),
				zap.String("signature", signature.String()))
		}

		if errDuringSigning {
			l.Warn("Errors while signing")
			return nil
		}

		if CLI.Sign.BackupNARInfos {
			if err = backNinfo(l, path); err != nil {
				l.Warn("Failed to backup narinfo file - signing aborted", zap.Error(err))
				return nil
			}
		}

		// Ignore errors - write logs its own errors
		_ = writeNInfo(l, path, ninfo)

		return nil
	})
	return err
}

func backNinfo(l *zap.Logger, path string) error {
	backupPath := fmt.Sprintf("%s.bak")
	oldNarBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(backupPath, oldNarBytes, os.FileMode(0644)); err != nil {
		return err
	}
	return nil
}

func writeNInfo(l *zap.Logger, path string, ninfo nixtypes.NarInfo) error {
	newPath := fmt.Sprintf("%s.new")
	newBytes, err := ninfo.MarshalText()
	if err != nil {
		l.Warn("Failed to serialize narinfo file - signing aborted", zap.Error(err))
		return err
	}
	if err := os.WriteFile(newPath, newBytes, os.FileMode(0644)); err != nil {
		l.Warn("Failed to write narinfo file - signing aborted")
		return err
	}
	if err := os.Rename(newPath, path); err != nil {
		l.Warn("Failed to atomically replace narinfo file - signing aborted")
		return err
	}
	return nil
}

// Verify implements NARInfo and archive verification
func Verify(cmdCtx CmdContext) error {
	publicKeys, err := loadPublicKeys(cmdCtx)
	if err != nil {
		cmdCtx.logger.Error("Error loading public keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	if CLI.Verify.IncludePrivateKeys {
		cmdCtx.logger.Debug("Including private keys for verification")
		privateKeys, err := loadPrivateKeys(cmdCtx)
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

	err = readPaths(cmdCtx, CLI.Verify.NarInfoFiles, func(path string) error {
		cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", color.CyanString(path))))

		l := cmdCtx.logger.With(zap.String("path", path))

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
		}
		cmdCtx.stdOut.Write([]byte("\n"))
		return nil
	})
	return err
}
