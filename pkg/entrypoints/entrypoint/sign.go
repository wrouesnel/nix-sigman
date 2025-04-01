package entrypoint

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixsigman"
	"go.uber.org/zap"
	"io"
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
	IncludePrivateKeys bool     `help:"Private Keys should also be used for trust" default:"false"`
	TrustedKeys        []string `help:"Names of keys to sign with (default all)" default:"*"`
}

// Sign implements (re)-signing a NARInfo file
func Sign(logger *zap.Logger, stdIn io.ReadCloser) error {
	manager, err := initializeNixSigMan(logger)
	if err != nil {
		logger.Error("Error initializing signature manager")
		return err
	}

	signingKeys := []nixsigman.KeyIdentity{}
	knownKeys := manager.ListPrivateKeys()
	if lo.Contains(CLI.Sign.SigningKeys, "*") {
		for _, knownKey := range knownKeys {
			signingKeys = append(signingKeys, knownKey)
		}
	} else {
		for _, requestedKey := range CLI.Sign.SigningKeys {
			foundKey := false
		innerLoop:
			for _, knownKey := range knownKeys {
				if requestedKey == knownKey.PublicKey {
					signingKeys = append(signingKeys, knownKey)
					foundKey = true
					break innerLoop
				}
			}
			if !foundKey {
			innerLoop2:
				for _, knownKey := range knownKeys {
					if requestedKey == knownKey.Name {
						signingKeys = append(signingKeys, knownKey)
						foundKey = true
						break innerLoop2
					}
				}
			}
			if !foundKey {
				return fmt.Errorf("requested signing key could not be found: %s", requestedKey)
			}
		}
	}

	signingNames := []string{}
	validationManager := nixsigman.NewNixSignatureManager()
	for _, signingKey := range signingKeys {
		if err := validationManager.LoadPublicKeyFromString(signingKey.String()); err != nil {
			return fmt.Errorf("BUG: error loading key from manager? %w", err)
		}
		signingNames = append(signingNames, signingKey.Name)
	}

	filenameCh := make(chan string)
	errorCh := make(chan error)
	go fileSigner(logger, manager, signingNames, validationManager, filenameCh, errorCh)

loop:
	for _, filename := range CLI.Sign.NarInfoFiles {
		select {
		case err = <-errorCh:
			break loop
		default:
		}
		if filename == "-" {
			sc := bufio.NewScanner(stdIn)
			for sc.Scan() {
				filename = strings.TrimSpace(sc.Text())
				if filename == "" {
					continue
				}
				select {
				case err = <-errorCh:
					break loop
				default:
				}
				filenameCh <- filename
			}
			if sc.Err() != nil {
				close(filenameCh)
				return err
			}
			stdIn.Close()
		} else {
			filenameCh <- filename
		}
	}
	close(filenameCh)

	<-errorCh

	return err
}

func fileSigner(logger *zap.Logger, manager *nixsigman.NixSigMan,
	signingNames []string,
	validationManager *nixsigman.NixSigMan,
	filenameCh chan string, errCh chan<- error) {
	defer close(errCh)
	for filename := range filenameCh {
		fl := logger.With(zap.String("path", filename))
		ninfo, err := nixsigman.NewNarInfoFromFile(filename)
		if err != nil {
			fl.Warn("Error reading file - not signing", zap.Error(err))
			continue
		}

		fl.Debug("Check for existing signature from signing keys")
		_, _, invalidKeys := validationManager.Verify(ninfo)
		if len(invalidKeys) > 0 {
			fl.Debug("Found missing key signatures - adding", zap.Int("missing_sigs", len(invalidKeys)))
			signatures := manager.Sign(ninfo, signingNames)
			for _, sig := range signatures {
				fl.Debug("Adding signature to NARinfo", zap.String("signature", sig))
				if err := ninfo.AddSignatureFromString(sig); err != nil {
					errCh <- errors.New("failed to update signatures on NARinfo blob")
					return
				}
			}
			// Output the new file
			newName := fmt.Sprintf("%s.new", filename)
			narBytes, err := ninfo.MarshalText()
			if err != nil {
				errCh <- err
				return
			}
			if err := os.WriteFile(newName, narBytes, os.FileMode(0777)); err != nil {
				errCh <- err
				return
			}
			// Backup old file if needed
			if CLI.Sign.BackupNARInfos {
				fl.Info("Backing up original NARInfo file")
				backupName := fmt.Sprintf("%s.bak", filename)
				if err := os.Rename(filename, backupName); err != nil {
					errCh <- err
					return
				}
			}
			// Move the new file into place
			if err := os.Rename(newName, filename); err != nil {
				errCh <- err
				return
			}
		} else {
			fl.Debug("Key signatures are up to date with signing keys")
		}
	}
}
