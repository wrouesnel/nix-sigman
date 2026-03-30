package resigning

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type ResigningConfig struct {
	SigningMap             map[string]string `help:"Map of public key names to private key names to sign if present"`
	SigningMapFile         string            `help:"File to load the signing map from"`
	AllowUnsignedResigning bool              `help:"Allow signing unsigned packages via the empty key specifier"`
	UnsignedResigningKeys  []string          `help:"List of key names to be used for signing unsigned packages"`
}

type ConditionalResigners []func(ninfo *nixtypes.NarInfo) (bool, error)

// MaybeResign will evaluate the resigning conditions for a NARinfo file and resign it if needed
func (c ConditionalResigners) MaybeResign(l *zap.Logger, ninfo *nixtypes.NarInfo) (bool, error) {
	didNewSignature := false
	for _, signer := range c {
		didSign, err := signer(ninfo)
		if err != nil {
			l.Warn("Signing Error", zap.String("error", err.Error()))
			return didNewSignature, err
		}
		if !didNewSignature && didSign {
			didNewSignature = didSign
		}
	}
	if didNewSignature {
		l.Debug("Resigned narinfo file")
	} else {
		l.Debug("No match narinfo file")
	}
	return didNewSignature, nil
}

func LoadSigningMap(l *zap.Logger, signingConfig *ResigningConfig, privateKeys []nixtypes.NamedPrivateKey, publicKeys []nixtypes.NamedPublicKey) (signers ConditionalResigners, err error) {
	signingMap := make(map[string]string, 0)

	if signingConfig.SigningMapFile != "" {
		signingMap, err = loadSigningMapFile(signingConfig.SigningMapFile)
		if err != nil {
			l.Error("Signing map file specified but could not be loaded")
			return
		}
	}

	for k, v := range signingConfig.SigningMap {
		if lo.HasKey(signingMap, k) {
			l.Debug("Command line overriding signing map file key", zap.String("key", k))
		}
		signingMap[k] = v
	}

	l.Info("Building resigning map")
	signers, err = buildSigningMap(publicKeys, privateKeys, signingMap)
	if err != nil {
		return
	}

	if signingConfig.AllowUnsignedResigning {
		var unsignedErr error
		if len(lo.CoalesceSliceOrEmpty(signingConfig.UnsignedResigningKeys)) == 0 {
			l.Warn("Unsigned Resigning Activated but no keys specified - unsigned packages will not be resigned")
		} else {
			// Validate the unsigned keys
			privateKeyMap := lo.SliceToMap(privateKeys, func(item nixtypes.NamedPrivateKey) (string, nixtypes.NamedPrivateKey) {
				return item.KeyName, item
			})

			unsignedResigningKeys := []nixtypes.NamedPrivateKey{}
			for _, keyName := range signingConfig.UnsignedResigningKeys {
				if pKey, found := privateKeyMap[keyName]; found {
					unsignedResigningKeys = append(unsignedResigningKeys, pKey)
				} else {
					unsignedErr = multierr.Append(unsignedErr, fmt.Errorf("requested private key not loaded: %s"))
				}
			}

			l.Warn("Unsigned Resigning Activated: all unsigned packages will have these keys applied",
				zap.Strings("unsigned_resigning_keys", signingConfig.UnsignedResigningKeys))
			// Add the unsigned singer to the map
			signers = append(signers, func(ninfo *nixtypes.NarInfo) (bool, error) {
				if len(ninfo.Sig) > 0 {
					// Don't sign package with signature already.
					return false, nil
				}
				l.Info("Signing unsigned package with unsigned package keys")
				for _, pkey := range unsignedResigningKeys {
					_, _, err := ninfo.Sign(pkey)
					if err != nil {
						return false, err
					}
				}
				return true, nil
			})
		}
		if unsignedErr != nil {
			err = unsignedErr
			return
		}
	}

	return
}

func loadSigningMapFile(path string) (map[string]string, error) {
	signingMap := map[string]string{}

	signingMapFile := pathlib.NewPath(path, pathlib.PathWithAfero(afero.OsFs{}))
	fh, err := signingMapFile.Open()
	if err != nil {
		return signingMap, err
	}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := sc.Text()
		path := strings.TrimSpace(line)
		if path == "" || strings.HasPrefix(path, "#") {
			// Just skip empty lines and comments
			continue
		}
		fromKey, toKey, found := strings.Cut(path, "=")
		if !found {
			return signingMap, fmt.Errorf("invalid map entry: %s", path)
		}
		signingMap[fromKey] = toKey
	}
	return signingMap, nil
}

// buildSigningMap builds the data structures for doing conditional signing
func buildSigningMap(publicKeys []nixtypes.NamedPublicKey,
	privateKeys []nixtypes.NamedPrivateKey, signingMap map[string]string) (signers ConditionalResigners, setupErr error) {

	privMap := lo.SliceToMap(privateKeys, func(item nixtypes.NamedPrivateKey) (string, nixtypes.NamedPrivateKey) {
		return item.KeyName, item
	})

	pubMap := lo.SliceToMap(publicKeys, func(item nixtypes.NamedPublicKey) (string, nixtypes.NamedPublicKey) {
		return item.KeyName, item
	})

	for k, v := range signingMap {
		requiredPublicKeys := strings.Split(k, "&")
		requiredPrivateKeys := strings.Split(v, ",")

		requiredKeys := []nixtypes.NamedPublicKey{}
		for _, key := range requiredPublicKeys {
			if !lo.HasKey(pubMap, key) && key != "" {
				setupErr = multierr.Append(setupErr, fmt.Errorf("requested public key not loaded: %s", key))
			} else if key != "" {
				requiredKeys = append(requiredKeys, pubMap[key])
			}
		}

		signingKeys := []nixtypes.NamedPrivateKey{}
		for _, key := range requiredPrivateKeys {
			if !lo.HasKey(privMap, key) {
				setupErr = multierr.Append(setupErr, fmt.Errorf("requested private key not loaded: %s", key))
			} else {
				signingKeys = append(signingKeys, privMap[key])
			}
		}

		signers = append(signers, func(ninfo *nixtypes.NarInfo) (bool, error) {
			// Abort as soon as something doesn't match
			for _, key := range requiredKeys {
				match, _ := ninfo.Verify(key)
				if !match {
					return false, nil
				}
			}
			didNewSignature := false
			// Good signatures - resign
			for _, key := range signingKeys {
				didSign, _, err := ninfo.Sign(key)
				if err != nil {
					return didSign, err
				}
				if didSign {
					didNewSignature = true
				}
			}
			return didNewSignature, nil
		})
	}
	return
}
