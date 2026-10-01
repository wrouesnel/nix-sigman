// Package cmdutil contains the shared command context and helpers used by the
// CLI entrypoint and the command implementations which live in their own packages.
package cmdutil

import (
	"context"
	"io"
	"os"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
)

type ErrCommand struct {
}

func (e ErrCommand) Error() string {
	return "command error"
}

// KeyConfig is the global key loading configuration
type KeyConfig struct {
	PrivateKeyFiles []string `help:"Private Key Files" type:"existingfile"`
	PublicKeyFiles  []string `help:"Public Key Files" type:"existingfile"`

	PrivateKeys []string `help:"Private Keys"`
	PublicKeys  []string `help:"Public Keys"`
}

// CmdContext packages common parameters for CLI commands
type CmdContext struct {
	Logger *zap.Logger
	Ctx    context.Context
	StdIn  io.ReadCloser
	StdOut io.Writer
	Fs     afero.Fs
	// FsBackend is the name of the filesystem backend Fs was built from
	FsBackend string
	Keys      *KeyConfig
}

// LoadPrivateKeys loads all private keys from the configured files and command line.
func (k *KeyConfig) LoadPrivateKeys(logger *zap.Logger) ([]nixtypes.NamedPrivateKey, error) {
	privateKeys := []nixtypes.NamedPrivateKey{}
	for _, path := range k.PrivateKeyFiles {
		fh, err := os.Open(path)
		if err != nil {
			return privateKeys, err
		}
		keys, err := nixtypes.ParsePrivateKeys(fh)
		if err != nil {
			return privateKeys, err
		}
		privateKeys = append(privateKeys, keys...)
	}
	for _, key := range k.PrivateKeys {
		r := nixtypes.NamedPrivateKey{}
		if err := r.UnmarshalText([]byte(key)); err != nil {
			return privateKeys, err
		}
		privateKeys = append(privateKeys, r)
	}
	logger.Debug("Loaded Private Keys", zap.Int("private_keys_count", len(privateKeys)))
	return privateKeys, nil
}

// LoadPublicKeys loads all public keys from the configured files and command line.
func (k *KeyConfig) LoadPublicKeys(logger *zap.Logger) ([]nixtypes.NamedPublicKey, error) {
	publicKeys := []nixtypes.NamedPublicKey{}
	for _, path := range k.PublicKeyFiles {
		fh, err := os.Open(path)
		if err != nil {
			return publicKeys, err
		}
		keys, err := nixtypes.ParsePublicKeys(fh)
		if err != nil {
			return publicKeys, err
		}
		publicKeys = append(publicKeys, keys...)
	}
	for _, key := range k.PublicKeys {
		r := nixtypes.NamedPublicKey{}
		if err := r.UnmarshalText([]byte(key)); err != nil {
			return publicKeys, err
		}
		publicKeys = append(publicKeys, r)
	}
	logger.Debug("Loaded Public Keys", zap.Int("public_keys_count", len(publicKeys)))
	return publicKeys, nil
}

// LoadNarInfo reads and parses a NARInfo file
func LoadNarInfo(l *zap.Logger, path *pathlib.Path) (nixtypes.NarInfo, error) {
	fileBytes, err := path.ReadFile()
	if err != nil {
		//l.Warn("Could not read file", zap.Error(err))
		return nixtypes.NarInfo{}, err
	}

	ninfo := nixtypes.NarInfo{}
	if err := ninfo.UnmarshalText(fileBytes); err != nil {
		l.Warn("Could not parse file", zap.Error(err))
		return nixtypes.NarInfo{}, err
	}
	return ninfo, nil
}
