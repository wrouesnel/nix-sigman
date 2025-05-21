package entrypoint

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"io"
	"os"
	"strings"
)

// readNinfoFromPaths reads a list of paths and optionally reads an additional file from
// stdin (if "-" is specified in the path list).
func readNinfoFromPaths(cmdCtx *CmdContext, paths []string, cb func(path *pathlib.Path, ninfo *nixtypes.NarInfo) error) error {
	var commandErr error
	readStdin := false
	if lo.Contains(paths, "-") {
		readStdin = true
	}

	for _, path := range paths {
		if path == "-" {
			continue
		}
		fileBytes, err := pathlib.NewPath(path, pathlib.PathWithAfero(cmdCtx.fs)).ReadFile()
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
		if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(cmdCtx.fs)), &ninfo); err != nil {
			cmdCtx.logger.Error("Aborting error during path handling", zap.String("path", path), zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
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
				// represent stdin as a memmap fs path
				stdinPath := pathlib.NewPath("-", pathlib.PathWithAfero(afero.NewMemMapFs()))
				if err := cb(stdinPath, &ninfo); err != nil {
					cmdCtx.logger.Error("Aborting error during path handling", zap.String("path", "-"), zap.Error(err))
					return errors.Join(&ErrCommand{}, err)
				}
			}
		}
	}
	return commandErr
}

// readPathsFromStdin allows reading a list of paths from stdin
func readPaths(ctx *CmdContext, paths []string, cb func(path *pathlib.Path) error) error {
	readStdin := false
	if lo.Contains(paths, "-") {
		readStdin = true
	}

	for _, path := range paths {
		if path == "-" {
			continue
		}
		if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(ctx.fs))); err != nil {
			ctx.logger.Error("Aborting error during path handling",
				zap.String("path", path), zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
	}

	if readStdin {
		sc := bufio.NewScanner(ctx.stdIn)
		for sc.Scan() {
			if err := ctx.ctx.Err(); err != nil {
				ctx.logger.Warn("Context closed during iteration", zap.String("msg", err.Error()))
				return errors.Join(&ErrCommand{}, err)
			}

			line := sc.Text()
			path := strings.TrimSpace(line)
			if line == "" {
				// Just skip empty lines
				continue
			}

			if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(ctx.fs))); err != nil {
				ctx.logger.Error("Aborting error during path handling",
					zap.String("path", path), zap.Error(err))
				return errors.Join(&ErrCommand{}, err)
			}
		}
		if !errors.Is(sc.Err(), io.EOF) && sc.Err() != nil {
			return errors.Join(&ErrCommand{}, sc.Err())
		}
	}
	return nil
}

func loadPrivateKeys(logger *zap.Logger) ([]nixtypes.NamedPrivateKey, error) {
	privateKeys := []nixtypes.NamedPrivateKey{}
	for _, path := range CLI.PrivateKeyFiles {
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
	for _, key := range CLI.PrivateKeys {
		r := nixtypes.NamedPrivateKey{}
		if err := r.UnmarshalText([]byte(key)); err != nil {
			return privateKeys, err
		}
		privateKeys = append(privateKeys, r)
	}
	logger.Debug("Loaded Private Keys", zap.Int("private_keys_count", len(privateKeys)))
	return privateKeys, nil
}

func loadPublicKeys(logger *zap.Logger) ([]nixtypes.NamedPublicKey, error) {
	publicKeys := []nixtypes.NamedPublicKey{}
	for _, path := range CLI.PublicKeyFiles {
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
	for _, key := range CLI.PublicKeys {
		r := nixtypes.NamedPublicKey{}
		if err := r.UnmarshalText([]byte(key)); err != nil {
			return publicKeys, err
		}
		publicKeys = append(publicKeys, r)
	}
	logger.Debug("Loaded Public Keys", zap.Int("public_keys_count", len(publicKeys)))
	return publicKeys, nil
}

func loadNarInfo(l *zap.Logger, path *pathlib.Path) (nixtypes.NarInfo, error) {
	fileBytes, err := path.ReadFile()
	if err != nil {
		l.Warn("Could not read file", zap.Error(err))
		return nixtypes.NarInfo{}, err
	}

	ninfo := nixtypes.NarInfo{}
	if err := ninfo.UnmarshalText(fileBytes); err != nil {
		l.Warn("Could not parse file", zap.Error(err))
		return nixtypes.NarInfo{}, err
	}
	return ninfo, nil
}

// narHashCheck checks the actual file hash.
// TODO: consider moving to a NarInfo function.
func narHashCheck(l *zap.Logger, path *pathlib.Path, ninfo nixtypes.NarInfo) (bool, nixtypes.TypedNixHash, error) {
	narPath := path.Parent().Join(ninfo.URL)
	nl := l.With(zap.String("nar_path", narPath.String()))
	nl.Debug("Hash Verification")
	fh, err := narPath.Open()
	defer fh.Close()
	if err != nil {
		nl.Warn("Could not find file", zap.Error(err))
		return false, nixtypes.TypedNixHash{}, err
	}
	if ninfo.FileHash.HashName != "sha256" {
		nl.Warn("Unsupported hash", zap.String("hash_name", ninfo.FileHash.HashName))
		return false, nixtypes.TypedNixHash{}, errors.New("unsupported hash")
	}
	// Only handle sha256 for now
	hasher := sha256.New()
	sizeBytes, err := io.Copy(hasher, fh)
	nl.Debug("Read Bytes", zap.Int64("read_bytes", sizeBytes))
	if err != nil {
		return false, nixtypes.TypedNixHash{}, err
	}
	obtainedHash := nixtypes.TypedNixHash{
		HashName: ninfo.FileHash.HashName,
		Hash:     hasher.Sum(nil),
	}
	return bytes.Equal(obtainedHash.Hash, ninfo.FileHash.Hash), obtainedHash, nil
}

func backNinfo(l *zap.Logger, path *pathlib.Path) error {
	backupPath := fmt.Sprintf("%s.bak", path)
	oldNarBytes, err := path.ReadFile()
	if err != nil {
		return err
	}
	if err := os.WriteFile(backupPath, oldNarBytes, os.FileMode(0644)); err != nil {
		return err
	}
	return nil
}

// outputDir adapts the output directory path based on the backing file handler type
// namely "." gets reinterpreted as bucket root in S3 mode.
func NormalizeOutputDir(outputDir string) string {
	switch CLI.FsBackend {
	case "s3":
		if strings.HasPrefix(outputDir, ".") {
			outputDir = fmt.Sprintf("/%s", outputDir[1:])
		}
		if outputDir == "" {
			outputDir = "/"
		}
		return outputDir
	default:
		return outputDir
	}
}

func writeNInfo(l *zap.Logger, path *pathlib.Path, ninfo nixtypes.NarInfo) error {
	newPath := path.Parent().Join(fmt.Sprintf("%s.new", path.Name()))
	newBytes, err := ninfo.MarshalText()
	if err != nil {
		l.Warn("Failed to serialize narinfo file - signing aborted", zap.Error(err))
		return err
	}
	switch CLI.FsBackend {
	case "s3":
		// For S3, just do an in-place PUT
		l.Debug("In-place PUT due to object-type storage")
		if err := path.WriteFileMode(newBytes, os.FileMode(0644)); err != nil {
			l.Warn("Failed to write narinfo file - signing aborted")
			return err
		}
	default:
		l.Debug("Atomic replace with temporary file due to file-like storage")
		if err := newPath.WriteFileMode(newBytes, os.FileMode(0644)); err != nil {
			l.Warn("Failed to write narinfo file - signing aborted")
			return err
		}
		if err := newPath.Rename(path); err != nil {
			l.Warn("Failed to atomically replace narinfo file")
			return err
		}
	}

	return nil
}

type ConditionalResigners []func(ninfo *nixtypes.NarInfo) (bool, error)

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
