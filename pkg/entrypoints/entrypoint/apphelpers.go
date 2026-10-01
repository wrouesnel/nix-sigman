package entrypoint

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
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
		fileBytes, err := pathlib.NewPath(path, pathlib.PathWithAfero(cmdCtx.Fs)).ReadFile()
		if err != nil {
			cmdCtx.Logger.Warn("Could not read file", zap.String("path", path), zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			continue
		}
		ninfo := nixtypes.NarInfo{}
		if err := ninfo.UnmarshalText(fileBytes); err != nil {
			cmdCtx.Logger.Warn("Could not parse file", zap.String("path", path), zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			continue
		}
		if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(cmdCtx.Fs)), &ninfo); err != nil {
			cmdCtx.Logger.Error("Aborting error during path handling", zap.String("path", path), zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
	}
	// Read stdin last
	if readStdin {
		fileBytes, err := io.ReadAll(cmdCtx.StdIn)
		if err != nil {
			cmdCtx.Logger.Warn("Could not parse stdin input", zap.Error(err))
			commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
		} else {
			ninfo := nixtypes.NarInfo{}
			if err := ninfo.UnmarshalText(fileBytes); err != nil {
				cmdCtx.Logger.Warn("Could not parse stdin", zap.Error(err))
				commandErr = errors.Join(&ErrCommand{}, errors.New("not all files were read"))
			} else {
				// represent stdin as a memmap fs path
				stdinPath := pathlib.NewPath("-", pathlib.PathWithAfero(afero.NewMemMapFs()))
				if err := cb(stdinPath, &ninfo); err != nil {
					cmdCtx.Logger.Error("Aborting error during path handling", zap.String("path", "-"), zap.Error(err))
					return errors.Join(&ErrCommand{}, err)
				}
			}
		}
	}
	return commandErr
}

// readPaths allows reading a list of paths
func readPaths(ctx *CmdContext, paths iter.Seq[string], cb func(path *pathlib.Path) error) error {
	readStdin := false

	for path := range paths {
		if path == "-" {
			readStdin = true
			continue
		}
		if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(ctx.Fs))); err != nil {
			ctx.Logger.Error("Aborting error during path handling",
				zap.String("path", path), zap.Error(err))
			return errors.Join(&ErrCommand{}, err)
		}
	}

	if readStdin {
		sc := bufio.NewScanner(ctx.StdIn)
		for sc.Scan() {
			if err := ctx.Ctx.Err(); err != nil {
				ctx.Logger.Warn("Context closed during iteration", zap.String("msg", err.Error()))
				return errors.Join(&ErrCommand{}, err)
			}

			line := sc.Text()
			path := strings.TrimSpace(line)
			if path == "" {
				// Just skip empty lines
				continue
			}

			if err := cb(pathlib.NewPath(path, pathlib.PathWithAfero(ctx.Fs))); err != nil {
				ctx.Logger.Error("Aborting error during path handling",
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

// narHashCheck checks the actual file hash.
// TODO: consider moving to a NarInfo function.
func narHashCheck(l *zap.Logger, path *pathlib.Path, ninfo nixtypes.NarInfo) (bool, nixtypes.TypedNixHash, error) {
	narPath := path.Parent().Join(ninfo.URL)
	nl := l.With(zap.String("nar_path", narPath.String()))
	nl.Debug("Hash Verification")
	fh, err := narPath.Open()
	if err != nil {
		nl.Warn("Could not find file", zap.Error(err))
		return false, nixtypes.TypedNixHash{}, err
	}
	defer fh.Close()
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
	// Write the backup through the same filesystem as the original (which may not be the OS).
	backupPath := path.Parent().Join(fmt.Sprintf("%s.bak", path.Name()))
	oldNarBytes, err := path.ReadFile()
	if err != nil {
		return err
	}
	if err := backupPath.WriteFileMode(oldNarBytes, os.FileMode(0644)); err != nil {
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
	case "s3", "nix-http-cache":
		// For S3, just do an in-place PUT
		// While the nix-cache-http FS can't (yet) write files, if it could, then
		// it would work the same way (since it's pretty much identical to S3).
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
