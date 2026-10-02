package nixstore

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/samber/lo"
	"github.com/wrouesnel/go-nix/nar"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
)

// ErrRejected is returned when an import is refused because of the content supplied
// by the client (as opposed to a server-side failure).
type ErrRejected struct {
	Reason string
}

func (e ErrRejected) Error() string {
	return fmt.Sprintf("rejected: %s", e.Reason)
}

func rejectf(format string, args ...any) error {
	return &ErrRejected{Reason: fmt.Sprintf(format, args...)}
}

// NixStoreWriter imports NAR files into a local Nix store and registers them in the
// Nix database, the same way Nix does when substituting a path.
type NixStoreWriter interface {
	// IsValidPath reports whether the store path is registered in the database.
	IsValidPath(storePath string) (bool, error)
	// ImportNar unpacks the uncompressed NAR into the store and registers it using
	// the metadata from ninfo. Returns false if the path was already valid.
	ImportNar(ctx context.Context, ninfo *nixtypes.NarInfo, narReader io.Reader) (bool, error)
	Close() error
}

type nixStoreWriter struct {
	// storeRoot is the real location of the nix store
	storeRoot *pathlib.Path
	// storePath is the logical store path recorded in the database (usually /nix/store)
	storePath string
	db        *sqlx.DB
	// bigLock is held with a shared lock for the lifetime of the writer, as Nix does.
	bigLock *os.File
	// pathMtx serializes imports of the same path within this process, since fcntl
	// locks don't exclude other threads of the same process.
	pathMtx   sync.Mutex
	pathLocks map[string]*sync.Mutex
}

// NewNixStoreWriter opens the Nix database for writing. storeRoot is where the store
// actually lives on disk, and storePath is the store directory it is known as to Nix
// (these differ when the store is mounted somewhere other than /nix/store).
func NewNixStoreWriter(nixDb *pathlib.Path, storeRoot *pathlib.Path, storePath string) (NixStoreWriter, error) {
	if err := checkWritable(storeRoot.String(), nixDb.String(), filepath.Dir(nixDb.String())); err != nil {
		return nil, err
	}

	// Nix holds a shared lock on big-lock while using the database; schema upgrades take it exclusively.
	var bigLock *os.File
	bigLockPath := filepath.Join(filepath.Dir(nixDb.String()), "big-lock")
	if _, err := os.Stat(bigLockPath); err == nil {
		bigLock, err = lockFile(bigLockPath, false)
		if err != nil {
			return nil, fmt.Errorf("could not lock %s: %w", bigLockPath, err)
		}
	}

	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(60000)&_pragma=foreign_keys(1)", nixDb.String()))
	if err != nil {
		closeLock(bigLock)
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		closeLock(bigLock)
		return nil, err
	}

	return &nixStoreWriter{
		storeRoot: storeRoot,
		storePath: strings.TrimSuffix(storePath, "/"),
		db:        db,
		bigLock:   bigLock,
		pathLocks: map[string]*sync.Mutex{},
	}, nil
}

func (n *nixStoreWriter) Close() error {
	err := n.db.Close()
	closeLock(n.bigLock)
	return err
}

func (n *nixStoreWriter) IsValidPath(storePath string) (bool, error) {
	var id int64
	err := n.db.Get(&id, `SELECT id FROM ValidPaths WHERE path = ?`, storePath)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// lockPath takes the in-process lock for a store path name.
func (n *nixStoreWriter) lockPath(name string) func() {
	n.pathMtx.Lock()
	mtx, ok := n.pathLocks[name]
	if !ok {
		mtx = new(sync.Mutex)
		n.pathLocks[name] = mtx
	}
	n.pathMtx.Unlock()
	mtx.Lock()
	return mtx.Unlock
}

// validateNarInfo checks a client-supplied narinfo is safe to import into this store.
func (n *nixStoreWriter) validateNarInfo(ninfo *nixtypes.NarInfo) error {
	dir, name := filepath.Split(ninfo.StorePath)
	if strings.TrimSuffix(dir, "/") != n.storePath {
		return rejectf("store path %q is not in store %q", ninfo.StorePath, n.storePath)
	}
	if err := ValidateStorePathName(name); err != nil {
		return err
	}
	for _, ref := range ninfo.References {
		if err := ValidateStorePathName(ref); err != nil {
			return err
		}
	}
	if ninfo.Deriver != "" && ninfo.Deriver != "unknown-deriver" {
		if err := ValidateStorePathName(ninfo.Deriver); err != nil {
			return err
		}
	}
	if ninfo.NarHash.HashName != "sha256" || len(ninfo.NarHash.Hash) != sha256.Size {
		return rejectf("unsupported NAR hash %q", ninfo.NarHash.String())
	}
	return nil
}

func (n *nixStoreWriter) ImportNar(ctx context.Context, ninfo *nixtypes.NarInfo, narReader io.Reader) (bool, error) {
	if err := n.validateNarInfo(ninfo); err != nil {
		return false, err
	}
	name := filepath.Base(ninfo.StorePath)
	realPath := n.storeRoot.Join(name).String()

	defer n.lockPath(name)()
	// Use the same lock file as Nix so we exclude a nix-daemon substituting the same path.
	unlock, err := lockStorePath(realPath)
	if err != nil {
		return false, fmt.Errorf("could not lock store path: %w", err)
	}
	defer unlock()

	if valid, err := n.IsValidPath(ninfo.StorePath); err != nil {
		return false, err
	} else if valid {
		return false, nil
	}

	for _, ref := range ninfo.References {
		if ref == name {
			continue
		}
		refPath := n.storePath + "/" + ref
		if valid, err := n.IsValidPath(refPath); err != nil {
			return false, err
		} else if !valid {
			return false, rejectf("reference %q is not valid in this store", refPath)
		}
	}

	// An invalid path may be left over from an interrupted import.
	if err := removeAll(realPath); err != nil {
		return false, fmt.Errorf("could not remove invalid path: %w", err)
	}

	imported := false
	defer func() {
		if !imported {
			_ = removeAll(realPath)
		}
	}()

	hasher := sha256.New()
	counter := &countingWriter{}
	tee := io.TeeReader(narReader, io.MultiWriter(hasher, counter))
	if err := restoreNar(ctx, nar.NewReader(bufio.NewReader(tee)), realPath); err != nil {
		var rejected *ErrRejected
		if errors.As(err, &rejected) || ctx.Err() != nil {
			return false, err
		}
		return false, rejectf("could not unpack NAR: %v", err)
	}

	if !slices.Equal(hasher.Sum(nil), ninfo.NarHash.Hash) {
		return false, rejectf("NAR hash mismatch: expected %s got sha256:%s", ninfo.NarHash.String(),
			nixtypes.NixBase32Field(hasher.Sum(nil)).String())
	}
	if ninfo.NarSize != 0 && ninfo.NarSize != counter.n {
		return false, rejectf("NAR size mismatch: expected %d got %d", ninfo.NarSize, counter.n)
	}

	if err := canonicalisePath(realPath); err != nil {
		return false, fmt.Errorf("could not canonicalise path: %w", err)
	}

	var drvOutputs map[string]string
	if strings.HasSuffix(name, ".drv") {
		drvOutputs, err = readDerivationOutputs(realPath)
		if err != nil {
			return false, rejectf("could not parse derivation: %v", err)
		}
	}

	if err := n.registerValidPath(ninfo, drvOutputs, counter.n); err != nil {
		return false, err
	}
	imported = true
	return true, nil
}

// registerValidPath records the path in the database, as Nix's registerValidPath does.
func (n *nixStoreWriter) registerValidPath(ninfo *nixtypes.NarInfo, drvOutputs map[string]string, narSize uint64) error {
	tx, err := n.db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	deriver := sql.Null[string]{}
	if ninfo.Deriver != "" && ninfo.Deriver != "unknown-deriver" {
		deriver = sql.Null[string]{V: n.storePath + "/" + ninfo.Deriver, Valid: true}
	}
	sigs := lo.Map(ninfo.Sig, func(item nixtypes.NixSignature, _ int) string { return item.String() })

	result, err := tx.Exec(`INSERT INTO ValidPaths (path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca)
		VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`,
		ninfo.StorePath,
		fmt.Sprintf("sha256:%s", hex.EncodeToString(ninfo.NarHash.Hash)),
		time.Now().Unix(),
		deriver,
		narSize,
		sql.Null[string]{V: strings.Join(sigs, " "), Valid: len(sigs) > 0},
		sql.Null[string]{V: ninfo.CA, Valid: ninfo.CA != ""},
	)
	if err != nil {
		return fmt.Errorf("could not register path: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	for _, ref := range ninfo.References {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO Refs (referrer, reference)
			VALUES (?, (SELECT id FROM ValidPaths WHERE path = ?))`, id, n.storePath+"/"+ref); err != nil {
			return fmt.Errorf("could not register reference %s: %w", ref, err)
		}
	}

	for outputName, outputPath := range drvOutputs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO DerivationOutputs (drv, id, path) VALUES (?, ?, ?)`,
			id, outputName, outputPath); err != nil {
			return fmt.Errorf("could not register derivation output %s: %w", outputName, err)
		}
	}

	return tx.Commit()
}

// readDerivationOutputs returns the output paths of an input-addressed derivation.
func readDerivationOutputs(path string) (map[string]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	drv, err := derivation.ReadDerivation(fh)
	if err != nil {
		return nil, err
	}
	outputs := map[string]string{}
	for outputName, output := range drv.Outputs {
		// Floating content-addressed outputs have no path until they're built.
		if output.Path != "" {
			outputs[outputName] = output.Path
		}
	}
	return outputs, nil
}

// restoreNar unpacks a NAR to dest, which must not exist.
func restoreNar(ctx context.Context, nr *nar.Reader, dest string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := nr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// The reader validates entry names, so joining can't escape dest.
		target := dest
		if hdr.Path != "" {
			target = filepath.Join(dest, filepath.FromSlash(hdr.Path))
		}

		switch {
		case hdr.Mode.IsDir():
			if err := os.Mkdir(target, 0o755); err != nil {
				return err
			}
		case hdr.Mode&fs.ModeSymlink != 0:
			if err := os.Symlink(hdr.LinkTarget, target); err != nil {
				return err
			}
		case hdr.Mode.IsRegular():
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			if err := writeFile(target, nr, mode); err != nil {
				return err
			}
		default:
			return rejectf("unsupported NAR entry type for %q", hdr.Path)
		}
	}
}

func writeFile(target string, r io.Reader, mode os.FileMode) error {
	fh, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(fh, r); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// canonicalisePath sets the permissions and timestamps of an imported path the way Nix
// expects them: read-only, executable bits preserved, and mtime of 1.
func canonicalisePath(root string) error {
	paths := []string{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return err
	}
	// Children first, so directories are made read-only after their contents.
	for _, path := range slices.Backward(paths) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			mode := os.FileMode(0o444)
			if info.IsDir() || info.Mode()&0o100 != 0 {
				mode = 0o555
			}
			if err := os.Chmod(path, mode); err != nil {
				return err
			}
		}
		if err := lchtimes(path, time.Unix(1, 0)); err != nil {
			return err
		}
	}
	return nil
}

// removeAll removes a path, including read-only directories from a canonicalised import.
func removeAll(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
	return os.RemoveAll(path)
}

type countingWriter struct {
	n uint64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}

// storePathNameMaxLen is the longest store path name (hash and name) Nix accepts.
const storePathNameMaxLen = 211 + storeHashLen + 1

// ValidateStorePathName checks a store path base name (<hash>-<name>) is well-formed.
func ValidateStorePathName(name string) error {
	hash, pkgName, found := strings.Cut(name, "-")
	if !found || !isStoreHash(hash) {
		return rejectf("invalid store path hash in %q", name)
	}
	if pkgName == "" || len(name) > storePathNameMaxLen || pkgName == "." || pkgName == ".." {
		return rejectf("invalid store path name %q", name)
	}
	for _, c := range pkgName {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && !strings.ContainsRune("+-._?=", c) {
			return rejectf("invalid character in store path name %q", name)
		}
	}
	return nil
}
