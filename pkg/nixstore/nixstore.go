//go:generate go tool go-enum --marshal --names --values
package nixstore

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/samber/lo"
	"github.com/wrouesnel/go-nix/nar"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"

	_ "modernc.org/sqlite"
)

type ErrInvalid struct {
}

func (e ErrInvalid) Error() string {
	return "invalid query"
}

type ErrNotFound struct {
	HashName string
}

func (e ErrNotFound) Error() string {
	return fmt.Sprintf("not found: %s", e.HashName)
}

type ErrShortWrite struct {
	Header       nar.Header
	WrittenBytes int64
}

func (e ErrShortWrite) Error() string {
	return fmt.Sprintf("too few bytes copied for nar header content: expected %v got %v", e.Header.Size, e.WrittenBytes)
}

type NixStore interface {
	GetNarInfo(path string) (nixtypes.NarInfo, time.Time, error)
	GetNar(w io.Writer, ninfo *nixtypes.NarInfo) error
	// GetStorePathByURL presuming the supplied string is following the convention
	GetStorePathByURL(urlPath string) (string, error)
	GetStorePathByFileHash(fileHash string) (string, error)
}

// Note: this is only efficient if a fixed prefix (the nix store path) is the glob
// i.e. /nix/store/<somehash>-*
const sqlLookupPath = `
SELECT * FROM ValidPaths
         WHERE path glob ?;
`

const sqlLookupPathRefs = `
select path from Refs join ValidPaths on reference = id where referrer = ?;
`

const sqlLookupPathByFileHash = `
SELECT * FROM ValidPaths
         WHERE hash = ?
`

const sqlGetHashingAlg = `
SELECT * FROM ValidPaths ORDER BY ROWID ASC LIMIT 1
`

const DefaultNixDBPath = "nix/var/nix/db/db.sqlite"
const DefaultNixStoreRoot = "nix/store"
const DefaultStorePath = "/nix/store"

// NarURLFormatConvention defines the convention to use for NAR URLs served by
// the server.
// ENUM(
// nixhash  // Use the Nix hash path for lookups
// filehash // Use the filehash only. Slow if an index on the hash is not included
// )
type NarURLFormatConvention string

type NixStoreOption func(opt *nixStoreOptions)

type nixStoreOptions struct {
	narURLFormatConvention NarURLFormatConvention
}

func WithNARURLFormatConvention(conv NarURLFormatConvention) NixStoreOption {
	return func(opt *nixStoreOptions) {
		opt.narURLFormatConvention = conv
	}
}

func DefaultNixStore(root *pathlib.Path) (db *pathlib.Path, storeRoot *pathlib.Path) {
	db = root.Join(DefaultNixDBPath)
	storeRoot = root.Join(DefaultNixStoreRoot)
	return
}

func NewNixStore(nixDb *pathlib.Path, storeRoot *pathlib.Path, storePath string, opts ...NixStoreOption) (NixStore, error) {
	options := nixStoreOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", nixDb.String()))
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	nixPaths := make([]ValidPaths, 0)
	if err := db.Select(&nixPaths, sqlGetHashingAlg); err != nil {
		return nil, err
	}

	hashingAlg := "sha256"
	if len(nixPaths) > 0 {
		hashingAlg, _, _ = strings.Cut(nixPaths[0].Hash, ":")
	}

	return &nixStore{
		nixDb:           nixDb,
		storeRoot:       storeRoot,
		storePath:       storePath,
		db:              db,
		hashingAlg:      hashingAlg,
		nixStoreOptions: options,
	}, nil
}

type nixStore struct {
	// nixDb is the path to the nix database
	nixDb *pathlib.Path
	// storeRoot is the path to the real location of the nix store
	storeRoot *pathlib.Path
	// storePath is prefix to be expected from store paths (removed to look them up in storeRoot)
	storePath string
	db        *sqlx.DB
	// hashingAlg is the detected file hashing algorithm from the database
	hashingAlg string
	// nix store behavior options from users
	nixStoreOptions
}

func (n *nixStore) GetNarInfo(path string) (nixtypes.NarInfo, time.Time, error) {
	// Extract the hashname
	trimmed, _, _ := strings.Cut(filepath.Base(path), ".")
	hashName, _, _ := strings.Cut(trimmed, "-")

	// TODO: does this need sanitizing? You can't really do anything by messing with
	// the lookup given the construction.

	// Execute a very loosey-goosey search so we can work with other paths
	nixPath := new(ValidPaths)
	lookupArg := fmt.Sprintf("%s/%s-*", n.storePath, hashName)
	if err := n.db.Get(nixPath, sqlLookupPath, lookupArg); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nixtypes.NarInfo{}, time.Time{}, &ErrNotFound{HashName: hashName}
		}
		return nixtypes.NarInfo{}, time.Time{}, err
	}

	registrationTime := time.Unix(int64(nixPath.RegistrationTime), 0)

	fileHash := nixtypes.TypedNixHash{}
	if err := fileHash.UnmarshalText([]byte(nixPath.Hash)); err != nil {
		return nixtypes.NarInfo{}, time.Time{}, err
	}

	sigs := []nixtypes.NixSignature{}
	for _, sigStr := range strings.Split(nixPath.Sigs.V, " ") {
		if sigStr == "" {
			continue
		}
		sig := nixtypes.NixSignature{}
		if err := sig.UnmarshalText([]byte(sigStr)); err != nil {
			return nixtypes.NarInfo{}, time.Time{}, err
		}
		sigs = append(sigs, sig)
	}

	// Query the refs
	refs := []string{}
	if err := n.db.Select(&refs, sqlLookupPathRefs, nixPath.Id); err != nil {
		return nixtypes.NarInfo{}, time.Time{}, err
	}

	refs = lo.Map(refs, func(item string, index int) string {
		return filepath.Base(item)
	})

	slices.Sort(refs)

	url := fmt.Sprintf("nar/%s.nar", hashName)
	switch n.nixStoreOptions.narURLFormatConvention {
	case NarURLFormatConventionFilehash:
		url = fmt.Sprintf("nar/%s.nar", fileHash.Hash.String())
	default:
		// No change from store default
	}

	// Return the narinfo
	return nixtypes.NarInfo{
		StorePath:   nixPath.Path,
		URL:         url,
		Compression: "none",
		FileHash:    fileHash,
		FileSize:    nixPath.NarSize,
		NarHash:     fileHash, // No compression means these are the same
		NarSize:     nixPath.NarSize,
		References:  refs,
		Deriver:     lo.Ternary(nixPath.Deriver.Valid, filepath.Base(nixPath.Deriver.V), ""),
		Sig:         sigs,
		CA:          nixPath.Ca.V,
		Extra:       map[string]string{},
	}, registrationTime, nil
}

// GetStorePathByURL returns a store path presuming that the supplied URL convention of
// the store is in effect.
func (n *nixStore) GetStorePathByURL(urlPath string) (string, error) {
	switch n.nixStoreOptions.narURLFormatConvention {
	case NarURLFormatConventionFilehash:
		return n.GetStorePathByFileHash(urlPath)
	default:
		// format is nar/<nixhash> - so easy
		ninfo, _, err := n.GetNarInfo(urlPath)
		if err != nil {
			return "", err
		}
		return ninfo.StorePath, nil
	}
}

// GetStorePathByFileHash returns a store path by its filehash. This function is only likely
// to work with NAR info files served by the same server, since if the hash type changes
// then the database lookup won't find anything.
func (n *nixStore) GetStorePathByFileHash(fileHash string) (string, error) {
	// As far as we know, the store paths in the database are always hex-encoded SHA256
	typedHash := nixtypes.TypedNixHash{}
	if err := typedHash.UnmarshalText([]byte(fmt.Sprintf("%s:%s", n.hashingAlg, fileHash))); err != nil {
		return "", errors.Join(&ErrInvalid{}, err)
	}

	// There's an observed failure where the hex encoded file hash gets passed directly through to
	// the substitution endpoint. If that's the case, we can end up double-encoding and thus
	// failing.
	// Handle this by, in the event of a failure, just trying a direct lookup of whatever we
	// we were given. TODO: maybe check if the path looks plausibly like it if we see performance issues?

	hashLookup := fmt.Sprintf("%s:%s", n.hashingAlg, hex.EncodeToString(typedHash.Hash))
	// Execute a very loosey-goosey search so we can work with other paths
	nixPaths := make([]ValidPaths, 0)
	if err := n.db.Select(&nixPaths, sqlLookupPathByFileHash, hashLookup); err != nil {
		return "", err
	}

	if len(nixPaths) == 0 {
		rawLookup := fmt.Sprintf("%s:%s", n.hashingAlg, typedHash.Hash)
		if err := n.db.Select(&nixPaths, sqlLookupPathByFileHash, rawLookup); err != nil {
			return "", err
		}
		if len(nixPaths) == 0 {
			return "", &ErrNotFound{fileHash}
		}
	}

	return nixPaths[0].Path, nil
}

// GetNar writes the NAR referenced by ninfo to the given io.Writer.
func (n *nixStore) GetNar(w io.Writer, ninfo *nixtypes.NarInfo) error {
	// Our expectation is n.root points to `/nix` or wherever `/nix` has been mounted.
	// So our intepretation of nix paths should reflect this - namely we go one level up,
	// and then use that as the base for what path we want to dump from the DB.
	// What path we actually use is determined by the value of n.storePath, which should
	// normally be /nix/store.

	basePath, _ := strings.CutPrefix(ninfo.StorePath, n.storePath)
	realPath := n.storeRoot.Join(basePath)

	writerFunc := func(w *nar.Writer, hdr *nar.Header, fspath string) error {
		// Copy the file directly to the underlying stream (which will be a TCPConn usually)
		// which will allow io.Copy to use splice/sendfile to avoid the user space transfer.
		f, err := os.Open(n.storeRoot.Join(fspath).String())
		if err != nil {
			return err
		}

		// Discard the bytes from the NAR writer itself (which returns us a writer to use
		// for the catch up.
		underlyingWriter, err := w.Skip(hdr.Size)
		if err != nil {
			return err
		}
		// Let io.Copy pipe the file content directly to the writer
		nBytes, err := io.Copy(underlyingWriter, f)
		if nBytes < hdr.Size {
			return &ErrShortWrite{
				Header:       *hdr,
				WrittenBytes: nBytes,
			}
		}
		return err
	}

	err := nar.DumpPath(w, realPath.String(), nar.WithWriterFunc(writerFunc))
	return err
}
