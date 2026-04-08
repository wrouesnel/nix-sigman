package nixstore

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"zombiezen.com/go/nix/nar"

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

type NixStore interface {
	GetNarInfo(path string) (nixtypes.NarInfo, time.Time, error)
	GetNar(path string) (io.ReadCloser, *nixtypes.NarInfo, time.Time, error)
	GetStorePathByFileHash(fileHash string) (string, error)
}

const sqlLookupPath = `
SELECT * FROM ValidPaths
         WHERE path LIKE ?
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

func DefaultNixStore(root *pathlib.Path) (db *pathlib.Path, storeRoot *pathlib.Path) {
	db = root.Join(DefaultNixDBPath)
	storeRoot = root.Join(DefaultNixStoreRoot)
	return
}

func NewNixStore(nixDb *pathlib.Path, storeRoot *pathlib.Path, storePath string) (NixStore, error) {
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
		nixDb:      nixDb,
		storeRoot:  storeRoot,
		storePath:  storePath,
		db:         db,
		hashingAlg: hashingAlg,
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
}

func (n *nixStore) GetNarInfo(path string) (nixtypes.NarInfo, time.Time, error) {
	// Extract the hashname
	trimmed, _, _ := strings.Cut(filepath.Base(path), ".")
	hashName, _, _ := strings.Cut(trimmed, "-")

	// TODO: does this need sanitizing? You can't really do anything by messing with
	// the lookup given the construction.

	// Execute a very loosey-goosey search so we can work with other paths
	nixPath := new(ValidPaths)
	lookupArg := fmt.Sprintf("%%/%s-%%", hashName)
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

	// Return the narinfo
	return nixtypes.NarInfo{
		StorePath:   nixPath.Path,
		URL:         fmt.Sprintf("nar/%s.nar", fileHash.Hash.String()),
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

// GetStorePathByFileHash returns a store path by its filehash. This function is only likely
// to work with NAR info files served by the same server, since if the hash type changes
// then the database lookup won't find anything.
func (n *nixStore) GetStorePathByFileHash(fileHash string) (string, error) {
	// As far as we know, the store paths in the database are always hex-encoded SHA256
	typedHash := nixtypes.TypedNixHash{}
	if err := typedHash.UnmarshalText([]byte(fmt.Sprintf("%s:%s", n.hashingAlg,fileHash))); err != nil {
		return "", err
	}

	hashLookup := fmt.Sprintf("%s:%s", n.hashingAlg, hex.EncodeToString(typedHash.Hash))
	// Execute a very loosey-goosey search so we can work with other paths
	nixPaths := make([]ValidPaths, 0)
	if err := n.db.Select(&nixPaths, sqlLookupPathByFileHash, hashLookup); err != nil {
		return "", err
	}

	if len(nixPaths) == 0 {
		return "", &ErrNotFound{fileHash}
	}

	return nixPaths[0].Path, nil
}

func (n *nixStore) GetNar(path string) (io.ReadCloser, *nixtypes.NarInfo, time.Time, error) {
	ninfo, registrationTime, err := n.GetNarInfo(path)
	if err != nil {
		return nil, nil, registrationTime, err
	}

	// Our expectation is n.root points to `/nix` or wherever `/nix` has been mounted.
	// So our intepretation of nix paths should reflect this - namely we go one level up,
	// and then use that as the base for what path we want to dump from the DB.
	// What path we actually use is determined by the value of n.storePath, which should
	// normally be /nix/store.

	basePath, _ := strings.CutPrefix(ninfo.StorePath, n.storePath)
	realPath := n.storeRoot.Join(basePath)

	rdr, wr := io.Pipe()
	go func() {
		err := nar.DumpPath(wr, realPath.String())
		wr.CloseWithError(err)
	}()

	return rdr, &ninfo, registrationTime, nil
}
