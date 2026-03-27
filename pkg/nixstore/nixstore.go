package nixstore

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"zombiezen.com/go/nix/nar"

	_ "modernc.org/sqlite"
)

type NixStore interface {
	GetNarInfo(path string) (nixtypes.NarInfo, error)
	GetNar(path string) (io.ReadCloser, error)
}

const sqlLookupPath = `
SELECT * FROM ValidPaths
         WHERE path LIKE ?
`

const sqlLookupPathRefs = `
select path from Refs join ValidPaths on reference = id where referrer = ?;
`

func NewNixStore(root *pathlib.Path) (NixStore, error) {
	// Try and open the database
	dbPath := root.Join("var/nix/db/db.sqlite")

	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", dbPath.String()))
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// It's presumed the root is a path to the root of /nix
	// By contention, nix stores pretty much all paths are /nix/store/<something>
	//

	return &nixStore{
		root: root,
		db:   db,
	}, nil
}

type nixStore struct {
	root *pathlib.Path
	db   *sqlx.DB
}

func (n *nixStore) GetNarInfo(path string) (nixtypes.NarInfo, error) {
	// Extract the hashname
	hashName, _, _ := strings.Cut(filepath.Base(path), "-")

	// TODO: does this need sanitizing? You can't really do anything by messing with
	// the lookup given the construction.

	// Execute a very loosey-goosey search so we can work with other paths
	nixPath := new(ValidPaths)
	lookupArg := fmt.Sprintf("%%/%s-%%", hashName)
	if err := n.db.Get(nixPath, sqlLookupPath, lookupArg); err != nil {
		return nixtypes.NarInfo{}, err
	}

	fileHash := nixtypes.TypedNixHash{}
	if err := fileHash.UnmarshalText([]byte(nixPath.Hash)); err != nil {
		return nixtypes.NarInfo{}, err
	}

	sigs := []nixtypes.NixSignature{}
	for _, sigStr := range strings.Split(nixPath.Sigs.V, " ") {
		if sigStr == "" {
			continue
		}
		sig := nixtypes.NixSignature{}
		if err := sig.UnmarshalText([]byte(sigStr)); err != nil {
			return nixtypes.NarInfo{}, err
		}
		sigs = append(sigs, sig)
	}

	// Query the refs
	refs := []string{}
	if err := n.db.Select(&refs, sqlLookupPathRefs, nixPath.Id); err != nil {
		return nixtypes.NarInfo{}, err
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
		Deriver:     filepath.Base(nixPath.Deriver.V),
		Sig:         sigs,
		CA:          nixPath.Ca.V,
		Extra:       map[string]string{},
	}, nil
}

func (n *nixStore) GetNar(path string) (io.ReadCloser, error) {
	// Extract the hashname
	hashName, _, _ := strings.Cut(filepath.Base(path), "-")

	// TODO: does this need sanitizing? You can't really do anything by messing with
	// the lookup given the construction.

	// Execute a very loosey-goosey search so we can work with other paths
	nixPath := new(ValidPaths)
	lookupArg := fmt.Sprintf("%%/%s-%%", hashName)
	if err := n.db.Get(nixPath, sqlLookupPath, lookupArg); err != nil {
		return nil, err
	}

	// Our expectation is n.root points to `/nix` or wherever `/nix` has been mounted.
	// So our intepretation of nix paths should reflect this - namely we go one level up,
	// and then use that as the base for what path we want to dump from the DB.
	// This _does not work_ with alternate store directories.
	rdr, wr := io.Pipe()
	go func() {
		err := nar.DumpPath(wr,n.root.Parent().Join(nixPath.Path).String())
		wr.CloseWithError(err)
	}()

	return rdr, nil
}
