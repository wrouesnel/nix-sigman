package nixstore_test

import (
	"fmt"
	"path/filepath"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	. "gopkg.in/check.v1"
)

// NixStoreDBSuite tests against a minimal synthetic Nix database so it does not
// depend on the host having a Nix store.
type NixStoreDBSuite struct {
	nixDb *pathlib.Path
}

var _ = Suite(&NixStoreDBSuite{})

const testStorePath = "/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37"

func (s *NixStoreDBSuite) SetUpTest(c *C) {
	dbPath := filepath.Join(c.MkDir(), "db.sqlite")
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s", dbPath))
	c.Assert(err, IsNil)
	defer db.Close()
	db.MustExec(`CREATE TABLE ValidPaths (id integer primary key autoincrement not null, path text unique not null,
		hash text not null, registrationTime integer not null, deriver text, narSize integer,
		ultimate integer, sigs text, ca text)`)
	db.MustExec(`CREATE TABLE Refs (referrer integer not null, reference integer not null, primary key (referrer, reference))`)
	db.MustExec(`INSERT INTO ValidPaths (path, hash, registrationTime, narSize) VALUES (?, ?, 0, 1640)`,
		testStorePath, "sha256:f2a9a5bd4b4ad3d3bb3fe9b9bcb9a4b04e5a92ee2be5e5e3d9b0fc6cdda1d66d")
	s.nixDb = pathlib.NewPath(dbPath, pathlib.PathWithAfero(afero.NewOsFs()))
}

func (s *NixStoreDBSuite) addHashIndex(c *C) {
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s", s.nixDb.String()))
	c.Assert(err, IsNil)
	defer db.Close()
	db.MustExec(`CREATE INDEX IndexValidPathsHash ON ValidPaths(hash)`)
}

func (s *NixStoreDBSuite) narURL(c *C, store nixstore.NixStore) string {
	ninfo, _, err := store.GetNarInfo("58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo")
	c.Assert(err, IsNil)
	return ninfo.URL
}

func (s *NixStoreDBSuite) TestAutoFallsBackToNixhashWithoutIndex(c *C) {
	store, err := nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithNARURLFormatConvention(nixstore.NarURLFormatConventionAuto))
	c.Assert(err, IsNil)
	c.Check(s.narURL(c, store), Equals, "nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar")
}

func (s *NixStoreDBSuite) TestAutoUsesFilehashWithIndex(c *C) {
	s.addHashIndex(c)
	store, err := nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithNARURLFormatConvention(nixstore.NarURLFormatConventionAuto))
	c.Assert(err, IsNil)
	c.Check(s.narURL(c, store), Not(Equals), "nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar")
}

func (s *NixStoreDBSuite) TestFilehashRequiresIndex(c *C) {
	_, err := nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithNARURLFormatConvention(nixstore.NarURLFormatConventionFilehash))
	c.Assert(err, NotNil)

	_, err = nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithNARURLFormatConvention(nixstore.NarURLFormatConventionFilehash),
		nixstore.WithNoPerformanceCheck(true))
	c.Assert(err, IsNil)

	s.addHashIndex(c)
	_, err = nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithNARURLFormatConvention(nixstore.NarURLFormatConventionFilehash))
	c.Assert(err, IsNil)
}

func (s *NixStoreDBSuite) TestNixCacheInfo(c *C) {
	store, err := nixstore.NewNixStore(s.nixDb, s.nixDb.Parent(), nixstore.DefaultStorePath,
		nixstore.WithPriority(30))
	c.Assert(err, IsNil)
	text, err := store.GetNixCacheInfo().MarshalText()
	c.Assert(err, IsNil)
	c.Check(string(text), Equals, "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n")
}
