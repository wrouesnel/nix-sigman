package entrypoint_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	"github.com/wrouesnel/nix-sigman/pkg/nixconsts"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	. "gopkg.in/check.v1"
)

type BundleSuite struct{}

var _ = Suite(&BundleSuite{})

const bundleHash = "58br4vk3q5akf4g8lx0pqzfhn47k3j8d"

// makeStore creates a tiny store path and a Nix DB describing it.
func (s *BundleSuite) makeStore(c *C) (storeDir string, dbPath string) {
	baseDir := c.MkDir()
	storeDir = filepath.Join(baseDir, "store")
	storePath := filepath.Join(storeDir, bundleHash+"-hello")
	c.Assert(os.MkdirAll(storePath, os.FileMode(0755)), IsNil)
	c.Assert(os.WriteFile(filepath.Join(storePath, "hello.txt"), []byte("hello world\n"), os.FileMode(0644)), IsNil)

	dbPath = filepath.Join(baseDir, "db.sqlite")
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s", dbPath))
	c.Assert(err, IsNil)
	defer db.Close()
	db.MustExec(`CREATE TABLE ValidPaths (id integer primary key autoincrement not null, path text unique not null,
		hash text not null, registrationTime integer not null, deriver text, narSize integer,
		ultimate integer, sigs text, ca text)`)
	db.MustExec(`CREATE TABLE Refs (referrer integer not null, reference integer not null, primary key (referrer, reference))`)
	hash := "sha256:" + fmt.Sprintf("%x", sha256.Sum256([]byte("unused")))
	db.MustExec(`INSERT INTO ValidPaths (id, path, hash, registrationTime, sigs) VALUES (1, ?, ?, 0, '')`, storePath, hash)
	// Insert references so their natural row order is not sorted.
	db.MustExec(`INSERT INTO ValidPaths (id, path, hash, registrationTime) VALUES (2, ?, ?, 0)`,
		filepath.Join(storeDir, "zzzzvk3q5akf4g8lx0pqzfhn47k3j8d-z"), hash)
	db.MustExec(`INSERT INTO ValidPaths (id, path, hash, registrationTime) VALUES (3, ?, ?, 0)`,
		filepath.Join(storeDir, "aaaavk3q5akf4g8lx0pqzfhn47k3j8d-a"), hash)
	db.MustExec(`INSERT INTO Refs (referrer, reference) VALUES (1, 2), (1, 3)`)
	return storeDir, dbPath
}

func (s *BundleSuite) TestBundle(c *C) {
	storeDir, dbPath := s.makeStore(c)
	outputDir := filepath.Join(c.MkDir(), "out")

	ret := entrypoint.Entrypoint([]string{"bundle", "--nix-db", dbPath, "--output-dir", outputDir,
		filepath.Join(storeDir, bundleHash+"-hello")},
		io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Assert(ret, Equals, 0)

	content, err := os.ReadFile(filepath.Join(outputDir, bundleHash+".narinfo"))
	c.Assert(err, IsNil)
	ninfo := nixtypes.NarInfo{}
	c.Assert(ninfo.UnmarshalText(content), IsNil)

	narFile, err := os.ReadFile(filepath.Join(outputDir, ninfo.URL))
	c.Assert(err, IsNil)
	fileHash := sha256.Sum256(narFile)
	c.Check(ninfo.FileSize, Equals, uint64(len(narFile)))
	c.Check(ninfo.FileHash.Hash, DeepEquals, nixtypes.NixBase32Field(fileHash[:]))
	c.Check(ninfo.Deriver, Equals, "")
	c.Check(ninfo.References, DeepEquals, []string{
		"aaaavk3q5akf4g8lx0pqzfhn47k3j8d-a", "zzzzvk3q5akf4g8lx0pqzfhn47k3j8d-z"})

	cacheInfo, err := os.ReadFile(filepath.Join(outputDir, nixconsts.NixCacheInfoName))
	c.Assert(err, IsNil)
	c.Check(string(cacheInfo), Matches, fmt.Sprintf("(?s)StoreDir: %s\n.*", storeDir))
}
