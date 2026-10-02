//go:build unix

package nixstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/afero"
	"github.com/wrouesnel/go-nix/nar"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	. "gopkg.in/check.v1"
)

// nixSchema is the Nix database schema (from Nix's schema.sql).
const nixSchema = `
CREATE TABLE ValidPaths (
    id               integer primary key autoincrement not null,
    path             text unique not null,
    hash             text not null,
    registrationTime integer not null,
    deriver          text,
    narSize          integer,
    ultimate         integer,
    sigs             text,
    ca               text
);
CREATE TABLE Refs (
    referrer  integer not null,
    reference integer not null,
    primary key (referrer, reference),
    foreign key (referrer) references ValidPaths(id) on delete cascade,
    foreign key (reference) references ValidPaths(id) on delete restrict
);
CREATE INDEX IndexReference on Refs(reference);
CREATE TABLE DerivationOutputs (
    drv  integer not null,
    id   text not null,
    path text not null,
    primary key (drv, id),
    foreign key (drv) references ValidPaths(id) on delete cascade
);
CREATE INDEX IndexDerivationOutputs on DerivationOutputs(path);
`

const (
	depName  = "0000000000000000000000000000000d-dep-1.0"
	mainName = "000000000000000000000000000000m0-main-1.0"
	drvName  = "00000000000000000000000000000dr0-main-1.0.drv"
)

// WriterSuite imports into a store whose real location (storeRoot) differs from the
// store path recorded in the database, as when /nix is mounted elsewhere.
type WriterSuite struct {
	nixDb     *pathlib.Path
	storeRoot *pathlib.Path
	srcDir    string
	writer    nixstore.NixStoreWriter
}

var _ = Suite(&WriterSuite{})

func osPath(p string) *pathlib.Path {
	return pathlib.NewPath(p, pathlib.PathWithAfero(afero.NewOsFs()))
}

func (s *WriterSuite) SetUpTest(c *C) {
	root := c.MkDir()
	dbDir := filepath.Join(root, "nix", "var", "nix", "db")
	storeRoot := filepath.Join(root, "nix", "store")
	c.Assert(os.MkdirAll(dbDir, 0o755), IsNil)
	c.Assert(os.MkdirAll(storeRoot, 0o755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(dbDir, "big-lock"), nil, 0o600), IsNil)

	dbPath := filepath.Join(dbDir, "db.sqlite")
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s", dbPath))
	c.Assert(err, IsNil)
	db.MustExec(nixSchema)
	c.Assert(db.Close(), IsNil)

	s.nixDb = osPath(dbPath)
	s.storeRoot = osPath(storeRoot)
	s.srcDir = c.MkDir()
	s.writer, err = nixstore.NewNixStoreWriter(s.nixDb, s.storeRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)
}

func (s *WriterSuite) TearDownTest(c *C) {
	c.Check(s.writer.Close(), IsNil)
	// Imported paths are read-only, which would stop the test directories being removed.
	_ = filepath.WalkDir(s.storeRoot.String(), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}

// makeNar builds a source tree with a regular file, an executable, a symlink and a
// subdirectory and returns its NAR serialisation.
func (s *WriterSuite) makeNar(c *C, name string, content string) []byte {
	src := filepath.Join(s.srcDir, name)
	c.Assert(os.MkdirAll(filepath.Join(src, "bin"), 0o755), IsNil)
	c.Assert(os.WriteFile(filepath.Join(src, "data.txt"), []byte(content), 0o644), IsNil)
	c.Assert(os.WriteFile(filepath.Join(src, "bin", "run"), []byte("#!/bin/sh\n"), 0o755), IsNil)
	c.Assert(os.Symlink("bin/run", filepath.Join(src, "link")), IsNil)
	buf := new(bytes.Buffer)
	c.Assert(nar.DumpPath(buf, src), IsNil)
	return buf.Bytes()
}

func narInfoFor(name string, narData []byte, refs ...string) *nixtypes.NarInfo {
	hash := sha256.Sum256(narData)
	return &nixtypes.NarInfo{
		StorePath:  nixstore.DefaultStorePath + "/" + name,
		NarHash:    nixtypes.TypedNixHash{HashName: "sha256", Hash: hash[:]},
		NarSize:    uint64(len(narData)),
		References: refs,
		Extra:      map[string]string{},
	}
}

func (s *WriterSuite) importNar(c *C, ninfo *nixtypes.NarInfo, narData []byte) (bool, error) {
	return s.writer.ImportNar(context.Background(), ninfo, bytes.NewReader(narData))
}

func (s *WriterSuite) openDB(c *C) *sqlx.DB {
	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", s.nixDb.String()))
	c.Assert(err, IsNil)
	return db
}

func (s *WriterSuite) checkNotPresent(c *C, name string) {
	_, err := os.Lstat(s.storeRoot.Join(name).String())
	c.Check(os.IsNotExist(err), Equals, true, Commentf("%s should not exist", name))
	valid, err := s.writer.IsValidPath(nixstore.DefaultStorePath + "/" + name)
	c.Assert(err, IsNil)
	c.Check(valid, Equals, false)
}

func (s *WriterSuite) TestImportRegistersPath(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData, mainName)
	ninfo.Deriver = drvName
	sig := nixtypes.NixSignature{}
	c.Assert(sig.UnmarshalText([]byte("test-1:"+strings.Repeat("A", 86)+"==")), IsNil)
	ninfo.Sig = []nixtypes.NixSignature{sig}

	imported, err := s.importNar(c, ninfo, narData)
	c.Assert(err, IsNil)
	c.Check(imported, Equals, true)

	// Files are unpacked into the real store root and canonicalised.
	realPath := s.storeRoot.Join(mainName).String()
	data, err := os.ReadFile(filepath.Join(realPath, "data.txt"))
	c.Assert(err, IsNil)
	c.Check(string(data), Equals, "hello")
	for path, mode := range map[string]os.FileMode{
		"":            os.ModeDir | 0o555,
		"bin":         os.ModeDir | 0o555,
		"data.txt":    0o444,
		"bin/run":     0o555,
		"link":        os.ModeSymlink,
		"nonexistent": 0,
	} {
		info, err := os.Lstat(filepath.Join(realPath, path))
		if mode == 0 {
			c.Check(os.IsNotExist(err), Equals, true)
			continue
		}
		c.Assert(err, IsNil)
		if mode == os.ModeSymlink {
			c.Check(info.Mode()&os.ModeSymlink, Equals, os.ModeSymlink)
		} else {
			c.Check(info.Mode(), Equals, mode, Commentf("mode of %q", path))
		}
		c.Check(info.ModTime().Unix(), Equals, int64(1), Commentf("mtime of %q", path))
	}
	target, err := os.Readlink(filepath.Join(realPath, "link"))
	c.Assert(err, IsNil)
	c.Check(target, Equals, "bin/run")

	// The database records the logical store path, not where it is on disk.
	db := s.openDB(c)
	defer db.Close()
	var row nixstore.ValidPaths
	c.Assert(db.Get(&row, `SELECT * FROM ValidPaths WHERE path = ?`, ninfo.StorePath), IsNil)
	hash := sha256.Sum256(narData)
	c.Check(row.Hash, Equals, fmt.Sprintf("sha256:%x", hash))
	c.Check(row.NarSize, Equals, uint64(len(narData)))
	c.Check(row.Deriver, Equals, sql.Null[string]{V: "/nix/store/" + drvName, Valid: true})
	c.Check(row.Sigs, Equals, sql.Null[string]{V: sig.String(), Valid: true})
	c.Check(row.Ca.Valid, Equals, false)
	c.Check(time.Since(time.Unix(int64(row.RegistrationTime), 0)) < time.Minute, Equals, true)

	var refs []string
	c.Assert(db.Select(&refs, `SELECT v.path FROM Refs JOIN ValidPaths v ON v.id = reference WHERE referrer = ?`, row.Id), IsNil)
	c.Check(refs, DeepEquals, []string{ninfo.StorePath})

	// The read side serves back an identical NAR.
	store, err := nixstore.NewNixStore(s.nixDb, s.storeRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)
	served, _, err := store.GetNarInfo(mainName)
	c.Assert(err, IsNil)
	c.Check(served.Deriver, Equals, drvName)
	out := new(bytes.Buffer)
	c.Assert(store.GetNar(out, &served), IsNil)
	c.Check(sha256.Sum256(out.Bytes()), Equals, hash)
}

func (s *WriterSuite) TestImportAlreadyValid(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData)
	imported, err := s.importNar(c, ninfo, narData)
	c.Assert(err, IsNil)
	c.Check(imported, Equals, true)

	imported, err = s.importNar(c, ninfo, narData)
	c.Assert(err, IsNil)
	c.Check(imported, Equals, false)
}

func (s *WriterSuite) TestImportRequiresReferences(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData, depName, mainName)

	_, err := s.importNar(c, ninfo, narData)
	_, rejected := err.(*nixstore.ErrRejected)
	c.Assert(rejected, Equals, true, Commentf("%v", err))
	s.checkNotPresent(c, mainName)

	depData := s.makeNar(c, depName, "dep")
	_, err = s.importNar(c, narInfoFor(depName, depData), depData)
	c.Assert(err, IsNil)

	_, err = s.importNar(c, ninfo, narData)
	c.Assert(err, IsNil)

	db := s.openDB(c)
	defer db.Close()
	var refs []string
	c.Assert(db.Select(&refs, `SELECT v2.path FROM Refs JOIN ValidPaths v1 ON v1.id = referrer
		JOIN ValidPaths v2 ON v2.id = reference WHERE v1.path = ? ORDER BY v2.path`, ninfo.StorePath), IsNil)
	c.Check(refs, DeepEquals, []string{"/nix/store/" + depName, "/nix/store/" + mainName})
}

func (s *WriterSuite) TestImportRejectsHashMismatch(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, s.makeNar(c, depName, "other"))
	ninfo.NarSize = 0

	_, err := s.importNar(c, ninfo, narData)
	c.Assert(err, ErrorMatches, ".*NAR hash mismatch.*")
	s.checkNotPresent(c, mainName)
}

func (s *WriterSuite) TestImportRejectsSizeMismatch(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData)
	ninfo.NarSize++

	_, err := s.importNar(c, ninfo, narData)
	c.Assert(err, ErrorMatches, ".*NAR size mismatch.*")
	s.checkNotPresent(c, mainName)
}

func (s *WriterSuite) TestImportRejectsCorruptNar(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	truncated := narData[:len(narData)/2]

	_, err := s.importNar(c, narInfoFor(mainName, truncated), truncated)
	_, rejected := err.(*nixstore.ErrRejected)
	c.Assert(rejected, Equals, true, Commentf("%v", err))
	s.checkNotPresent(c, mainName)
}

func (s *WriterSuite) TestImportRejectsBadPaths(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	for _, mutate := range []func(n *nixtypes.NarInfo){
		func(n *nixtypes.NarInfo) { n.StorePath = "/other/store/" + mainName },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/../" + mainName },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/.." },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/short-name" },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/000000000000000000000000000000m0-bad/name" },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/000000000000000000000000000000m0-" },
		func(n *nixtypes.NarInfo) { n.StorePath = "/nix/store/000000000000000000000000000000m0-.." },
		func(n *nixtypes.NarInfo) { n.References = []string{"../../etc"} },
		func(n *nixtypes.NarInfo) { n.Deriver = "../x.drv" },
		func(n *nixtypes.NarInfo) { n.NarHash.HashName = "sha1" },
	} {
		ninfo := narInfoFor(mainName, narData)
		mutate(ninfo)
		_, err := s.importNar(c, ninfo, narData)
		_, rejected := err.(*nixstore.ErrRejected)
		c.Check(rejected, Equals, true, Commentf("%+v: %v", ninfo, err))
	}
	s.checkNotPresent(c, mainName)
}

func (s *WriterSuite) TestImportReplacesInvalidLeftover(c *C) {
	leftover := s.storeRoot.Join(mainName).String()
	c.Assert(os.MkdirAll(filepath.Join(leftover, "junk"), 0o755), IsNil)
	c.Assert(os.Chmod(leftover, 0o555), IsNil)

	narData := s.makeNar(c, mainName, "hello")
	imported, err := s.importNar(c, narInfoFor(mainName, narData), narData)
	c.Assert(err, IsNil)
	c.Check(imported, Equals, true)
	_, err = os.Stat(filepath.Join(leftover, "junk"))
	c.Check(os.IsNotExist(err), Equals, true)
}

func (s *WriterSuite) TestImportDerivationRegistersOutputs(c *C) {
	outPath := "/nix/store/" + mainName
	drv := fmt.Sprintf(`Derive([("out","%s","","")],[],[],"x86_64-linux","/bin/sh",[],[("name","main-1.0"),("out","%s")])`, outPath, outPath)
	src := filepath.Join(s.srcDir, drvName)
	c.Assert(os.WriteFile(src, []byte(drv), 0o644), IsNil)
	buf := new(bytes.Buffer)
	c.Assert(nar.DumpPath(buf, src), IsNil)

	ninfo := narInfoFor(drvName, buf.Bytes())
	ninfo.CA = "text:sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s"
	_, err := s.importNar(c, ninfo, buf.Bytes())
	c.Assert(err, IsNil)

	db := s.openDB(c)
	defer db.Close()
	var outputs []struct {
		Id   string `db:"id"`
		Path string `db:"path"`
	}
	c.Assert(db.Select(&outputs, `SELECT d.id, d.path FROM DerivationOutputs d JOIN ValidPaths v ON v.id = d.drv
		WHERE v.path = ?`, ninfo.StorePath), IsNil)
	c.Assert(outputs, HasLen, 1)
	c.Check(outputs[0].Id, Equals, "out")
	c.Check(outputs[0].Path, Equals, outPath)
	var ca string
	c.Assert(db.Get(&ca, `SELECT ca FROM ValidPaths WHERE path = ?`, ninfo.StorePath), IsNil)
	c.Check(ca, Equals, ninfo.CA)
}

func (s *WriterSuite) TestConcurrentImportsOfSamePath(c *C) {
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData)

	const workers = 8
	results := make(chan bool, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			imported, err := s.writer.ImportNar(context.Background(), ninfo, bytes.NewReader(narData))
			c.Check(err, IsNil)
			results <- imported
		}()
	}
	wg.Wait()
	close(results)
	count := 0
	for imported := range results {
		if imported {
			count++
		}
	}
	c.Check(count, Equals, 1)
	_, err := os.Stat(s.storeRoot.Join(mainName + ".lock").String())
	c.Check(os.IsNotExist(err), Equals, true)
}

func (s *WriterSuite) TestNotWritableStore(c *C) {
	if os.Geteuid() == 0 {
		c.Skip("root can write to read-only directories")
	}
	c.Assert(os.Chmod(s.storeRoot.String(), 0o555), IsNil)
	defer os.Chmod(s.storeRoot.String(), 0o755)
	_, err := nixstore.NewNixStoreWriter(s.nixDb, s.storeRoot, nixstore.DefaultStorePath)
	c.Assert(err, ErrorMatches, ".*not writable.*")
}

func (s *WriterSuite) TestValidateStorePathName(c *C) {
	c.Check(nixstore.ValidateStorePathName(mainName), IsNil)
	c.Check(nixstore.ValidateStorePathName("00000000000000000000000000000000-a+b_c=d?e.f"), IsNil)
	for _, name := range []string{
		"", "-", mainName[:32], "0000000000000000000000000000000e-x", "00000000000000000000000000000000-",
		"00000000000000000000000000000000-.", "00000000000000000000000000000000-..",
		"00000000000000000000000000000000-a/b", "00000000000000000000000000000000-a b",
		"00000000000000000000000000000000-" + strings.Repeat("a", 212),
	} {
		c.Check(nixstore.ValidateStorePathName(name), NotNil, Commentf("%q", name))
	}
}

func (s *WriterSuite) TestSignPath(c *C) {
	key, err := nixtypes.GeneratePrivateKey("push-1")
	c.Assert(err, IsNil)
	sign := func(ninfo *nixtypes.NarInfo) (bool, error) {
		signed, _, err := ninfo.Sign(key)
		return signed, err
	}

	_, err = s.writer.SignPath(nixstore.DefaultStorePath+"/"+mainName, sign)
	_, notFound := err.(*nixstore.ErrNotFound)
	c.Check(notFound, Equals, true, Commentf("%v", err))

	depData := s.makeNar(c, depName, "dep")
	_, err = s.importNar(c, narInfoFor(depName, depData), depData)
	c.Assert(err, IsNil)
	narData := s.makeNar(c, mainName, "hello")
	ninfo := narInfoFor(mainName, narData, mainName, depName)
	_, err = s.importNar(c, ninfo, narData)
	c.Assert(err, IsNil)

	// The callback sees the registered metadata, and its signatures are stored.
	signed, err := s.writer.SignPath(ninfo.StorePath, func(stored *nixtypes.NarInfo) (bool, error) {
		c.Check(stored.StorePath, Equals, ninfo.StorePath)
		c.Check(stored.NarHash, DeepEquals, ninfo.NarHash)
		c.Check(stored.NarSize, Equals, ninfo.NarSize)
		c.Check(stored.References, DeepEquals, []string{depName, mainName})
		return sign(stored)
	})
	c.Assert(err, IsNil)
	c.Check(signed, Equals, true)
	signed, err = s.writer.SignPath(ninfo.StorePath, sign)
	c.Assert(err, IsNil)
	c.Check(signed, Equals, false)

	// The signature is valid for the narinfo the store serves.
	store, err := nixstore.NewNixStore(s.nixDb, s.storeRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)
	served, _, err := store.GetNarInfo(mainName)
	c.Assert(err, IsNil)
	valid, _ := served.Verify(key.PublicKey())
	c.Check(valid, Equals, true)
	c.Check(served.Sig, HasLen, 1)

	// Nothing is written if the callback fails.
	other, err := nixtypes.GeneratePrivateKey("other-1")
	c.Assert(err, IsNil)
	_, err = s.writer.SignPath(ninfo.StorePath, func(stored *nixtypes.NarInfo) (bool, error) {
		_, _, _ = stored.Sign(other)
		return true, errors.New("failed")
	})
	c.Check(err, ErrorMatches, "failed")
	served, _, err = store.GetNarInfo(mainName)
	c.Assert(err, IsNil)
	c.Check(served.Sig, HasLen, 1)
}
