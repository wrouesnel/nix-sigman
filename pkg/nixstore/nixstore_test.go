package nixstore_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/samber/lo"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&NixStoreSuite{})

const wellKnownPath = "/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37"

//const wellKnownPath = "/nix/store/8ranqggwk67p5mii3vimljcb9jr0nliq-nixexprs.tar.xz"

type NixStoreSuite struct {
	nixDb        *pathlib.Path
	nixStoreRoot *pathlib.Path
	store        nixstore.NixStore
}

func (n *NixStoreSuite) SetUpSuite(c *C) {
	var err error
	n.nixDb, n.nixStoreRoot = nixstore.DefaultNixStore(pathlib.NewPath("", pathlib.PathWithAfero(afero.NewOsFs())))
	n.store, err = nixstore.NewNixStore(n.nixDb, n.nixStoreRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)
}

func createBinaryFromNix(c *C, nixPath string) string {
	targetDir := c.MkDir()
	cmd := exec.Command("nix", "copy", "--to", fmt.Sprintf("file://%s?compression=none", targetDir), nixPath)
	err := cmd.Start()
	c.Assert(err, IsNil, Commentf("error invoking system nix command: %v", err))
	err = cmd.Wait()
	c.Assert(err, IsNil, Commentf("error invoking system nix command: %v", err))
	return targetDir
}

// TODO: make up a fake path
func (n *NixStoreSuite) TestNarServingWorks(c *C) {
	ninfo, _, err := n.store.GetNarInfo(wellKnownPath)
	c.Assert(err, IsNil)
	ninfoText, err := ninfo.MarshalText()
	c.Assert(err, IsNil)

	// Compare to the NarInfo
	storeDir := pathlib.NewPath(createBinaryFromNix(c, wellKnownPath), pathlib.PathWithAfero(afero.NewOsFs()))
	canonicalNarInfo, err := storeDir.Join(fmt.Sprintf("%v.narinfo", ninfo.NixHash())).ReadFile()
	c.Assert(err, IsNil)
	c.Assert(string(ninfoText), Equals, string(canonicalNarInfo))

	// Serve the NAR file from the store
	rdr, wr := io.Pipe()

	outputNarFile := lo.Must(storeDir.Join("comparison.nar").OpenFileMode(os.O_CREATE|os.O_WRONLY, os.FileMode(0644)))

	sizeReader := io.TeeReader(rdr, outputNarFile)

	h := sha256.New()
	errp := new(error)
	size := new(int64)
	wg := new(sync.WaitGroup)
	wg.Go(func() {
		*size, *errp = io.Copy(h, sizeReader)
	})

	// Get the NAR
	err = n.store.GetNar(wr, &ninfo)
	wr.CloseWithError(nil)
	// Once we return all our pointers should be safely handled.
	c.Assert(err, IsNil)
	wg.Wait()
	outputNarFile.Close()
	c.Assert(err, IsNil)
	c.Assert(*errp, IsNil)
	c.Assert(uint64(*size), Equals, ninfo.FileSize, Commentf("resulting nar did not match the supplied narinfo size: %v != %v", *size, ninfo.FileSize))

	// Now hash the actual on-disk file and check its the same
	canonicalNarRdr, err := storeDir.Join(ninfo.URL).Open()
	c.Assert(err, IsNil)
	canonicalHash := sha256.New()
	canonicalSize, err := io.Copy(canonicalHash, canonicalNarRdr)
	c.Assert(err, IsNil)
	c.Assert(uint64(canonicalSize), Equals, ninfo.FileSize)

	c.Assert(hex.EncodeToString(h.Sum(nil)), Equals, hex.EncodeToString(canonicalHash.Sum(nil)), Commentf("nar hashes fdid not match"))
}

func (n *NixStoreSuite) BenchmarkNarFileGeneration(c *C) {
	ninfo, _, err := n.store.GetNarInfo(wellKnownPath)
	c.Assert(err, IsNil)

	outputDir := c.MkDir()
	for i := 0; i < c.N; i++ {
		f := lo.Must(os.Create(filepath.Join(outputDir, fmt.Sprintf("%v.nar", i))))
		err := n.store.GetNar(f, &ninfo)
		c.Assert(err, IsNil)
	}
}

// TestMissingNarInfoIsntFound check that searching a hash that definitely does not exist also works.
func (n *NixStoreSuite) TestMissingNarInfoIsntFound(c *C) {
	nixDb, nixStoreRoot := nixstore.DefaultNixStore(pathlib.NewPath("", pathlib.PathWithAfero(afero.NewOsFs())))
	store, err := nixstore.NewNixStore(nixDb, nixStoreRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)

	_, _, err = store.GetNarInfo("/nix/store/00000000000000000000000000000000-bash-5.2p37")
	_, isErr := errors.AsType[*nixstore.ErrNotFound](err)
	c.Assert(isErr, Equals, true, Commentf("expected not found error for invalid path, got %v", err))
}
