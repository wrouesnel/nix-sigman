package nixstore_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
	"github.com/wrouesnel/nix-sigman/pkg/nixstore"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&NixStoreSuite{})

const wellKnownPath = "/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37"

//const wellKnownPath = "/nix/store/8ranqggwk67p5mii3vimljcb9jr0nliq-nixexprs.tar.xz"

type NixStoreSuite struct{}

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
	pathlib.NewPath("/nix", pathlib.PathWithAfero(afero.NewOsFs()))

	nixDb, nixStoreRoot := nixstore.DefaultNixStore(pathlib.NewPath("", pathlib.PathWithAfero(afero.NewOsFs())))
	store, err := nixstore.NewNixStore(nixDb, nixStoreRoot, nixstore.DefaultStorePath)
	c.Assert(err, IsNil)

	ninfo, _, err := store.GetNarInfo(wellKnownPath)
	c.Assert(err, IsNil)
	ninfoText, err := ninfo.MarshalText()
	c.Assert(err, IsNil)

	// Compare to the NarInfo
	storeDir := pathlib.NewPath(createBinaryFromNix(c, wellKnownPath), pathlib.PathWithAfero(afero.NewOsFs()))
	canonicalNarInfo, err := storeDir.Join(fmt.Sprintf("%v.narinfo", ninfo.NixHash())).ReadFile()
	c.Assert(err, IsNil)
	c.Assert(string(ninfoText), Equals, string(canonicalNarInfo))

	// Serve the NAR file from the store
	rdr, _, _, err := store.GetNar(wellKnownPath)
	c.Assert(err, IsNil)

	// Hash it...
	h := sha256.New()

	fmode, err := storeDir.Join("comparison.nar").OpenFileMode(os.O_CREATE|os.O_WRONLY, os.FileMode(0644))
	c.Assert(err, IsNil)

	teer := io.TeeReader(rdr, fmode)
	size, err := io.Copy(h, teer)
	c.Assert(err, IsNil)
	c.Assert(uint64(size), Equals, ninfo.FileSize)

	fmode.Close()

	// Now hash the actual on-disk file and check its the same
	canonicalNarRdr, err := storeDir.Join(ninfo.URL).Open()
	c.Assert(err, IsNil)
	canonicalHash := sha256.New()
	canonicalSize, err := io.Copy(canonicalHash, canonicalNarRdr)
	c.Assert(err, IsNil)
	c.Assert(uint64(canonicalSize), Equals, ninfo.FileSize)

	c.Assert(hex.EncodeToString(h.Sum(nil)), Equals, hex.EncodeToString(canonicalHash.Sum(nil)))

	// Copy the nix path to a different root and check we can extract it properly
	//altRoot := pathlib.NewPath(c.MkDir(), pathlib.PathWithAfero(afero.NewOsFs()))
	//canonicalNarRdr, err = storeDir.Join(ninfo.URL).Open()
	//c.Assert(err, IsNil)
	//narRdr := nar.NewReader(canonicalNarRdr)
	//for {
	//	header, err := narRdr.Next()
	//	if err != nil {
	//		if err == io.EOF {
	//			break
	//		}
	//		c.Fatalf("%v", err)
	//	}
	//	outputPath := altRoot.Join(header.Path)
	//	if header.FileInfo().IsDir() {
	//		// Make the directory
	//		err = outputPath.Mkdir()
	//		c.Assert(err, IsNil)
	//	} else {
	//		// Otherwise write the file
	//		f, err := outputPath.OpenFileMode(os.O_CREATE|os.O_WRONLY, header.Mode)
	//		c.Assert(err, IsNil)
	//		_, err = io.Copy(f, narRdr)
	//		c.Assert(err, IsNil)
	//	}
	//}
}
