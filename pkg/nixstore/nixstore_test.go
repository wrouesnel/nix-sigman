package nixstore_test

import (
	"fmt"
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

const wellKnownPath = "/nix/store/8ranqggwk67p5mii3vimljcb9jr0nliq-nixexprs.tar.xz"

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
func (n *NixStoreSuite) TestNarInfoRetrievalWorks(c *C) {
	store, err := nixstore.NewNixStore(pathlib.NewPath("/nix", pathlib.PathWithAfero(afero.NewOsFs())))
	c.Assert(err, IsNil)

	ninfo, err := store.GetNarInfo(wellKnownPath)
	c.Assert(err, IsNil)
	ninfoText, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Logf(string(ninfoText))

	// Compare to the NarInfo
	storeDir := pathlib.NewPath(createBinaryFromNix(c, wellKnownPath), pathlib.PathWithAfero(afero.NewOsFs()))
	canonicalNarInfo, err := storeDir.Join(fmt.Sprintf("%v.narinfo", ninfo.NixHash())).ReadFile()
	c.Assert(err, IsNil)
	c.Assert(string(ninfoText), Equals, string(canonicalNarInfo))
}
