package entrypoint_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	. "gopkg.in/check.v1"
)

type DerivationsSuite struct{}

var _ = Suite(&DerivationsSuite{})

const testDrv = `Derive([("out","/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-hello","","")],[],[],"x86_64-linux","/bin/sh",["-c","echo hello > $out"],[("builder","/bin/sh"),("name","hello"),("out","/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-hello"),("system","x86_64-linux")])`

func (s *DerivationsSuite) TestShowOutputExtension(c *C) {
	baseDir := c.MkDir()
	drvPath := filepath.Join(baseDir, "8ranqggwk67p5mii3vimljcb9jr0nliq-hello.drv")
	c.Assert(os.WriteFile(drvPath, []byte(testDrv), os.FileMode(0644)), IsNil)
	outputRoot := filepath.Join(baseDir, "out")

	ret := entrypoint.Entrypoint([]string{"derivations", "show", "--format", "json-compact", "--output-root", outputRoot, drvPath},
		io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Assert(ret, Equals, 0)

	_, err := os.Stat(filepath.Join(outputRoot, "8ranqggwk67p5mii3vimljcb9jr0nliq-hello.drv.json"))
	c.Check(err, IsNil)
}
