package entrypoint_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	. "gopkg.in/check.v1"
)

type ValidateSuite struct{}

var _ = Suite(&ValidateSuite{})

// misorderedNarInfo parses fine but does not match the canonical serialization.
const misorderedNarInfo = `URL: nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar
StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
Compression: none
FileHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
FileSize: 1640
NarHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
NarSize: 1640
References: 
`

func (s *ValidateSuite) runFix(c *C, extraArgs ...string) string {
	path := filepath.Join(c.MkDir(), "58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo")
	c.Assert(os.WriteFile(path, []byte(misorderedNarInfo), os.FileMode(0644)), IsNil)
	args := append([]string{"validate", "--fix"}, extraArgs...)
	ret := entrypoint.Entrypoint(append(args, path), io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Assert(ret, Equals, 0)

	content, err := os.ReadFile(path)
	c.Assert(err, IsNil)
	c.Assert(string(content), Not(Equals), misorderedNarInfo, Commentf("file was not rewritten"))
	return path
}

func (s *ValidateSuite) TestFixBacksUpByDefault(c *C) {
	path := s.runFix(c)
	backup, err := os.ReadFile(path + ".bak")
	c.Assert(err, IsNil)
	c.Check(string(backup), Equals, misorderedNarInfo)
}

func (s *ValidateSuite) TestFixWithoutBackup(c *C) {
	path := s.runFix(c, "--backup-nar-infos=false")
	_, err := os.Stat(path + ".bak")
	c.Check(os.IsNotExist(err), Equals, true)
}
