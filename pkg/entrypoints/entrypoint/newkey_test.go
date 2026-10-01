package entrypoint_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	. "gopkg.in/check.v1"
)

type NewKeySuite struct{}

var _ = Suite(&NewKeySuite{})

func (s *NewKeySuite) TestNewKeyUsesOutputDir(c *C) {
	outputDir := filepath.Join(c.MkDir(), "keys")
	ret := entrypoint.Entrypoint([]string{"new-key", "--output-dir", outputDir},
		io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Assert(ret, Equals, 0)

	entries, err := os.ReadDir(outputDir)
	c.Assert(err, IsNil)
	c.Check(len(entries), Equals, 2)
	for _, entry := range entries {
		info, err := entry.Info()
		c.Assert(err, IsNil)
		if filepath.Ext(entry.Name()) == ".key" {
			c.Check(info.Mode().Perm(), Equals, os.FileMode(0600))
		}
	}
}
