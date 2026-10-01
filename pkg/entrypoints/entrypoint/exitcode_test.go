package entrypoint_test

import (
	"bytes"
	"io"
	"path/filepath"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	. "gopkg.in/check.v1"
)

type ExitCodeSuite struct{}

var _ = Suite(&ExitCodeSuite{})

func (s *ExitCodeSuite) TestCommandErrorIsNonZeroExit(c *C) {
	ret := entrypoint.Entrypoint([]string{"bundle", "--nix-db", filepath.Join(c.MkDir(), "missing.sqlite"), "some-path"},
		io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Check(ret, Not(Equals), 0)
}
