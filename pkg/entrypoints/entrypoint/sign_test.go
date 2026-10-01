package entrypoint_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	. "gopkg.in/check.v1"
)

type SignSuite struct{}

var _ = Suite(&SignSuite{})

func (s *SignSuite) TestSignUsesSigningMap(c *C) {
	upstream, err := nixtypes.GeneratePrivateKey("upstream-1")
	c.Assert(err, IsNil)
	local, err := nixtypes.GeneratePrivateKey("local-1")
	c.Assert(err, IsNil)

	ninfo := nixtypes.NarInfo{}
	c.Assert(ninfo.UnmarshalText([]byte(misorderedNarInfo)), IsNil)
	_, _, err = ninfo.Sign(upstream)
	c.Assert(err, IsNil)
	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	path := filepath.Join(c.MkDir(), "58br4vk3q5akf4g8lx0pqzfhn47k3j8d.narinfo")
	c.Assert(os.WriteFile(path, content, os.FileMode(0644)), IsNil)

	upstreamPub, localPub := upstream.PublicKey(), local.PublicKey()
	ret := entrypoint.Entrypoint([]string{
		"--private-keys", upstream.String(), "--private-keys", local.String(),
		"--public-keys", upstreamPub.String(), "--public-keys", localPub.String(),
		"sign", "--signing-map", "upstream-1=local-1", path,
	}, io.NopCloser(new(bytes.Buffer)), io.Discard, io.Discard)
	c.Assert(ret, Equals, 0)

	signed := nixtypes.NarInfo{}
	content, err = os.ReadFile(path)
	c.Assert(err, IsNil)
	c.Assert(signed.UnmarshalText(content), IsNil)
	ok, _ := signed.Verify(localPub)
	c.Check(ok, Equals, true, Commentf("narinfo was not resigned by the signing map:\n%s", content))
}
