package resigning_test

import (
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"github.com/wrouesnel/nix-sigman/pkg/resigning"
	"go.uber.org/zap"
	. "gopkg.in/check.v1"
)

type ResigningSuite struct {
	upstream nixtypes.NamedPrivateKey
	local    nixtypes.NamedPrivateKey
}

var _ = Suite(&ResigningSuite{})

func (s *ResigningSuite) SetUpSuite(c *C) {
	var err error
	s.upstream, err = nixtypes.GeneratePrivateKey("upstream-1")
	c.Assert(err, IsNil)
	s.local, err = nixtypes.GeneratePrivateKey("local-1")
	c.Assert(err, IsNil)
}

func testNarInfo() nixtypes.NarInfo {
	ninfo := nixtypes.NarInfo{}
	_ = ninfo.UnmarshalText([]byte(`StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37.nar
Compression: none
FileHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
FileSize: 1640
NarHash: sha256:1ccvd1lyd3icx3bs1asmhb5xw2yzz3c4bngdrjs3sgsb5vrjlxbz
NarSize: 1640
References:
`))
	return ninfo
}

func (s *ResigningSuite) load(c *C, cfg resigning.ResigningConfig) (resigning.ConditionalResigners, error) {
	return resigning.LoadSigningMap(zap.NewNop(), &cfg,
		[]nixtypes.NamedPrivateKey{s.upstream, s.local},
		[]nixtypes.NamedPublicKey{s.upstream.PublicKey(), s.local.PublicKey()})
}

func (s *ResigningSuite) TestEmptySpecifierRequiresAllowUnsigned(c *C) {
	_, err := s.load(c, resigning.ResigningConfig{SigningMap: map[string]string{"": "local-1"}})
	c.Assert(err, NotNil)
}

func (s *ResigningSuite) TestEmptySpecifierOnlySignsUnsigned(c *C) {
	signers, err := s.load(c, resigning.ResigningConfig{
		SigningMap:             map[string]string{"": "local-1"},
		AllowUnsignedResigning: true,
	})
	c.Assert(err, IsNil)

	unsigned := testNarInfo()
	didSign, err := signers.MaybeResign(zap.NewNop(), &unsigned)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, true)
	ok, _ := unsigned.Verify(s.local.PublicKey())
	c.Check(ok, Equals, true)

	// A package signed by anything (here a key with no mapping) must not match.
	other, err := nixtypes.GeneratePrivateKey("other-1")
	c.Assert(err, IsNil)
	signed := testNarInfo()
	_, _, err = signed.Sign(other)
	c.Assert(err, IsNil)
	didSign, err = signers.MaybeResign(zap.NewNop(), &signed)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, false)
	c.Check(len(signed.Sig), Equals, 1)
}

func (s *ResigningSuite) TestSignedBySpecifier(c *C) {
	signers, err := s.load(c, resigning.ResigningConfig{SigningMap: map[string]string{"upstream-1": "local-1"}})
	c.Assert(err, IsNil)

	unsigned := testNarInfo()
	didSign, err := signers.MaybeResign(zap.NewNop(), &unsigned)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, false)

	signed := testNarInfo()
	_, _, err = signed.Sign(s.upstream)
	c.Assert(err, IsNil)
	didSign, err = signers.MaybeResign(zap.NewNop(), &signed)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, true)
	ok, _ := signed.Verify(s.local.PublicKey())
	c.Check(ok, Equals, true)
}

func (s *ResigningSuite) TestUnconditionalOnlyReportsNewSignatures(c *C) {
	signers, err := s.load(c, resigning.ResigningConfig{
		AllowUnconditionalResigning: true,
		UnconditionalResigningKeys:  []string{"local-1"},
	})
	c.Assert(err, IsNil)

	ninfo := testNarInfo()
	didSign, err := signers.MaybeResign(zap.NewNop(), &ninfo)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, true)

	didSign, err = signers.MaybeResign(zap.NewNop(), &ninfo)
	c.Assert(err, IsNil)
	c.Check(didSign, Equals, false, Commentf("already signed by the unconditional key"))
}

func (s *ResigningSuite) TestMissingResigningKeyIsNamed(c *C) {
	_, err := s.load(c, resigning.ResigningConfig{
		AllowUnconditionalResigning: true,
		UnconditionalResigningKeys:  []string{"missing-1"},
	})
	c.Assert(err, ErrorMatches, ".*requested private key not loaded: missing-1.*")

	_, err = s.load(c, resigning.ResigningConfig{
		AllowUnsignedResigning: true,
		UnsignedResigningKeys:  []string{"missing-2"},
	})
	c.Assert(err, ErrorMatches, ".*requested private key not loaded: missing-2.*")
}
