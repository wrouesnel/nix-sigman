package nixtypes

import (
	. "gopkg.in/check.v1"
	"strings"
)

type NarInfoSuite struct{}

var _ = Suite(&NarInfoSuite{})

const publicKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

const narInfo = `StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw.nar.xz
Compression: xz
FileHash: sha256:1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw
FileSize: 445184
NarHash: sha256:07pyb1bl3q4ivh86vx6vjjivfsm1hqrwdfm5d2x8kk7qzysl5j4j
NarSize: 1654408
References: 58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37 rmy663w9p7xb202rcln4jjzmvivznmz8-glibc-2.40-66
Deriver: cfp8jh04f3jfdcjskw2p64ri3w6njndm-bash-5.2p37.drv
Sig: cache.nixos.org-1:jmkQzt2cr2aaXwrftMjybjNktqNZXcb+6LR8auhzEnIGzU9t6A3HU8Y67vraZJpgJ90XPNfkYiqUvXs5yiomAQ==
`

const narInfoEmptyReferences = `StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw.nar.xz
Compression: xz
FileHash: sha256:1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw
FileSize: 445184
NarHash: sha256:07pyb1bl3q4ivh86vx6vjjivfsm1hqrwdfm5d2x8kk7qzysl5j4j
NarSize: 1654408
References: 
Deriver: cfp8jh04f3jfdcjskw2p64ri3w6njndm-bash-5.2p37.drv
Sig: cache.nixos.org-1:jmkQzt2cr2aaXwrftMjybjNktqNZXcb+6LR8auhzEnIGzU9t6A3HU8Y67vraZJpgJ90XPNfkYiqUvXs5yiomAQ==
`

const narInfoWithExtraKeys = `StorePath: /nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37
URL: nar/1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw.nar.xz
Compression: xz
FileHash: sha256:1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw
FileSize: 445184
NarHash: sha256:07pyb1bl3q4ivh86vx6vjjivfsm1hqrwdfm5d2x8kk7qzysl5j4j
NarSize: 1654408
References: 58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37 rmy663w9p7xb202rcln4jjzmvivznmz8-glibc-2.40-66
Deriver: cfp8jh04f3jfdcjskw2p64ri3w6njndm-bash-5.2p37.drv
Sig: cache.nixos.org-1:jmkQzt2cr2aaXwrftMjybjNktqNZXcb+6LR8auhzEnIGzU9t6A3HU8Y67vraZJpgJ90XPNfkYiqUvXs5yiomAQ==
CA: text:somevalue:whocares
a reall bad feild: with a value
`

func (s *NarInfoSuite) TestNarInfo(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfo)
}

func (s *NarInfoSuite) TestNarInfoEmptyReferences(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	c.Assert(len(ninfo.References), Equals, 0)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoEmptyReferences)
}

func (s *NarInfoSuite) TestNarInfoExtraKeys(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoWithExtraKeys))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoWithExtraKeys)
}

func (s *NarInfoSuite) TestNarInfoVerify(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	key := NamedPublicKey{}
	err = key.UnmarshalText([]byte(publicKey))
	c.Assert(err, IsNil)

	verified, matchedSigs := ninfo.Verify(key)
	c.Assert(verified, Equals, true)
	c.Assert(len(matchedSigs), Equals, 1)
	c.Assert(matchedSigs[0].String(), Equals, "cache.nixos.org-1:jmkQzt2cr2aaXwrftMjybjNktqNZXcb+6LR8auhzEnIGzU9t6A3HU8Y67vraZJpgJ90XPNfkYiqUvXs5yiomAQ==")
}

func (s *NarInfoSuite) TestNarInfoSign(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	keyName := strings.ReplaceAll(c.TestName(), " ", "")
	signKey, err := GeneratePrivateKey(keyName)
	_, err = ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	_, err = ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	c.Assert(len(ninfo.Sig), Equals, 2)

	verified, signatures := ninfo.Verify(signKey.PublicKey())
	c.Assert(verified, Equals, true)
	c.Assert(len(signatures), Equals, 1, Commentf("sign should only have added 1 signature when multiple calls made"))
	c.Assert(signatures[0].KeyName, Equals, keyName)
}
