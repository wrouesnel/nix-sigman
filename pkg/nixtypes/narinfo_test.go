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

// Important: nix parsing requires the References field to be "References:" with no trailing space, otherwise
// parser
const narInfoEmptyReferences = `StorePath: /nix/store/2kgif7n5hi16qhkrnjnv5swnq9aq3qhj-gcc-14-20241116-libgcc
URL: nar/1xabljs3h2qfbdfl1z0hbm1nvlcl27qlvdb8ib0j39f51rvka2dr.nar.xz
Compression: xz
FileHash: sha256:1xabljs3h2qfbdfl1z0hbm1nvlcl27qlvdb8ib0j39f51rvka2dr
FileSize: 74020
NarHash: sha256:0wdfccp187mcmnbvk464zypkwdjnyfiwkf7d6q0wfinlk5z67j4i
NarSize: 201856
References: 
Deriver: ci1f3qvj2i3bgr2wibfxl52cfw0wfks6-gcc-14-20241116.drv
Sig: cache.nixos.org-1:BUOAstUWfupkmoOCjZyXYdtvMX3GzNLSXcTDZEsvUzmlhsSEU+Bxed+dCXfOHBb3Gn7znamBF7aeOwuOMi0YCg==
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

const narInfoMultiSig = `StorePath: /nix/store/s0kylmi4nxahi0jgs7a1cd19q6s00smw-clang-src-17.0.6
URL: nar/1wbdzanpck57g3r2hwxjczicd20ws2d01hzgr59qiw0g4qmiflji.nar.xz
Compression: xz
FileHash: sha256:1wbdzanpck57g3r2hwxjczicd20ws2d01hzgr59qiw0g4qmiflji
FileSize: 24265320
NarHash: sha256:11vbjvwfris38n50wpbb5laanxkkkb5iybck4a28cv5i13v2wjw9
NarSize: 416259664
References: 
Deriver: j6cn8bxikh82jwzwva0nmnq31xl1i20k-clang-src-17.0.6.drv
Sig: cache.nixos.org-1:GnSFytFjswxd8f+VjvVXusiaaT2LN3KCaS3wlJDBOrueGOHKpxhn8KwTWGsPVRaT5mp4cPOg9Cww4mCyjzAfAg==
Sig: test-key-1:p4ZE4Vz3pQ6P3KkVuJM2xQdMlW7sI3g0NND+Z/u/r6IjSMz5vyMWj+qg68uBjJKjc75Fz5tLJicpF/Vc6ocNDA==
`

func (s *NarInfoSuite) TestNarInfo(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfo)
}

func (s *NarInfoSuite) TestNarInfoWithMultipleSignatures(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoMultiSig))
	c.Assert(err, IsNil)

	c.Assert(len(ninfo.Sig), Equals, 2)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoMultiSig)
}

func (s *NarInfoSuite) TestNarInfoEmptyReferences(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	c.Assert(len(ninfo.References), Equals, 0)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoEmptyReferences)
	// This used to check the references field didn't have a trailing space,
	// but it turn out cache.nixos.org serves these that way so that's correct.
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Split(line, ":")
		if parts[0] == "References" {
			c.Assert(parts[1], Equals, " ")
		}
	}
}

func (s *NarInfoSuite) TestNarInfoEmptyReferencesVerify(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	key := NamedPublicKey{}
	err = key.UnmarshalText([]byte(publicKey))
	c.Assert(err, IsNil)

	verified, matchedSigs := ninfo.Verify(key)
	c.Assert(verified, Equals, true)
	c.Assert(len(matchedSigs), Equals, 1)
	c.Assert(matchedSigs[0].String(), Equals, "cache.nixos.org-1:BUOAstUWfupkmoOCjZyXYdtvMX3GzNLSXcTDZEsvUzmlhsSEU+Bxed+dCXfOHBb3Gn7znamBF7aeOwuOMi0YCg==")
}

func (s *NarInfoSuite) TestNarInfoEmptyReferencesSign(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	keyName := strings.ReplaceAll(c.TestName(), " ", "")
	signKey, err := GeneratePrivateKey(keyName)
	didSign, _, err := ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	c.Assert(didSign, Equals, true)
	didSign, _, err = ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	c.Assert(len(ninfo.Sig), Equals, 2)
	c.Assert(didSign, Equals, false)

	verified, signatures := ninfo.Verify(signKey.PublicKey())
	c.Assert(verified, Equals, true)
	c.Assert(len(signatures), Equals, 1, Commentf("sign should only have added 1 signature when multiple calls made"))
	c.Assert(signatures[0].KeyName, Equals, keyName)
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
	didSign, _, err := ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	c.Assert(didSign, Equals, true)
	didSign, _, err = ninfo.Sign(signKey)
	c.Assert(err, IsNil)
	c.Assert(len(ninfo.Sig), Equals, 2)
	c.Assert(didSign, Equals, false)

	verified, signatures := ninfo.Verify(signKey.PublicKey())
	c.Assert(verified, Equals, true)
	c.Assert(len(signatures), Equals, 1, Commentf("sign should only have added 1 signature when multiple calls made"))
	c.Assert(signatures[0].KeyName, Equals, keyName)
}
