package nixsigman

import (
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type NixSuite struct{}

var _ = Suite(&NixSuite{})

func (s *NixSuite) TestNarHashMarshalling(c *C) {
	testBytes := []byte{60, 215, 161, 139, 144, 189, 79, 60, 222, 12, 31, 29, 145, 170, 159, 207, 222, 177, 204, 186, 185, 222, 113, 206, 109, 25, 171, 69, 176, 202, 141, 217}
	testHash := "sha256:1ncdraq4baqrdp773pmrpb6b3pngkym9278z1kg3qkxxj25s3mrw"

	hashSpec := &NarHashSpec{}
	err := hashSpec.UnmarshalText([]byte(testHash))
	c.Assert(err, IsNil)
	c.Assert(hashSpec.Hash, DeepEquals, testBytes)

	outputHash, err := hashSpec.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(outputHash), DeepEquals, testHash)
}

const publicKey = "cache.nixos.org-1:jmkQzt2cr2aaXwrftMjybjNktqNZXcb+6LR8auhzEnIGzU9t6A3HU8Y67vraZJpgJ90XPNfkYiqUvXs5yiomAQ=="

func (s *NixSuite) TestLoadPublicKeyFromString(c *C) {
	sigman := NewNixSignatureManager()
	err := sigman.LoadPublicKeyFromString(publicKey)
	c.Assert(err, IsNil)
}

func (s *NixSuite) TestLoadPublicKeyFromFile(c *C) {
	testDir := c.MkDir()
	publicKeyFile := filepath.Join(testDir, "key.public")
	fh, err := os.OpenFile(publicKeyFile, os.O_CREATE|os.O_WRONLY, os.FileMode(0777))
	c.Assert(err, IsNil)
	_, err = fh.WriteString(publicKey + "\n")
	c.Assert(err, IsNil)
	err = fh.Close()
	c.Assert(err, IsNil)

	sigman := NewNixSignatureManager()
	err = sigman.LoadPublicKeyFromFile(publicKeyFile)
	c.Assert(err, IsNil)
}

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

func (s *NixSuite) TestNarInfo(c *C) {
	ninfo := &NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfo)
}
