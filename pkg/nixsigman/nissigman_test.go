package nixsigman

import (
	"github.com/wrouesnel/nix-sigman/pkg/nixkeys"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
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

	hashSpec := &nixtypes.TypedNixHash{}
	err := hashSpec.UnmarshalText([]byte(testHash))
	c.Assert(err, IsNil)
	c.Assert(hashSpec.Hash, DeepEquals, testBytes)

	outputHash, err := hashSpec.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(outputHash), DeepEquals, testHash)
}

const publicKey = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

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

func (s *NixSuite) TestValidatePublicKey(c *C) {
	sigman := NewNixSignatureManager()
	err := sigman.LoadPublicKeyFromString(publicKey)
	c.Assert(err, IsNil)

	ninfo := &nixtypes.NarInfo{}
	err = ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	verified, valid, invalid := sigman.Verify(ninfo)
	c.Assert(verified, Equals, true)
	c.Assert(len(valid), Equals, 1)
	c.Assert(len(invalid), Equals, 0)
}

func (s *NixSuite) TestWithNewPrivateKey(c *C) {
	sigman := NewNixSignatureManager()
	privateKey, err := nixkeys.GeneratePrivateKey("test-key-0")
	c.Assert(err, IsNil)
	err = sigman.LoadPrivateKeyFromString(privateKey)
	c.Assert(err, IsNil)

	ninfo := &nixtypes.NarInfo{}
	err = ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	signature := sigman.Sign(ninfo, []string{"test-key-0"})
	err = ninfo.AddSignatureFromString(signature[0])
	c.Assert(err, IsNil)

	validMan := NewNixSignatureManager()
	err = validMan.LoadPublicKeyFromPrivateKey(privateKey)
	c.Assert(err, IsNil)

	verified, valid, invalid := validMan.Verify(ninfo)
	c.Assert(verified, Equals, true)
	c.Assert(len(valid), Equals, 1)
	c.Assert(len(invalid), Equals, 0)
}

func (s *NixSuite) TestNarInfo(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfo)
}

func (s *NixSuite) TestNarInfoEmptyReferences(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	c.Assert(len(ninfo.References), Equals, 0)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoEmptyReferences)
}

func (s *NixSuite) TestNarInfoFingerprintWithReferences(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	// Ensure the fingerprint is correct for empty references
	fingerprint := string(ninfo.Fingerprint())
	c.Assert(fingerprint, Equals, "1;/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37;sha256:07pyb1bl3q4ivh86vx6vjjivfsm1hqrwdfm5d2x8kk7qzysl5j4j;1654408;/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37,/nix/store/rmy663w9p7xb202rcln4jjzmvivznmz8-glibc-2.40-66")
}

func (s *NixSuite) TestNarInfoFingerprintEmptyReferences(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoEmptyReferences))
	c.Assert(err, IsNil)

	// Ensure the fingerprint is correct for empty references
	fingerprint := string(ninfo.Fingerprint())
	c.Assert(fingerprint, Equals, "1;/nix/store/58br4vk3q5akf4g8lx0pqzfhn47k3j8d-bash-5.2p37;sha256:07pyb1bl3q4ivh86vx6vjjivfsm1hqrwdfm5d2x8kk7qzysl5j4j;1654408;")
}

func (s *NixSuite) TestNarInfoWithExtraKeys(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfoWithExtraKeys))
	c.Assert(err, IsNil)

	content, err := ninfo.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(content), DeepEquals, narInfoWithExtraKeys)
}

func (s *NixSuite) TestSignatureChecking(c *C) {
	ninfo := &nixtypes.NarInfo{}
	err := ninfo.UnmarshalText([]byte(narInfo))
	c.Assert(err, IsNil)

	sigman := NewNixSignatureManager()
	err = sigman.LoadPublicKeyFromString(publicKey)
	c.Assert(err, IsNil)

	result, _, _ := sigman.Verify(ninfo)
	c.Assert(result, Equals, true)
}
