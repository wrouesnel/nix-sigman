package nixtypes

import (
	"bytes"

	"github.com/samber/lo"
	. "gopkg.in/check.v1"
)

type KeyUtilsSuite struct{}

var _ = Suite(&KeyUtilsSuite{})

func (k *KeyUtilsSuite) TestGeneratePrivateKey(c *C) {
	pkey, err := GeneratePrivateKey("somename")
	c.Assert(err, IsNil)

	c.Assert(pkey.KeyName, Equals, "somename")
}

// Round trip the private key generator
func (k *KeyUtilsSuite) TestParsing(c *C) {
	pkeys := []NamedPrivateKey{}
	b := bytes.NewBuffer(nil)
	publicBytes := bytes.NewBuffer(nil)
	for i := 0; i < 10; i++ {
		pkey, err := GeneratePrivateKey("TestKey")
		c.Assert(err, IsNil)
		pkeys = append(pkeys, pkey)
		pkeyBytes, err := pkey.MarshalText()
		c.Assert(err, IsNil)
		b.Write(pkeyBytes)
		b.Write([]byte("\n"))

		pubkey := pkey.PublicKey()
		pubkeyBytes, err := pubkey.MarshalText()
		c.Assert(err, IsNil)
		publicBytes.Write(pubkeyBytes)
		publicBytes.Write([]byte("\n"))
	}

	rpkeys, err := ParsePrivateKeys(bytes.NewReader(b.Bytes()))
	c.Assert(err, IsNil)

	c.Assert(rpkeys, DeepEquals, pkeys)

	rpubkeys, err := ParsePublicKeys(bytes.NewReader(publicBytes.Bytes()))
	c.Assert(err, IsNil)

	c.Assert(rpubkeys, DeepEquals, lo.Map(pkeys, func(item NamedPrivateKey, index int) NamedPublicKey {
		return item.PublicKey()
	}))
}
