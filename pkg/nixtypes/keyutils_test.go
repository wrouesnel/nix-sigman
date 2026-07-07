package nixtypes

import (
	"bytes"
	"fmt"

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
	const numKeys = 10
	pkeys := make([]NamedPrivateKey, 0, numKeys)
	b := bytes.NewBuffer(nil)
	publicBytes := bytes.NewBuffer(nil)
	for range numKeys {
		pkey, err := GeneratePrivateKey("TestKey")
		c.Assert(err, IsNil)
		pkeys = append(pkeys, pkey)
		pkeyBytes, err := pkey.MarshalText()
		c.Assert(err, IsNil)
		b.Write(fmt.Append(pkeyBytes, '\n'))

		pubkey := pkey.PublicKey()
		pubkeyBytes, err := pubkey.MarshalText()
		c.Assert(err, IsNil)
		publicBytes.Write(fmt.Append(pubkeyBytes, '\n'))
	}

	rpkeys, err := ParsePrivateKeys(bytes.NewReader(b.Bytes()))
	c.Assert(err, IsNil)

	c.Assert(rpkeys, DeepEquals, pkeys)

	rpubkeys, err := ParsePublicKeys(bytes.NewReader(publicBytes.Bytes()))
	c.Assert(err, IsNil)

	c.Assert(
		rpubkeys,
		DeepEquals,
		lo.Map(pkeys, func(item NamedPrivateKey, index int) NamedPublicKey {
			return item.PublicKey()
		}),
	)
}
