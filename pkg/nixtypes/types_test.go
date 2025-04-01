package nixtypes

import (
	. "gopkg.in/check.v1"
	"testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type TypeSuite struct{}

var _ = Suite(&TypeSuite{})

func (ts *TypeSuite) TestNixBase32Field(c *C) {
	const expected = "1lqbabq2bx50zxc5nk8qx15n40yabpr1xbvqywaa4dfjzk23qx5q"

	newData := new(NixBase32Field)
	err := newData.UnmarshalText([]byte(expected))
	c.Assert(err, IsNil)
	obtained, err := newData.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(obtained, DeepEquals, []byte(expected))
}

func (ts *TypeSuite) TestBase64Field(c *C) {
	const expected = "ZGF0YQ=="

	newData := new(Base64Field)
	err := newData.UnmarshalText([]byte(expected))
	c.Assert(err, IsNil)
	obtained, err := newData.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(obtained, DeepEquals, []byte(expected))

	c.Assert(new(Base64Field).String(), Equals, "")
}

func (ts *TypeSuite) TestNixSignature(c *C) {
	const TestSignature = "cache.nixos.org-1:GoGTthRLGbD6Z38o8SzJhihVUJhE+LlOZ1PiMB2/uf9A51SMWf3imqz8zbNuOAFdg4d+io/mSrdaX2dZGjGHAA=="
	var nixSig NixSignature
	err := nixSig.UnmarshalText([]byte(TestSignature))
	c.Assert(err, IsNil)
	c.Assert(nixSig.KeyName, Equals, "cache.nixos.org-1")
	result, err := nixSig.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(result), Equals, TestSignature)

	c.Assert(new(NixSignature).String(), Equals, "")
}

func (ts *TypeSuite) TestTypedNixHash(c *C) {
	const TestHash = "sha256:1lqbabq2bx50zxc5nk8qx15n40yabpr1xbvqywaa4dfjzk23qx5q"
	var nixSig TypedNixHash
	err := nixSig.UnmarshalText([]byte(TestHash))
	c.Assert(err, IsNil)
	c.Assert(nixSig.HashName, Equals, "sha256")
	result, err := nixSig.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(result), Equals, TestHash)

	c.Assert(new(TypedNixHash).String(), Equals, "")
}

func (ts *TypeSuite) TestNamedPublicKey(c *C) {
	const publicKey = "test-key-1:fLPd//RXMYq4eTB5Nf4RUB15BpGH9HxWc7KN1pTS2YU="
	var nixSig NamedPublicKey
	err := nixSig.UnmarshalText([]byte(publicKey))
	c.Assert(err, IsNil)
	c.Assert(nixSig.KeyName, Equals, "test-key-1")
	result, err := nixSig.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(result), Equals, publicKey)

	c.Assert(new(NamedPublicKey).String(), Equals, "")
}

func (ts *TypeSuite) TestNamedPrivateKey(c *C) {
	const privateKey = "test-key-1:9MRqEihjK1tX8zLFYD5inAWMrxzAA7hZWCK6sK3qepV8s93/9Fcxirh5MHk1/hFQHXkGkYf0fFZzso3WlNLZhQ=="
	var nixSig NamedPrivateKey
	err := nixSig.UnmarshalText([]byte(privateKey))
	c.Assert(err, IsNil)
	c.Assert(nixSig.KeyName, Equals, "test-key-1")
	result, err := nixSig.MarshalText()
	c.Assert(err, IsNil)
	c.Assert(string(result), Equals, privateKey)

	c.Assert(new(NamedPrivateKey).String(), Equals, "")
}
