package nixtypes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"zombiezen.com/go/nix/nixbase32"
)

type ErrInvalidDataFormat struct {
	Source string
}

func (e ErrInvalidDataFormat) Error() string {
	return fmt.Sprintf("invalid data format: %s", e.Source)
}

// NixBase32Field implements a field which is encoded as a
type NixBase32Field []byte

func (b NixBase32Field) String() string {
	return nixbase32.EncodeToString(b)
}

func (b *NixBase32Field) UnmarshalText(text []byte) error {
	decoded, err := nixbase32.DecodeString(string(text))
	*b = decoded
	return err
}

func (b *NixBase32Field) MarshalText() (text []byte, err error) {
	return []byte(b.String()), nil
}

// Base64 field implements a field which is encoded and decoded from bytes to
// standard base64.
type Base64Field []byte

func (b *Base64Field) String() string {
	return base64.StdEncoding.EncodeToString(*b)
}

func (b *Base64Field) UnmarshalText(text []byte) error {
	decoded, err := base64.StdEncoding.DecodeString(string(text))
	*b = decoded
	return err
}

func (b *Base64Field) MarshalText() (text []byte, err error) {
	return []byte(b.String()), nil
}

// NixSignature represents the typical structure of a NIXInfo signature
type NixSignature struct {
	KeyName   string
	Signature Base64Field
}

func (n *NixSignature) String() string {
	if len(n.Signature) == 0 {
		return ""
	} else {
		return fmt.Sprintf("%s:%s", n.KeyName, n.Signature.String())
	}
}

func (n *NixSignature) MarshalText() (text []byte, err error) {
	return []byte(n.String()), nil
}

func (n *NixSignature) UnmarshalText(text []byte) error {
	keyName, signature, ok := bytes.Cut(text, []byte(":"))
	if !ok {
		return &ErrInvalidDataFormat{string(text)}
	}
	n.KeyName = string(keyName)
	if err := n.Signature.UnmarshalText(signature); err != nil {
		return errors.Join(&ErrInvalidDataFormat{string(text)}, err)
	}
	return nil
}

type TypedNixHash struct {
	HashName string
	Hash     NixBase32Field
}

func (n *TypedNixHash) UnmarshalText(text []byte) error {
	hashName, encodedHash, ok := bytes.Cut(text, []byte(":"))
	if !ok {
		return &ErrInvalidDataFormat{string(text)}
	}
	n.HashName = string(hashName)
	if err := n.Hash.UnmarshalText(encodedHash); err != nil {
		// Nix also appears to support hex-encoded hashes in the same fields we might
		// see a TypedNixHash. So before failing, try a hex-decode.
		var herr error
		n.Hash, herr = hex.DecodeString(string(encodedHash))
		if herr == nil {
			// Was hex - leave it as hex.
			return nil
		}
		// Otherwise just return the original error
		return errors.Join(&ErrInvalidDataFormat{string(text)}, err)
	}
	return nil
}

func (n *TypedNixHash) MarshalText() (text []byte, err error) {
	return []byte(n.String()), nil
}

func (n *TypedNixHash) String() string {
	if len(n.HashName) == 0 {
		return ""
	} else {
		return fmt.Sprintf("%s:%s", n.HashName, nixbase32.EncodeToString(n.Hash))
	}
}

// NamedPublicKey is the <name>:<base64> encoded key format
type NamedPublicKey struct {
	KeyName string
	Key     ed25519.PublicKey
}

func (n *NamedPublicKey) UnmarshalText(text []byte) error {
	keyName, encodedKey, ok := bytes.Cut(text, []byte(":"))
	if !ok {
		return &ErrInvalidDataFormat{string(text)}
	}
	n.KeyName = string(keyName)

	publicKeyBytes, err := base64.StdEncoding.DecodeString(string(encodedKey))
	if err != nil {
		return errors.Join(&ErrInvalidDataFormat{string(text)}, err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return errors.Join(&ErrInvalidDataFormat{string(text)}, errors.New("public key must be 32 bytes"))
	}

	n.Key = publicKeyBytes

	return nil
}

func (n *NamedPublicKey) MarshalText() (text []byte, err error) {
	return []byte(n.String()), nil
}

func (n *NamedPublicKey) String() string {
	if len(n.KeyName) == 0 && len([]byte(n.Key)) == 0 {
		return ""
	} else {
		return fmt.Sprintf("%s:%s", n.KeyName, base64.StdEncoding.EncodeToString(n.Key))
	}
}

// NamedPrivateKey is the <name>:<base64> encoded key format
type NamedPrivateKey struct {
	KeyName string
	Key     ed25519.PrivateKey
}

// PublicKey returns the public key form of the private key
func (n *NamedPrivateKey) PublicKey() NamedPublicKey {
	return NamedPublicKey{
		KeyName: n.KeyName,
		Key:     n.Key.Public().(ed25519.PublicKey),
	}
}

func (n *NamedPrivateKey) UnmarshalText(text []byte) error {
	keyName, encodedKey, ok := bytes.Cut(text, []byte(":"))
	if !ok {
		return &ErrInvalidDataFormat{string(text)}
	}
	n.KeyName = string(keyName)

	privateKeyBytes, err := base64.StdEncoding.DecodeString(string(encodedKey))
	if err != nil {
		return errors.Join(&ErrInvalidDataFormat{string(text)}, err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return errors.Join(&ErrInvalidDataFormat{string(text)}, errors.New("private key must be 64 bytes"))
	}

	n.Key = privateKeyBytes

	return nil
}

func (n *NamedPrivateKey) MarshalText() (text []byte, err error) {
	return []byte(n.String()), nil
}

func (n *NamedPrivateKey) String() string {
	if len(n.KeyName) == 0 && len([]byte(n.Key)) == 0 {
		return ""
	} else {
		return fmt.Sprintf("%s:%s", n.KeyName, base64.StdEncoding.EncodeToString(n.Key))
	}
}
