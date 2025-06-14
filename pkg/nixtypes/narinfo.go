package nixtypes

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"path"
	"strconv"
	"strings"
)

type ErrSignature struct {
}

func (e ErrSignature) Error() string {
	return "signature error"
}

// NarInfo implements the basic NarInfo struct. It is not thread-safe to multiple
// accesses.
type NarInfo struct {
	StorePath   string
	URL         string
	Compression string
	FileHash    TypedNixHash
	FileSize    uint64
	NarHash     TypedNixHash
	NarSize     uint64
	References  []string
	Deriver     string
	Sig         []NixSignature

	// Extra is any extra fields we find
	Extra map[string]string
	// order stores the order the fields were read in
	order []string
}

// Fingerprint returns the fingerpint which is signed/verified by a signature
func (n *NarInfo) Fingerprint() []byte {
	storeRoot := path.Dir(n.StorePath)
	references := []string{}
	for _, ref := range n.References {
		references = append(references, path.Join(storeRoot, ref))
	}
	return []byte(fmt.Sprintf("1;%s;%s;%d;%s", n.StorePath, n.NarHash.String(), n.NarSize, strings.Join(references, ",")))
}

// Verify verifies the NARInfo signature against the given key and returns the
// matching signatures.
func (n *NarInfo) Verify(key NamedPublicKey) (bool, []NixSignature) {
	fingerprint := n.Fingerprint()
	matches := []NixSignature{}
	for _, signature := range n.Sig {
		if ed25519.Verify(key.Key, fingerprint, signature.Signature) {
			matches = append(matches, signature)
		}
	}
	return len(matches) > 0, matches
}

// MakeSignature generates but does not apply a signature for the given NarInfo
// file.
func (n *NarInfo) MakeSignature(key NamedPrivateKey) (NixSignature, error) {
	fingerprint := n.Fingerprint()
	signature, err := key.Key.Sign(nil, fingerprint, &ed25519.Options{})
	if err != nil {
		return NixSignature{}, errors.Join(&ErrSignature{}, err)
	}
	return NixSignature{
		KeyName:   key.KeyName,
		Signature: signature,
	}, nil
}

// Sign generates and applies a new signature to the NarInfo. It will check for
// identical signatures by keyname and signature.
func (n *NarInfo) Sign(key NamedPrivateKey) (bool, NixSignature, error) {
	signature, err := n.MakeSignature(key)
	if err != nil {
		return false, signature, err
	}
	for _, existingSignature := range n.Sig {
		if existingSignature.KeyName == signature.KeyName {
			if bytes.Equal(existingSignature.Signature, signature.Signature) {
				// Signature is identical, don't need to apply this one.
				return false, signature, nil
			}
		}
	}
	// No existing signature, apply a new one.
	n.Sig = append(n.Sig, signature)
	return true, signature, nil
}

// SignReplaceByName generates and applies a new signature to NarInfo. It will check
// for signatures with the same name as the signing key, and replace them if they differ.
func (n *NarInfo) SignReplaceByName(key NamedPrivateKey) (bool, NixSignature, error) {
	signature, err := n.MakeSignature(key)
	if err != nil {
		return false, signature, err
	}
	for _, existingSignature := range n.Sig {
		if existingSignature.KeyName == signature.KeyName {
			if bytes.Equal(existingSignature.Signature, signature.Signature) {
				// Signature is identical, don't need to apply this one.
				return false, signature, nil
			} else {
				// Bytes not equal, delete this signature and replace it.
				n.RemoveSigsByNames(key.KeyName)
				break
			}
		}
	}
	// No existing signature, apply a new one.
	n.Sig = append(n.Sig, signature)
	return true, signature, nil
}

// RemoveSigsByNames removes any signatures with a matching key name
func (n *NarInfo) RemoveSigsByNames(keyNames ...string) {
	newSigs := lo.Filter(n.Sig, func(item NixSignature, index int) bool {
		if lo.Contains(keyNames, item.KeyName) {
			return false
		}
		return true
	})
	n.Sig = newSigs
}

// RemoveAllSigs removes all existing signatures
func (n *NarInfo) RemoveAllSigs() {
	n.Sig = []NixSignature{}
}

func (n *NarInfo) UnmarshalText(text []byte) error {
	n.References = make([]string, 0)
	n.Sig = make([]NixSignature, 0)
	n.Extra = map[string]string{}

	n.order = make([]string, 0)

	narLines := strings.Split(string(text), "\n")
	for _, line := range narLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			// Not blank, not a key line? Corrupt - don't try and unmarshal
			// unknowns.
			return &ErrInvalidDataFormat{Source: line}
		}
		field = strings.TrimSpace(field)
		value = strings.TrimSpace(value)

		// Append an ordering item to the hidden field
		n.order = append(n.order, field)

		switch field {
		case "StorePath":
			n.StorePath = value

		case "URL":
			n.URL = value

		case "Compression":
			n.Compression = value

		case "FileHash":
			if err := n.FileHash.UnmarshalText([]byte(value)); err != nil {
				return &ErrInvalidDataFormat{Source: line}
			}

		case "FileSize":
			result, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return errors.Join(&ErrInvalidDataFormat{Source: line}, err)
			}
			n.FileSize = result

		case "NarHash":
			if err := n.NarHash.UnmarshalText([]byte(value)); err != nil {
				return errors.Join(&ErrInvalidDataFormat{Source: line}, err)
			}

		case "NarSize":
			result, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return errors.Join(&ErrInvalidDataFormat{Source: line}, err)
			}
			n.NarSize = result

		case "References":
			if value != "" {
				n.References = strings.Split(value, " ")
			}

		case "Deriver":
			n.Deriver = value

		case "Sig":
			// We misread the initial spec for this, and sig should be one
			// sig per line. But that doesn't seem to square with the signing
			// key spec, and since it's handy to use it this way let's just
			// handle it and fix it up.
			if value == "" {
				continue
			}
			sigStrings := strings.Split(value, " ")
			for _, sig := range sigStrings {
				var signature NixSignature
				if err := signature.UnmarshalText([]byte(sig)); err != nil {
					return errors.Join(&ErrInvalidDataFormat{Source: sig}, err)
				}
				n.Sig = append(n.Sig, signature)
			}
		default:
			n.Extra[field] = value
		}
	}
	return nil
}

// renderKey handles rendering output keys in the finicky nix format needed for signing
// - namely that empty keys aren't allowed to have a trailing space (breaks reference
// signature parsing). TODO: is this true? Or did we break the whole sig mechanism?
func (n *NarInfo) renderKey(key string, value string) string {
	if value == "" {
		return fmt.Sprintf("%s:", key)
	}
	return fmt.Sprintf("%s: %s", key, value)
}

type NarOutputLines []string

func (n *NarOutputLines) Add(key string, values ...string) {
	//if len(values) == 0 {
	//	*n = append(*n, fmt.Sprintf("%s:", key))
	//	return
	//}
	for _, value := range values {
		*n = append(*n, fmt.Sprintf("%s: %s", key, value))
	}
}

func (n *NarOutputLines) String() string {
	return strings.Join(*n, "\n")
}

func (n *NarInfo) MarshalText() (text []byte, err error) {
	outputLines := NarOutputLines{}

	outputLines.Add("StorePath", n.StorePath)
	outputLines.Add("URL", n.URL)
	if n.Compression != "" {
		outputLines.Add("Compression", n.Compression)
	}
	outputLines.Add("FileHash", n.FileHash.String())
	outputLines.Add("FileSize", fmt.Sprintf("%d", n.FileSize))
	outputLines.Add("NarHash", n.NarHash.String())
	outputLines.Add("NarSize", fmt.Sprintf("%d", n.NarSize))
	outputLines.Add("References", strings.Join(n.References, " "))

	if n.Deriver != "" {
		outputLines.Add("Deriver", n.Deriver)
	}

	sigs := lo.Map(n.Sig, func(item NixSignature, index int) string {
		return item.String()
	})
	outputLines.Add("Sig", sigs...)

	for key, value := range n.Extra {
		outputLines.Add(key, value)
	}

	text = []byte(outputLines.String())
	text = append(text, []byte("\n")...)

	return
}
