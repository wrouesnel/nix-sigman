package nixsigman

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"os"
	"strings"
	"sync"
)

type KeyIdentity struct {
	Name      string
	PublicKey string
}

func (k *KeyIdentity) String() string {
	return fmt.Sprintf("%s:%s", k.Name, k.PublicKey)
}

type NixSigMan struct {
	m *sync.Mutex
	// publickeys is the map of loaded public keys
	publicKeys map[string][]string
	// privateKeys is the map of loaded private keys
	privateKeys map[string][]string
	// privateKeysByPublic is a map of the private keys by their public part
	privateKeysByPublic map[string]string
}

// NewNixSignatureManager initializes a new signature manager
func NewNixSignatureManager() *NixSigMan {
	return &NixSigMan{
		m:                   &sync.Mutex{},
		publicKeys:          make(map[string][]string),
		privateKeys:         make(map[string][]string),
		privateKeysByPublic: make(map[string]string),
	}
}

// Verify NarInfo signatures. Returns the list of keys which matched, along with their names.
func (n *NixSigMan) Verify(ninfo *NarInfo) (verified bool, validKeys []KeyIdentity, invalidKeys []KeyIdentity) {
	n.m.Lock()
	defer n.m.Unlock()

	// TODO: track valid keys, misidentified keys, and failing keys
	validKeys = []KeyIdentity{}
	invalidKeys = []KeyIdentity{}
	// No info, no matches
	if ninfo == nil {
		return
	}

	for publicKey, names := range n.publicKeys {
		// this is protected on load so it always succeeds
		loadedKey := ed25519.PublicKey(lo.Must(base64.StdEncoding.DecodeString(publicKey)))

		keyValidated := false
		for _, signature := range ninfo.Sig {
			// TODO: check for signature name matching i.e. host != cert
			if ed25519.Verify(loadedKey, ninfo.Fingerprint(), signature) {
				keyValidated = true
				for _, name := range names {
					validKeys = append(validKeys, KeyIdentity{
						Name:      name,
						PublicKey: publicKey,
					})
				}
				break
			}
		}
		if !keyValidated {
			for _, name := range names {
				invalidKeys = append(invalidKeys, KeyIdentity{
					Name:      name,
					PublicKey: publicKey,
				})
			}
		}
	}

	return len(validKeys) > 0, validKeys, invalidKeys
}

func (n *NixSigMan) ListPrivateKeys() []KeyIdentity {
	n.m.Lock()
	defer n.m.Unlock()

	allNames := []KeyIdentity{}

	for privateKey, names := range n.privateKeys {
		loadedKey := ed25519.PrivateKey(lo.Must(base64.StdEncoding.DecodeString(privateKey)))
		publicBytes := loadedKey.Public().(ed25519.PublicKey)
		for _, name := range names {
			allNames = append(allNames, KeyIdentity{
				Name:      name,
				PublicKey: base64.StdEncoding.EncodeToString(publicBytes),
			})
		}

	}

	return allNames
}

func (n *NixSigMan) ListPublicKeys() []KeyIdentity {
	n.m.Lock()
	defer n.m.Unlock()

	allNames := []KeyIdentity{}

	for publicKey, names := range n.publicKeys {
		for _, name := range names {
			allNames = append(allNames, KeyIdentity{
				Name:      name,
				PublicKey: publicKey,
			})
		}

	}

	return allNames
}

func (n *NixSigMan) PrivateKeysCount() int {
	n.m.Lock()
	defer n.m.Unlock()
	return len(n.privateKeys)
}

func (n *NixSigMan) PublicKeysCount() int {
	n.m.Lock()
	defer n.m.Unlock()
	return len(n.publicKeys)
}

// Sign NarInfo files. Does not verify the NARInfo actually matches the file it
// refers to. Key names may be the string name or a public key matching a known
// private key.
func (n *NixSigMan) Sign(ninfo *NarInfo, keyNames []string) []string {
	n.m.Lock()
	defer n.m.Unlock()

	signingKeys := []ed25519.PrivateKey{}

	for _, name := range keyNames {
		// Check for matching public key first
		if privKey, found := n.privateKeysByPublic[name]; found {
			signingKeys = append(signingKeys, lo.Must(base64.StdEncoding.DecodeString(privKey)))
			continue
		}
		// Then search by name
		for privKey, names := range n.privateKeys {
			for _, knownName := range names {
				if name == knownName {
					signingKeys = append(signingKeys, lo.Must(base64.StdEncoding.DecodeString(privKey)))
				}
			}
		}
	}

	// Found the signing keys. Calculate the signatures.
	signatures := []string{}
	for idx, key := range signingKeys {
		signature := base64.StdEncoding.EncodeToString(lo.Must(key.Sign(nil, ninfo.Fingerprint(), &ed25519.Options{})))
		// Find the key and add the name
		if names, found := n.privateKeys[base64.StdEncoding.EncodeToString(key)]; found {
			for _, name := range names {
				signatures = append(signatures, fmt.Sprintf("%s:%s", name, signature))
			}
		} else {
			signatures = append(signatures, fmt.Sprintf("unknown-%d:%s", idx, signature))
		}
	}
	return signatures
}

func (n *NixSigMan) LoadPublicKeyFromString(key string) error {
	n.m.Lock()
	defer n.m.Unlock()
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid public key string")
	}

	if pubkey, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("could not decode public key string")
	} else if len(pubkey) != 32 {
		return fmt.Errorf("bad private key length (want 64 bytes got %d bytes)", len(pubkey))
	}

	if _, ok := n.publicKeys[parts[1]]; !ok {
		n.publicKeys[parts[1]] = make([]string, 0)
	}

	n.publicKeys[parts[1]] = append(n.publicKeys[parts[1]], parts[0])

	return nil
}

func (n *NixSigMan) LoadPublicKeyFromPrivateKey(key string) error {
	n.m.Lock()
	defer n.m.Unlock()
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid private key string")
	}

	if privKey, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("could not decode private key string")
	} else {
		if err != nil {
			return errors.New("invalid private key string")
		}
		publicKey := base64.StdEncoding.EncodeToString(ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey))
		if _, found := n.publicKeys[publicKey]; !found {
			n.publicKeys[publicKey] = make([]string, 0)
		}
		n.publicKeys[publicKey] = append(n.publicKeys[publicKey], parts[0])
	}
	return nil
}

func (n *NixSigMan) LoadPrivateKeyFromString(key string) error {
	n.m.Lock()
	defer n.m.Unlock()
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid private key string")
	}

	var publicKey string
	if privKey, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("could not decode private key string")
	} else if len(privKey) != 64 {
		return fmt.Errorf("bad private key length (want 64 bytes got %d bytes)", len(privKey))
	} else {
		publicKey = base64.StdEncoding.EncodeToString(ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey))
	}

	if _, ok := n.privateKeys[parts[1]]; !ok {
		n.privateKeys[parts[1]] = make([]string, 0)
	}

	n.privateKeys[parts[1]] = append(n.privateKeys[parts[1]], parts[0])
	n.privateKeysByPublic[publicKey] = parts[1]

	return nil
}

// TODO: support line comments

func (n *NixSigMan) LoadPublicKeyFromFile(path string) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, os.FileMode(0777))
	if err != nil {
		return nil
	}
	bio := bufio.NewScanner(fh)
	for bio.Scan() {
		line := bio.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		err = n.LoadPublicKeyFromString(line)
		if err != nil {
			return err
		}
	}
	if err := bio.Err(); err != nil {
		return err
	}
	return nil
}

func (n *NixSigMan) LoadPrivateKeyFromFile(path string) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, os.FileMode(0777))
	if err != nil {
		return nil
	}
	bio := bufio.NewScanner(fh)
	for bio.Scan() {
		line := bio.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		err = n.LoadPrivateKeyFromString(line)
		if err != nil {
			return err
		}
	}
	if err := bio.Err(); err != nil {
		return err
	}
	return nil
}
