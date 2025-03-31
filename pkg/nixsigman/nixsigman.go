package nixsigman

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
)
import "zombiezen.com/go/nix/nixbase32"

type NarHashSpec struct {
	HashName string
	Hash     []byte
}

func (n *NarHashSpec) UnmarshalText(text []byte) error {
	parts := strings.SplitN(string(text), ":", 2)
	decoded, err := nixbase32.DecodeString(parts[1])
	if err != nil {
		return err
	}
	n.Hash = decoded
	n.HashName = parts[0]
	return nil
}

func (n *NarHashSpec) MarshalText() (text []byte, err error) {
	text = []byte(fmt.Sprintf("%s:%s", n.HashName, nixbase32.EncodeToString(n.Hash)))
	return text, nil
}

func (n *NarHashSpec) String() string {
	text, _ := n.MarshalText()
	return string(text)
}

type NarInfo struct {
	StorePath   string
	URL         string
	Compression string
	FileHash    *NarHashSpec
	FileSize    uint64
	NarHash     *NarHashSpec
	NarSize     uint64
	References  []string
	Deriver     string
	Sig         map[string][]byte
	sigOrder    []string
	// extra is any extra fields we find
	extra map[string]string
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

func (n *NarInfo) UnmarshalText(text []byte) error {
	n.extra = map[string]string{}
	n.order = make([]string, 0)
	n.References = make([]string, 0)
	n.Sig = make(map[string][]byte)
	n.sigOrder = make([]string, 0)

	narLines := strings.Split(string(text), "\n")
	for _, line := range narLines {
		line = strings.TrimSpace(line)
		if line == "" {
			// Skip empty lines
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return fmt.Errorf("corrupt line: %s", line)
		}
		field := strings.TrimSpace(parts[0])
		switch field {
		case "StorePath":
			n.StorePath = parts[1]

		case "URL":
			n.URL = parts[1]

		case "Compression":
			n.Compression = parts[1]

		case "FileHash":
			hashspec := &NarHashSpec{}
			if err := hashspec.UnmarshalText([]byte(parts[1])); err != nil {
				return err
			}
			n.FileHash = hashspec

		case "FileSize":
			result, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return err
			}
			n.FileSize = result

		case "NarHash":
			hashspec := &NarHashSpec{}
			if err := hashspec.UnmarshalText([]byte(parts[1])); err != nil {
				return err
			}
			n.NarHash = hashspec

		case "NarSize":
			result, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return err
			}
			n.NarSize = result

		case "References":
			n.References = strings.Split(parts[1], " ")

		case "Deriver":
			n.Deriver = parts[1]

		case "Sig":
			signatures := strings.Split(parts[1], " ")
			for _, sig := range signatures {
				sigparts := strings.SplitN(sig, ":", 2)
				sigbytes, err := base64.StdEncoding.DecodeString(sigparts[1])
				if err != nil {
					return err
				}
				n.Sig[sigparts[0]] = sigbytes
				n.sigOrder = append(n.sigOrder, sigparts[0])
			}

		default:
			n.order = append(n.order, field)
			n.extra[field] = parts[1]
		}
	}
	return nil
}

func (n *NarInfo) MarshalText() (text []byte, err error) {
	lines := []string{}

	lines = append(lines, fmt.Sprintf("StorePath: %s", n.StorePath))
	lines = append(lines, fmt.Sprintf("URL: %s", n.URL))
	lines = append(lines, fmt.Sprintf("Compression: %s", n.Compression))
	lines = append(lines, fmt.Sprintf("FileHash: %s", n.FileHash.String()))
	lines = append(lines, fmt.Sprintf("FileSize: %d", n.FileSize))
	lines = append(lines, fmt.Sprintf("NarHash: %s", n.NarHash.String()))
	lines = append(lines, fmt.Sprintf("NarSize: %d", n.NarSize))
	lines = append(lines, fmt.Sprintf("References: %s", strings.Join(n.References, " ")))
	lines = append(lines, fmt.Sprintf("Deriver: %s", n.Deriver))

	unorderedSigs := lo.OmitByKeys(n.Sig, n.sigOrder)
	trailingSigs := []string{}
	for name, sig := range unorderedSigs {
		trailingSigs = append(trailingSigs, fmt.Sprintf("%s:%s", name, base64.StdEncoding.EncodeToString(sig)))
	}
	sort.Strings(trailingSigs)

	sigs := []string{}
	for _, name := range n.sigOrder {
		if sig, ok := n.Sig[name]; ok {
			sigs = append(sigs, fmt.Sprintf("%s:%s", name, base64.StdEncoding.EncodeToString(sig)))
		}

	}
	sigs = append(sigs, trailingSigs...)

	lines = append(lines, fmt.Sprintf("Sig: %s", strings.Join(sigs, " ")))
	lines = append(lines, "")

	text = []byte(strings.Join(lines, "\n"))
	err = nil
	return
}

type NixSigMan struct {
	m *sync.Mutex
	// publickeys is the map of loaded public keys
	publicKeys map[string][]string
	// privateKeys is the map of loaded private keys
	privateKeys map[string][]string
}

// NewNixSignatureManager initializes a new signature manager
func NewNixSignatureManager() *NixSigMan {
	return &NixSigMan{
		m:           &sync.Mutex{},
		publicKeys:  make(map[string][]string),
		privateKeys: make(map[string][]string),
	}
}

// Verify NarInfo signatures. Returns the list of keys which matched, along with their names.
func (n *NixSigMan) Verify(ninfo *NarInfo) (verified bool) {
	n.m.Lock()
	defer n.m.Unlock()

	// TODO: track valid keys, misidentified keys, and failing keys
	validKeys := make(map[string][]string)
	// No info, no matches
	if ninfo == nil {
		return
	}

	for publicKey, names := range n.publicKeys {
		// this is protected on load so it always succeeds
		loadedKey := ed25519.PublicKey(lo.Must(base64.StdEncoding.DecodeString(publicKey)))

		for _, signature := range ninfo.Sig {
			// TODO: check for signature name matching i.e. host != cert
			if ed25519.Verify(loadedKey, ninfo.Fingerprint(), signature) {
				// Verified
				if _, ok := validKeys[publicKey]; !ok {
					validKeys[publicKey] = make([]string, 0)
				}
				validKeys[publicKey] = append(validKeys[publicKey], names...)
			}
		}
	}

	return len(validKeys) > 0
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

func (n *NixSigMan) LoadPrivateKeyFromString(key string) error {
	n.m.Lock()
	defer n.m.Unlock()
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return errors.New("invalid private key string")
	}

	if privKey, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("could not decode private key string")
	} else if len(privKey) != 64 {
		return fmt.Errorf("bad private key length (want 64 bytes got %d bytes)", len(privKey))
	}

	if _, ok := n.privateKeys[parts[1]]; !ok {
		n.privateKeys[parts[1]] = make([]string, 0)
	}

	n.privateKeys[parts[1]] = append(n.privateKeys[parts[1]], parts[0])

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
