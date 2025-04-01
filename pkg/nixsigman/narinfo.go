package nixsigman

import (
	"encoding/base64"
	"fmt"
	"github.com/samber/lo"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"zombiezen.com/go/nix/nixbase32"
)

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

// AddSignatureFromString adds a signature from the given string
func (n *NarInfo) AddSignatureFromString(sigString string) error {
	if err := n.unmarshalSignature(sigString); err != nil {
		return err
	}
	return nil
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
				if err := n.unmarshalSignature(sig); err != nil {
					return err
				}
			}

		default:
			n.order = append(n.order, field)
			n.extra[field] = parts[1]
		}
	}
	return nil
}

func (n *NarInfo) unmarshalSignature(sig string) error {
	sigparts := strings.SplitN(sig, ":", 2)
	sigbytes, err := base64.StdEncoding.DecodeString(sigparts[1])
	if err != nil {
		return err
	}
	n.Sig[sigparts[0]] = sigbytes
	n.sigOrder = append(n.sigOrder, sigparts[0])
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
	if n.References != nil {
		if len(n.References) != 0 {
			lines = append(lines, fmt.Sprintf("References: %s", strings.Join(n.References, " ")))
		}
	}
	if n.Deriver != "" {
		lines = append(lines, fmt.Sprintf("Deriver: %s", n.Deriver))
	}

	// Handle signatures
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

	// Add any keys we don't recognize
	for _, unknownField := range n.order {
		if fieldValue, found := n.extra[unknownField]; found {
			lines = append(lines, fmt.Sprintf("%s: %s", unknownField, fieldValue))
		}
	}

	// Ensure file will be newline terminated
	lines = append(lines, "")

	text = []byte(strings.Join(lines, "\n"))
	err = nil
	return
}

func NewNarInfoFromFile(path string) (*NarInfo, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := new(NarInfo)
	if err := result.UnmarshalText(bytes); err != nil {
		return nil, err
	}
	return result, nil
}
