package nixtypes

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"io"
	"strings"
)

type ErrParsing struct {
	Failed []interface{}
}

func (e ErrParsing) Error() string {
	return fmt.Sprintf("errors during parsing: %d failed items", len(e.Failed))
}

// GeneratePrivateKey generate a new random public key
func GeneratePrivateKey(name string) (NamedPrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return NamedPrivateKey{}, err
	}
	return NamedPrivateKey{
		KeyName: name,
		Key:     privateKey,
	}, nil
}

func ParsePrivateKeys(reader io.Reader) ([]NamedPrivateKey, error) {
	keys := []NamedPrivateKey{}
	failed := []interface{}{}
	lines, err := commentedLineParser(reader)
	if err != nil {
		return keys, err
	}
	for _, line := range lines {
		r := NamedPrivateKey{}
		if err := r.UnmarshalText([]byte(line)); err != nil {
			// Record the error rather than the line, which may be secret key material.
			failed = append(failed, err)
		} else {
			keys = append(keys, r)
		}
	}
	if len(failed) > 0 {
		return keys, &ErrParsing{Failed: failed}
	}
	return keys, nil
}

func ParsePublicKeys(reader io.Reader) ([]NamedPublicKey, error) {
	keys := []NamedPublicKey{}
	failed := []interface{}{}
	lines, err := commentedLineParser(reader)
	if err != nil {
		return keys, err
	}
	for _, line := range lines {
		r := NamedPublicKey{}
		if err := r.UnmarshalText([]byte(line)); err != nil {
			// Record the error rather than the line, which may be secret key material.
			failed = append(failed, err)
		} else {
			keys = append(keys, r)
		}
	}
	if len(failed) > 0 {
		return keys, &ErrParsing{Failed: failed}
	}
	return keys, nil
}

// commentedLineParser parses through key-file like documents and returns bare lines
func commentedLineParser(reader io.Reader) ([]string, error) {
	bio := bufio.NewScanner(reader)
	lines := []string{}
	for bio.Scan() {
		line := bio.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comments, which must be separated from the key by whitespace.
		if idx := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' }); idx != -1 {
			if comment := strings.TrimSpace(line[idx:]); comment == "" || strings.HasPrefix(comment, "#") {
				line = line[:idx]
			}
		}
		lines = append(lines, line)
	}
	if err := bio.Err(); err != nil {
		return lines, err
	}
	return lines, nil
}
