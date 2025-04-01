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
			failed = append(failed, line)
		} else {
			keys = append(keys, r)
		}
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
			failed = append(failed, line)
		} else {
			keys = append(keys, r)
		}
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
		line, _ = strings.CutSuffix(line, " #")
		line, _ = strings.CutSuffix(line, "\t#")
		lines = append(lines, line)
	}
	if err := bio.Err(); err != io.EOF {
		return lines, err
	}
	return lines, nil
}
