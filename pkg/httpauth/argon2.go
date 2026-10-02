package httpauth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Default argon2id parameters for new hashes (RFC 9106 second recommended option).
const (
	DefaultArgon2Time    = 3
	DefaultArgon2Memory  = 64 * 1024
	DefaultArgon2Threads = 4
	argon2SaltLen        = 16
	argon2KeyLen         = 32
	// Limits on parameters read from password files, so a bad entry can't exhaust the server.
	maxArgon2Memory = 1024 * 1024
	maxArgon2Time   = 64
)

// Argon2Hash is a parsed argon2 hash in the PHC string format:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
type Argon2Hash struct {
	Variant string
	Memory  uint32
	Time    uint32
	Threads uint8
	Salt    []byte
	Key     []byte
}

// ParseArgon2Hash parses a PHC formatted argon2i or argon2id hash.
func ParseArgon2Hash(encoded string) (*Argon2Hash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return nil, errors.New("not a PHC formatted argon2 hash")
	}
	h := &Argon2Hash{Variant: parts[1]}
	if h.Variant != "argon2id" && h.Variant != "argon2i" {
		return nil, fmt.Errorf("unsupported argon2 variant %q", h.Variant)
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || parts[2] != fmt.Sprintf("v=%d", version) {
		return nil, errors.New("invalid argon2 version")
	}
	if version != argon2.Version {
		return nil, fmt.Errorf("unsupported argon2 version %d", version)
	}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.Memory, &h.Time, &h.Threads)
	if err != nil || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", h.Memory, h.Time, h.Threads) {
		return nil, errors.New("invalid argon2 parameters")
	}
	if h.Time == 0 || h.Threads == 0 || h.Time > maxArgon2Time || h.Memory > maxArgon2Memory {
		return nil, errors.New("argon2 parameters out of range")
	}
	if h.Salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, fmt.Errorf("invalid argon2 salt: %w", err)
	}
	if h.Key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, fmt.Errorf("invalid argon2 hash: %w", err)
	}
	if len(h.Key) == 0 {
		return nil, errors.New("empty argon2 hash")
	}
	return h, nil
}

func (h *Argon2Hash) derive(password string) []byte {
	if h.Variant == "argon2i" {
		return argon2.Key([]byte(password), h.Salt, h.Time, h.Memory, h.Threads, uint32(len(h.Key)))
	}
	return argon2.IDKey([]byte(password), h.Salt, h.Time, h.Memory, h.Threads, uint32(len(h.Key)))
}

// Verify checks the password against the hash in constant time.
func (h *Argon2Hash) Verify(password string) bool {
	return subtle.ConstantTimeCompare(h.derive(password), h.Key) == 1
}

func (h *Argon2Hash) String() string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", h.Variant, argon2.Version, h.Memory, h.Time, h.Threads,
		base64.RawStdEncoding.EncodeToString(h.Salt), base64.RawStdEncoding.EncodeToString(h.Key))
}

// HashPassword generates a new argon2id hash for the password with the default parameters.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := &Argon2Hash{
		Variant: "argon2id",
		Memory:  DefaultArgon2Memory,
		Time:    DefaultArgon2Time,
		Threads: DefaultArgon2Threads,
		Salt:    salt,
	}
	h.Key = argon2.IDKey([]byte(password), h.Salt, h.Time, h.Memory, h.Threads, argon2KeyLen)
	return h.String(), nil
}

// PasswordFileAuthenticator authenticates users against username:argon2-hash files.
type PasswordFileAuthenticator struct {
	users map[string]*Argon2Hash
	// dummy is verified for unknown users so response times don't reveal valid usernames.
	dummy *Argon2Hash
}

// LoadPasswordFiles reads files of "username:$argon2id$..." lines. Blank lines and lines
// starting with # are ignored. Later files override earlier ones.
func LoadPasswordFiles(paths ...string) (*PasswordFileAuthenticator, error) {
	a := &PasswordFileAuthenticator{users: map[string]*Argon2Hash{}}
	for _, path := range paths {
		if err := a.loadFile(path); err != nil {
			return nil, err
		}
	}
	dummy, err := HashPassword("")
	if err != nil {
		return nil, err
	}
	a.dummy, _ = ParseArgon2Hash(dummy)
	return a, nil
}

func (a *PasswordFileAuthenticator) loadFile(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		username, encoded, found := strings.Cut(line, ":")
		if !found || username == "" {
			return fmt.Errorf("%s:%d: expected username:hash", path, lineNo)
		}
		h, err := ParseArgon2Hash(encoded)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		a.users[username] = h
	}
	return sc.Err()
}

func (a *PasswordFileAuthenticator) Name() string {
	return "password-file"
}

// Users returns the number of users loaded.
func (a *PasswordFileAuthenticator) Users() int {
	return len(a.users)
}

func (a *PasswordFileAuthenticator) Authenticate(_ context.Context, username, password string) (Result, error) {
	h, found := a.users[username]
	if !found {
		a.dummy.Verify(password)
		return Denied, nil
	}
	if !h.Verify(password) {
		return Denied, nil
	}
	return Allowed, nil
}
