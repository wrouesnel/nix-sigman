package nixkeys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// GeneratePrivateKey makes a new private key in Nix string format
func GeneratePrivateKey(name string) (string, error) {
	_, privKey, err := ed25519.GenerateKey(nil)
	return fmt.Sprintf("%s:%s", name, base64.StdEncoding.EncodeToString(privKey)), err
}

func PublicKeyFromPrivateKey(privKey string) (string, error) {
	parts := strings.SplitN(privKey, ":", 2)
	privateBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	publicKey := ed25519.PrivateKey(privateBytes).Public().(ed25519.PublicKey)
	publicPart := base64.StdEncoding.EncodeToString(publicKey)
	return fmt.Sprintf("%s:%s", parts[0], publicPart), nil
}
