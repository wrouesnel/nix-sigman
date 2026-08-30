package config

import "embed"

//go:embed *.yml
var defaults embed.FS

// Config provides configurability for advanced features of nix-sigman. It also
// provides the default loader.
type Config struct {
}
