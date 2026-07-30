package main

import (
	"os"

	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/entrypoint"
)

func main() {
	// The real entry point is in the entrypoint package, which allows for efficient test integration.
	// Do not add more code to this file (it should also be excluded from coverage tracking).
	exitCode := entrypoint.Entrypoint(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
