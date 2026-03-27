package entrypoint

import (
	_ "modernc.org/sqlite"
)

type ServeConfig struct {
	Listen []string `help:"Listen addresses" default:"tcp://127.0.0.1:8081"`
	Root   string   `arg:"" help:"Path to the /nix mountpoint" default:/nix`
}

// Serve implements a Nix HTTP cache server by reading an extant `/nix` directory
// in flatfile format. It is possible, though not advised, to share this with a system
// nix-daemon.
func Serve(cmdCtx *CmdContext) error {
	l := cmdCtx.logger
}
