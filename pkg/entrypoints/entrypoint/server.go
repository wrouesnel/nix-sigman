package entrypoint

//nolint:gochecknoglobals
type ServerConfig struct {
	RequiredPublicKeys []string `help:"Names of public keys which must be present to allow resigning"`
	SigningKeys        []string `help:"Names of keys to sign with (default all)" default:"*"`
	Root               string   `arg:"" help:"Root path of the binary cache"`
}

// Server implements the dynamic resigning server
func Server(cmdCtx *CmdContext) error {
	return nil
}
