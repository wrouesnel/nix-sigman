package entrypoint

//nolint:gochecknoglobals
type SignConfig struct {
	SigningKeys []string `help:"Names of keys to sign with (default all)" default:"*"`
}

//nolint:gochecknoglobals
type VerifyConfig struct {
	IncludePrivateKeys bool     `help:"Private Keys should also be used for trust" default:"false"`
	TrustedKeys        []string `help:"Names of keys to sign with (default all)" default:"*"`
}
