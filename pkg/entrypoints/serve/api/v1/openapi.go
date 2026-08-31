package v1

import (
	"embed"
	_ "embed"
)

//go:embed openapi.yaml types.yaml
var ApiFS embed.FS
