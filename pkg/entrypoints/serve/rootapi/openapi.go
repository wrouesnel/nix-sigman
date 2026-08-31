//go:generate go tool oapi-codegen -config cfg.yaml openapi.yaml
package rootapi

import "embed"

//go:embed openapi.yaml
var ApiFS embed.FS
