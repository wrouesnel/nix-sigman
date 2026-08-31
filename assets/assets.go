package assets

import (
	"embed"
	"io/fs"
	"os"
)

const filesystemAssetPath = "assets"

//go:embed swagger-ui
var assets embed.FS

// Assets returns an fs.FS object pointing to the asset provider.
func Assets() fs.FS {
	if useFileSystem {
		return os.DirFS(filesystemAssetPath)
	}

	return assets
}

var useFileSystem bool = false //nolint:gochecknoglobals

// UseFilesystem configures whether to use local filesytem files or embedded ones.
func UseFilesystem(val bool) {
	useFileSystem = val
}

type Config struct {
	UseFilesystem  bool `default:"false" help:"Use assets from the filesystem rather then the embedded binary"`
	DebugTemplates bool `default:"false" help:"Enable template debugging (disables caching)"`
}
