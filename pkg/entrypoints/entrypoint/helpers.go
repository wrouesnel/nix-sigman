package entrypoint

import (
	"fmt"
	gap "github.com/muesli/go-app-paths"
	"github.com/samber/lo"
	"github.com/wrouesnel/nix-sigman/version"
	"os"
	"path"
)

func configFileName(prefix string, ext string) string {
	return fmt.Sprintf("%s%s.%s", prefix, version.Name, ext)
}

func configDirListGet() ([]string, []string) {
	deferredLogs := []string{}

	// Handle a sensible configuration loader path
	scope := gap.NewScope(gap.User, version.Name)
	baseConfigDirs, err := scope.ConfigDirs()
	if err != nil {
		deferredLogs = append(deferredLogs, err.Error())
	}

	supportedFmts := []string{"json", "yml", "yaml", "toml"}

	normConfigFiles := []string{}
	for _, configDir := range baseConfigDirs {
		normConfigFiles = append(normConfigFiles, lo.Map(supportedFmts, func(ext string, _ int) string {
			return path.Join(configDir, configFileName("", ext))
		})...)
	}

	var curDirConfigFiles []string = lo.Map(supportedFmts, func(ext string, _ int) string {
		return configFileName(".", ext)
	})

	var homeDirConfigFiles []string = lo.Map(curDirConfigFiles, func(configFileName string, _ int) string {
		return path.Join(os.Getenv("HOME"), configFileName)
	})

	configFiles := curDirConfigFiles
	configFiles = append(configFiles, homeDirConfigFiles...)
	configFiles = append(configFiles, normConfigFiles...)

	return configFiles, deferredLogs
}
