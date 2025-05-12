package entrypoint

import (
	"bytes"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/fatih/color"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"strings"
)

//nolint:gochecknoglobals
type ValidateConfig struct {
	BackupNARInfos bool     `help:"Make backups of NARinfo files" default:"true"`
	Fix            bool     `help:"Rewrite NARinfo files if they're not an exact match" default:"false"`
	NarInfoFiles   []string `arg:"" help:"NARInfo files to sign - specify - to read list from stdin"`
}

// Validate checks the format of the NARinfo file against the serialization.
func Validate(cmdCtx *CmdContext) error {
	err := readPaths(cmdCtx, CLI.Validate.NarInfoFiles, func(path *pathlib.Path) error {
		l := cmdCtx.logger

		var err error

		fileBytes, err := path.ReadFile()
		if err != nil {
			l.Warn("Could not read file", zap.Error(err))
			return err
		}

		ninfo := nixtypes.NarInfo{}
		err = ninfo.UnmarshalText(fileBytes)
		if err != nil {
			cmdCtx.stdOut.Write([]byte(
				fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
					color.RedString("FAILREAD"), strings.ReplaceAll(err.Error(), "\n", "\\\\n"))))
			return nil
		}

		// Remarshal the file
		remarshalled, err := ninfo.MarshalText()
		if err != nil {
			cmdCtx.stdOut.Write([]byte(
				fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
					color.RedString("FAILMRSL"), strings.ReplaceAll(err.Error(), "\n", "\\\\n"))))
			return nil
		}

		// Compare
		if bytes.Equal(fileBytes, remarshalled) == false {
			if CLI.Validate.Fix {
				if CLI.Sign.BackupNARInfos {
					if err = backNinfo(l, path); err != nil {
						l.Warn("Failed to backup narinfo file - rewrite aborted", zap.Error(err))
						return nil
					}
				}

				// Ignore errors - write logs its own errors
				_ = writeNInfo(l, path, ninfo)

				cmdCtx.stdOut.Write([]byte(
					fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
						color.YellowString("FIXEDFRM"), "Updated On-Disk Format")))
			} else {
				cmdCtx.stdOut.Write([]byte(
					fmt.Sprintf("%s:%s:%s\n", color.CyanString("%s", path),
						color.RedString("FAILFORM"), "On-Disk Does Not Match Reserialization")))
			}
			return nil
		}

		cmdCtx.stdOut.Write([]byte(
			fmt.Sprintf("%s:%s:\n",
				color.CyanString("%s", path), color.GreenString("GOODFORM"))))
		return nil
	})
	return err
}
