package entrypoint

import (
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/ncruces/go-strftime"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"os"
	"os/user"
	"time"
)

//nolint:gochecknoglobals
type NewKeyConfig struct {
	OutputDir       string `help:"output directory for the generated keys" default:"."`
	PrivateKeyExt   string `help:"private key file extension" default:"key"`
	PublicKeyExt    string `help:"public key file extension" default:"pub"`
	NoPublicKeyFile bool   `help:"do not emit a file for the public key"`
}

// NewKey implements a simple way to generate well formed signing keys
func NewKey(cmdCtx *CmdContext) error {
	l := cmdCtx.logger

	currentUser, err := user.Current()
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	timestamp := strftime.Format("%Y-%m-%d-%H-%M-%S", time.Now())

	keyName := fmt.Sprintf("%s-%s", currentUser.Username, timestamp)

	privateKey, err := nixtypes.GeneratePrivateKey(keyName)
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	outputDir := pathlib.NewPath(NormalizeOutputDir(CLI.Debug.ExtractTar.OutputDir), pathlib.PathWithAfero(cmdCtx.fs)).Clean()
	l.Debug("Ensuring output directory exists", zap.String("output_dir", outputDir.String()))
	if outputDir.Name() != "/" {
		if err := outputDir.MkdirAllMode(os.FileMode(0755)); err != nil {
			return errors.Join(&ErrCommand{}, errors.New("could not make output directory"), err)
		}
	}

	privateKeyFile := outputDir.Join(fmt.Sprintf("%s.%s", keyName, CLI.NewKey.PrivateKeyExt))
	publicKeyFile := outputDir.Join(fmt.Sprintf("%s.%s", keyName, CLI.NewKey.PublicKeyExt))

	err = privateKeyFile.WriteFile([]byte(fmt.Sprintf("%s\n", privateKey.String())))
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	publicKey := privateKey.PublicKey()

	if !CLI.NewKey.NoPublicKeyFile {
		err = publicKeyFile.WriteFile([]byte(fmt.Sprintf("%s\n", publicKey.String())))
		if err != nil {
			return errors.Join(&ErrCommand{}, err)
		}
	}

	fmt.Fprintf(cmdCtx.stdOut, "%s\n", publicKey.String())
	return nil
}
