package debug

import (
	"archive/tar"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/fatih/color"
	"github.com/wrouesnel/nix-sigman/pkg/entrypoints/cmdutil"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Cmd groups the debugging subcommands.
type Cmd struct {
	FromBytes   FromBytesCmd   `cmd:"" help:"Output the given bytes as a specific format"`
	ToBytes     ToBytesCmd     `cmd:"" help:"Convert the given input bytes to a specific format"`
	ConvertHash ConvertHashCmd `cmd:"" help:"Convert between hex and Nix hash encodings"`
	Fingerprint FingerprintCmd `cmd:"" help:"Generate the fingerprint for a NARInfo files"`
	Sign        SignCmd        `cmd:"" help:"Generate signatures for NARInfo files"`
	GenerateKey GenerateKeyCmd `cmd:"" help:"Generate a new key to stdout"`
	PublicKey   PublicKeyCmd   `cmd:"" help:"Get public key from supplied key on stdin"`
	ExtractTar  ExtractTarCmd  `cmd:"" help:"Extract tarball containing a binary cache to the target"`
	List        ListCmd        `cmd:"" help:"List all narinfo files in target"`
}

type FromBytesCmd struct {
	Format string `arg:"" help:"Format to output as" enum:"nix32,base64,hex"`
}

type ToBytesCmd struct {
	Format string `arg:"" help:"Format of the input" enum:"nix32,base64,hex"`
}

type ConvertHashCmd struct {
	Hash string `arg:"" help:"Hash to convert (hex or nix)"`
}

type FingerprintCmd struct {
	Paths []string `arg:"" help:"NARInfo files" type:"existingfile" `
}

type SignCmd struct {
	Paths []string `arg:"" help:"NARInfo files" type:"existingfile" `
}

type GenerateKeyCmd struct {
	Name string `arg:"" help:"Name of the key"`
}

type PublicKeyCmd struct {
}

type ExtractTarCmd struct {
	Dryrun    bool   `help:"Don't actually extract anything'"`
	Prefix    string `help:"Path prefix to match and remove while extracting"`
	OutputDir string `arg:"" help:"Path to extract to" default:"."`
	InputFile string `arg:"" help:"tar file (blank or - for stdin)" optional:"" default:"-"`
}

type ListCmd struct {
	Prefix string `help:"Prefix to list files under" default:"."`
}

func (c *ToBytesCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	text, err := io.ReadAll(cmdCtx.StdIn)
	if err != nil {
		cmdCtx.Logger.Error("Error while reading input")
		return err
	}

	switch c.Format {
	case "nix32":
		field := nixtypes.NixBase32Field{}
		if err := field.UnmarshalText(text); err != nil {
			cmdCtx.Logger.Error("Error decoding input", zap.Error(err))
			return err
		}
		cmdCtx.StdOut.Write(field)
	case "base64":
		output := []byte{}
		if buf, err := base64.StdEncoding.AppendDecode(output, text); err != nil {
			cmdCtx.Logger.Error("Error decoding input", zap.Error(err))
			return err
		} else {
			cmdCtx.StdOut.Write(buf)
		}
	case "hex":
		output := []byte{}
		if buf, err := hex.AppendDecode(output, text); err != nil {
			cmdCtx.Logger.Error("Error decoding input", zap.Error(err))
			return err
		} else {
			cmdCtx.StdOut.Write(buf)
		}
	}
	return nil
}

func (c *FromBytesCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	b, err := io.ReadAll(cmdCtx.StdIn)
	if err != nil {
		cmdCtx.Logger.Error("Error while reading input")
		return err
	}

	switch c.Format {
	case "nix32":
		cmdCtx.StdOut.Write([]byte(nixtypes.NixBase32Field(b).String()))
	case "base64":
		cmdCtx.StdOut.Write([]byte(base64.StdEncoding.EncodeToString(b)))
	case "hex":
		cmdCtx.StdOut.Write([]byte(hex.EncodeToString(b)))
	}
	cmdCtx.StdOut.Write([]byte("\n"))
	return nil
}

func (c *ConvertHashCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	hashStr := c.Hash
	prefix, hash, found := strings.Cut(hashStr, ":")
	if !found {
		prefix = ""
		hash = hashStr
	}

	// Try and decode hex
	if decoded, err := hex.DecodeString(hash); err != nil {
		// Probably a nix hash and we're doing the opposite.
		decoded := nixtypes.NixBase32Field{}
		if err = decoded.UnmarshalText([]byte(hash)); err != nil {
			cmdCtx.Logger.Error("Input was not usable as hex-bytes nor as a Nix Hash")
			return err
		}
		if prefix != "" {
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.StdOut.Write([]byte(hex.EncodeToString(decoded)))
		cmdCtx.StdOut.Write([]byte("\n"))
	} else {
		// Reformat as a nix hash
		nixenc := nixtypes.NixBase32Field(decoded)

		if prefix != "" {
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.StdOut.Write([]byte(nixenc.String()))
		cmdCtx.StdOut.Write([]byte("\n"))
	}
	return nil
}

func (c *GenerateKeyCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	privateKey, err := nixtypes.GeneratePrivateKey(c.Name)
	if err != nil {
		cmdCtx.Logger.Error("Failed generating private key", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}
	cmdCtx.StdOut.Write([]byte(privateKey.String()))
	cmdCtx.StdOut.Write([]byte("\n"))
	return nil
}

func (c *PublicKeyCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	privateKeys, err := nixtypes.ParsePrivateKeys(cmdCtx.StdIn)
	if err != nil {
		cmdCtx.Logger.Error("Failed reading private keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}
	for _, key := range privateKeys {
		publicKey := key.PublicKey()
		cmdCtx.StdOut.Write([]byte(publicKey.String()))
		cmdCtx.StdOut.Write([]byte("\n"))
	}

	return nil
}

func (c *FingerprintCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	err := cmdutil.ReadNinfoFromPaths(cmdCtx, c.Paths, func(path *pathlib.Path, ninfo *nixtypes.NarInfo) error {
		cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path.String()), ninfo.Fingerprint())))
		return nil
	})
	return err
}

func (c *SignCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	privateKeys, err := cmdCtx.Keys.LoadPrivateKeys(cmdCtx.Logger)
	if err != nil {
		cmdCtx.Logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}

	err = cmdutil.ReadNinfoFromPaths(cmdCtx, c.Paths, func(path *pathlib.Path, ninfo *nixtypes.NarInfo) error {
		for _, key := range privateKeys {
			value, err := ninfo.MakeSignature(key)
			if err != nil {
				cmdCtx.Logger.Warn("Could not generate signature for file", zap.String("path", path.String()))
			}
			cmdCtx.StdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path.String()), value.String())))
		}
		return nil
	})
	return err
}

// Run implements a basic helper function to extract a tarball and filter
// paths.
func (c *ExtractTarCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	l := cmdCtx.Logger
	outputDir := pathlib.NewPath(cmdCtx.NormalizeOutputDir(c.OutputDir), pathlib.PathWithAfero(cmdCtx.Fs)).Clean()
	l.Debug("Ensuring output directory exists", zap.String("output_dir", outputDir.String()))
	if outputDir.Name() != "/" {
		if err := outputDir.MkdirAllMode(os.FileMode(0755)); err != nil {
			return errors.Join(&cmdutil.ErrCommand{}, errors.New("could not make output directory"), err)
		}
	}

	reader := cmdCtx.StdIn
	if c.InputFile != "-" && c.InputFile != "" {
		inputFile, err := os.Open(c.InputFile)
		if err != nil {
			return errors.Join(&cmdutil.ErrCommand{}, err)
		}
		defer inputFile.Close()
		reader = inputFile
	}

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			l.Error("Error while reading tar file", zap.Error(err))
			return errors.Join(&cmdutil.ErrCommand{}, err)
		}

		cleanedPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanedPath, c.Prefix) {
			destPathStr := strings.TrimPrefix(cleanedPath, c.Prefix)
			fields := []zap.Field{zap.String("archive_path", cleanedPath), zap.String("dest_path", destPathStr)}
			// Never allow an archive entry to write outside of the output directory.
			if relPath := strings.TrimLeft(destPathStr, string(filepath.Separator)); relPath != "" && !filepath.IsLocal(relPath) {
				l.Warn("Skipping archive entry which would extract outside the output directory", fields...)
				continue
			}
			if c.Dryrun {
				fields = append(fields, zap.Bool("dryrun", c.Dryrun))
			}
			l.Debug("Extracting", fields...)
			if c.Dryrun {
				continue
			}
			destPath := outputDir.Join(destPathStr).Clean()
			if destPath.Parent().Name() == "/" && destPath.Name() == "/" {
				// This is the root, we never need to create it.
				continue
			}

			if header.FileInfo().IsDir() {
				// Just make directories
				if err := destPath.MkdirAllMode(os.FileMode(0755)); err != nil {
					l.Error("Could not create destination path", zap.Error(err))
					return errors.Join(&cmdutil.ErrCommand{}, err)
				}
			} else {
				exists, err := destPath.Exists()
				if err != nil {
					l.Error("Could not check path existence", zap.Error(err))
					return errors.Join(&cmdutil.ErrCommand{}, err)
				}
				if exists {
					destSize, err := destPath.Size()
					if err != nil {
						l.Error("Could not check path size", zap.Error(err))
						return errors.Join(&cmdutil.ErrCommand{}, err)
					}
					if destSize == header.Size {
						l.Debug("Skipped (exists and size matches)", fields...)
						continue
					}
					l.Debug("Size does not match - replacing")
					err = destPath.Remove()
					if err != nil {
						l.Error("Could not remove incomplete file", zap.Error(err))
						return errors.Join(&cmdutil.ErrCommand{}, err)
					}
				}

				err = func() error {
					dh, err := destPath.Create()
					if err != nil {
						l.Error("Could not create destination path", zap.Error(err))
						return err
					}
					defer dh.Close()

					size, err := io.Copy(dh, tarReader)
					if err != nil {
						l.Error("Error while reading tar file")
						return err
					}
					fields = append(fields, zap.Int64("nbytes", size))
					l.Debug("Extracted", fields...)
					return nil
				}()
				if err != nil {
					return errors.Join(&cmdutil.ErrCommand{}, err)
				}
			}
		}
	}

	return nil
}

// Run will list all the objects from the given path.
func (c *ListCmd) Run(cmdCtx *cmdutil.CmdContext) error {
	l := cmdCtx.Logger
	outputDir := pathlib.NewPath(cmdCtx.NormalizeOutputDir(c.Prefix), pathlib.PathWithAfero(cmdCtx.Fs)).Clean()
	l.Info("Reading directory (this may take a while)")
	dirNames, err := outputDir.ReadDir()
	if err != nil {
		return errors.Join(&cmdutil.ErrCommand{}, err)
	}
	for _, name := range dirNames {
		if strings.HasSuffix(name.Name(), ".narinfo") {
			fmt.Fprintf(cmdCtx.StdOut, "%s\n", name.Name())
		}
	}
	return nil
}
