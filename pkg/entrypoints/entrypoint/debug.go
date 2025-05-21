package entrypoint

import (
	"archive/tar"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/chigopher/pathlib"
	"github.com/fatih/color"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func DebugToBytes(cmdCtx *CmdContext) error {
	text, err := io.ReadAll(cmdCtx.stdIn)
	if err != nil {
		cmdCtx.logger.Error("Error while reading input")
		return err
	}

	switch CLI.Debug.ToBytes.Format {
	case "nix32":
		field := nixtypes.NixBase32Field{}
		if err := field.UnmarshalText(text); err != nil {
			cmdCtx.logger.Error("Error decoding input", zap.Error(err))
			return err
		}
		cmdCtx.stdOut.Write(field)
	case "base64":
		output := []byte{}
		if buf, err := base64.StdEncoding.AppendDecode(output, text); err != nil {
			cmdCtx.logger.Error("Error decoding input", zap.Error(err))
			return err
		} else {
			cmdCtx.stdOut.Write(buf)
		}
	case "hex":
		output := []byte{}
		if buf, err := hex.AppendDecode(output, text); err != nil {
			cmdCtx.logger.Error("Error decoding input", zap.Error(err))
			return err
		} else {
			cmdCtx.stdOut.Write(buf)
		}
	}
	return nil
}

func DebugFromBytes(cmdCtx *CmdContext) error {
	b, err := io.ReadAll(cmdCtx.stdIn)
	if err != nil {
		cmdCtx.logger.Error("Error while reading input")
		return err
	}

	switch CLI.Debug.FromBytes.Format {
	case "nix32":
		cmdCtx.stdOut.Write([]byte(nixtypes.NixBase32Field(b).String()))
	case "base64":
		cmdCtx.stdOut.Write([]byte(base64.StdEncoding.EncodeToString(b)))
	case "hex":
		cmdCtx.stdOut.Write([]byte(hex.EncodeToString(b)))
	}
	cmdCtx.stdOut.Write([]byte("\n"))
	return nil
}

func DebugConvertHash(cmdCtx *CmdContext) error {
	hashStr := CLI.Debug.ConvertHash.Hash
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
			cmdCtx.logger.Error("Input was not usable as hex-bytes nor as a Nix Hash")
			return err
		}
		if prefix != "" {
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.stdOut.Write([]byte(hex.EncodeToString(decoded)))
		cmdCtx.stdOut.Write([]byte("\n"))
	} else {
		// Reformat as a nix hash
		nixenc := nixtypes.NixBase32Field(decoded)

		if prefix != "" {
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:", prefix)))
		}
		cmdCtx.stdOut.Write([]byte(nixenc.String()))
		cmdCtx.stdOut.Write([]byte("\n"))
	}
	return nil
}

func DebugGenerateKey(cmdCtx *CmdContext) error {
	privateKey, err := nixtypes.GeneratePrivateKey(CLI.Debug.GenerateKey.Name)
	if err != nil {
		cmdCtx.logger.Error("Failed generating private key", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}
	cmdCtx.stdOut.Write([]byte(privateKey.String()))
	cmdCtx.stdOut.Write([]byte("\n"))
	return nil
}

func DebugPublicKey(cmdCtx *CmdContext) error {
	privateKeys, err := nixtypes.ParsePrivateKeys(cmdCtx.stdIn)
	if err != nil {
		cmdCtx.logger.Error("Failed reading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}
	for _, key := range privateKeys {
		publicKey := key.PublicKey()
		cmdCtx.stdOut.Write([]byte(publicKey.String()))
		cmdCtx.stdOut.Write([]byte("\n"))
	}

	return nil
}

func DebugFingerprint(cmdCtx *CmdContext) error {
	err := readNinfoFromPaths(cmdCtx, CLI.Debug.Fingerprint.Paths, func(path *pathlib.Path, ninfo *nixtypes.NarInfo) error {
		cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path.String()), ninfo.Fingerprint())))
		return nil
	})
	return err
}

func DebugSign(cmdCtx *CmdContext) error {
	privateKeys, err := loadPrivateKeys(cmdCtx.logger)
	if err != nil {
		cmdCtx.logger.Error("Error loading private keys", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	err = readNinfoFromPaths(cmdCtx, CLI.Debug.Sign.Paths, func(path *pathlib.Path, ninfo *nixtypes.NarInfo) error {
		for _, key := range privateKeys {
			value, err := ninfo.MakeSignature(key)
			if err != nil {
				cmdCtx.logger.Warn("Could not generate signature for file", zap.String("path", path.String()))
			}
			cmdCtx.stdOut.Write([]byte(fmt.Sprintf("%s:%s\n", color.CyanString(path.String()), value.String())))
		}
		return nil
	})
	return err
}

// DebugExtractTar implements a basic helper function to extract a tarball and filter
// paths.
func DebugExtractTar(cmdCtx *CmdContext) error {
	l := cmdCtx.logger
	outputDir := pathlib.NewPath(NormalizeOutputDir(CLI.Debug.ExtractTar.OutputDir), pathlib.PathWithAfero(cmdCtx.fs)).Clean()
	l.Debug("Ensuring output directory exists", zap.String("output_dir", outputDir.String()))
	if outputDir.Name() != "/" {
		if err := outputDir.MkdirAllMode(os.FileMode(0755)); err != nil {
			return errors.Join(&ErrCommand{}, errors.New("could not make output directory"), err)
		}
	}

	reader := cmdCtx.stdIn
	if CLI.Debug.ExtractTar.InputFile != "-" && CLI.Debug.ExtractTar.InputFile != "" {
		inputFile, err := os.Open(CLI.Debug.ExtractTar.InputFile)
		if err != nil {
			return errors.Join(&ErrCommand{}, err)
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
			return errors.Join(&ErrCommand{}, err)
		}

		cleanedPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanedPath, CLI.Debug.ExtractTar.Prefix) {
			destPathStr := strings.TrimPrefix(cleanedPath, CLI.Debug.ExtractTar.Prefix)
			fields := []zap.Field{zap.String("archive_path", cleanedPath), zap.String("dest_path", destPathStr)}
			if CLI.Debug.ExtractTar.Dryrun {
				fields = append(fields, zap.Bool("dryrun", CLI.Debug.ExtractTar.Dryrun))
			}
			l.Debug("Extracting", fields...)
			if CLI.Debug.ExtractTar.Dryrun {
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
					return errors.Join(&ErrCommand{}, err)
				}
			} else {
				exists, err := destPath.Exists()
				if err != nil {
					l.Error("Could not check path existence", zap.Error(err))
					return errors.Join(&ErrCommand{}, err)
				}
				if exists {
					destSize, err := destPath.Size()
					if err != nil {
						l.Error("Could not check path size", zap.Error(err))
						return errors.Join(&ErrCommand{}, err)
					}
					if destSize == header.Size {
						l.Debug("Skipped (exists and size matches)", fields...)
						continue
					}
					l.Debug("Size does not match - replacing")
					err = destPath.Remove()
					if err != nil {
						l.Error("Could not remove incomplete file", zap.Error(err))
						return errors.Join(&ErrCommand{}, err)
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
					return errors.Join(&ErrCommand{}, err)
				}
			}
		}
	}

	return nil
}

// DebugList will list all the objects from the given path.
func DebugList(cmdCtx *CmdContext) error {
	l := cmdCtx.logger
	outputDir := pathlib.NewPath(NormalizeOutputDir(CLI.Debug.List.Prefix), pathlib.PathWithAfero(cmdCtx.fs)).Clean()
	l.Info("Reading directory (this may take a while)")
	dirNames, err := outputDir.ReadDir()
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}
	for _, name := range dirNames {
		if strings.HasSuffix(name.Name(), ".narinfo") {
			fmt.Fprintf(cmdCtx.stdOut, "%s\n", name.Name())
		}
	}
	return nil
}
