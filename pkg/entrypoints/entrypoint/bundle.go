package entrypoint

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/1lann/countwriter"
	"github.com/chigopher/pathlib"
	"github.com/jmoiron/sqlx"
	"github.com/mholt/archives"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"zombiezen.com/go/nix/nar"
)

//nolint:gochecknoglobals
type BundleConfig struct {
	NixDB        string `help:"Path to the nix database" default:"/nix/var/nix/db/db.sqlite"`
	Compression  string `help:"NAR file compression" enum:"xz" default:"xz"`
	OutputDir    string `help:"Output directory to write the bundles too" default:"."`
	NarOutputDir string `help:"Subdirectory to save NAR files too" default:"nar"`
	// TODO: ShardStore - build a sharded store with multiple directory trees
	Paths []string `arg:"" help:"nix paths or hashes to bundle"`
}

// NixDBValidPaths is the DTO for interfacing to the nix database
type NixDBValidPaths struct {
	ID               int64   `db:"id"`
	Path             string  `db:"path"`
	Hash             string  `db:"hash"`
	RegistrationTime int64   `db:"registrationTime"`
	Deriver          *string `db:"deriver"`
	NarSize          *uint64 `db:"narSize"`
	Ultimate         *string `db:"ultimate"`
	Sigs             *string `db:"sigs"`
	Ca               *string `db:"ca"`
}

// NixCacheInfoName is the file which should be at the root of the output directory so
// it works as an HTTP cache
const NixCacheInfoName = "nix-cache-info"

// Bundle copies a given item out of the Nix Store
func Bundle(cmdCtx *CmdContext) error {
	l := cmdCtx.logger

	var nixDbPath string

	nixDbPath = CLI.Bundle.NixDB

	l.Debug("Nix Config", zap.String("db_path", nixDbPath))
	if _, err := os.Stat(nixDbPath); os.IsNotExist(err) {
		l.Error("Nix Database file does not appear to exist!")
		return errors.Join(&ErrCommand{}, err)
	}

	// Even opening readonly, sqlite gets upset if we don't have permissions to write - so make a copy
	tempDb, err := os.CreateTemp("", "nix.db.*")
	if err != nil {
		return errors.Join(&ErrCommand{}, errors.New("could not create temp file for DB"), err)
	}
	defer os.Remove(tempDb.Name())
	defer tempDb.Close()

	nixDBBinary, err := os.Open(nixDbPath)
	if err != nil {
		return errors.Join(&ErrCommand{}, errors.New("could not open Nix DB"), err)
	}

	if _, err := io.Copy(tempDb, nixDBBinary); err != nil {
		return errors.Join(&ErrCommand{}, errors.New("could not copy Nix DB to temp file"), err)
	}

	db, err := sqlx.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", tempDb.Name()))
	if err != nil {
		return errors.Join(&ErrCommand{}, err)
	}

	err = db.Ping()
	if err != nil {
		return errors.Join(&ErrCommand{}, errors.New("DB ping failed"), err)
	}
	l.Debug("Database Connected")

	outputDir := pathlib.NewPath(NormalizeOutputDir(CLI.Bundle.OutputDir), pathlib.PathWithAfero(cmdCtx.fs)).Clean()
	l.Debug("Ensuring output directory exists", zap.String("output_dir", outputDir.String()))
	if outputDir.Name() != "/" {
		if err := outputDir.MkdirAllMode(os.FileMode(0755)); err != nil {
			return errors.Join(&ErrCommand{}, errors.New("could not make output directory"), err)
		}
	}
	narOutputDir := outputDir.Join(CLI.Bundle.NarOutputDir).Clean()
	if filepath.IsAbs(CLI.Bundle.NarOutputDir) {
		narOutputDir = pathlib.NewPath(CLI.Bundle.NarOutputDir, pathlib.PathWithAfero(cmdCtx.fs))
	}
	l.Debug("Ensuring NAR output directory exists", zap.String("nar_output_dir", narOutputDir.String()))
	if err := narOutputDir.MkdirAllMode(os.FileMode(0755)); err != nil {
		return errors.Join(&ErrCommand{}, errors.New("could not make nar output directory"), err)
	}

	var compressor archives.Compressor
	switch CLI.Bundle.Compression {
	case "xz":
		compressor = new(archives.Xz)
	default:
		l.Error("BUG: Unknown compressor")
		return errors.New("unknown compressor")
	}

	nixStore := new(string)

	err = readPaths(cmdCtx, CLI.Bundle.Paths, func(path *pathlib.Path) error {
		shortPath := path.Name()
		narId, _, _ := strings.Cut(shortPath, "-")

		l := l.With(zap.String("path_id", narId))

		nixRows := make([]NixDBValidPaths, 0)

		if err := db.Select(&nixRows, "SELECT * FROM ValidPaths WHERE path LIKE  '%/' || ? || '-%';", narId); err != nil {
			l.Warn("Failed to query path ID", zap.String("path", path.String()))
			return err
		}

		if len(nixRows) > 1 {
			l.Warn("Got multiple matches for NixID? Is your database corrupt?")
			return errors.New("got more then 1 match for given path")
		}

		if len(nixRows) == 0 {
			l.Warn("Could not find the requested path in the store")
			return nil
		}

		nixRow := nixRows[0]

		if nixStore == nil {
			*nixStore = filepath.Dir(nixRow.Path)
		}

		l.Debug("Found store object", zap.Int64("id", nixRow.ID))

		l.Info("Generating NAR file")
		narPath := narOutputDir.Join(fmt.Sprintf("%s.nar.%s", narId, CLI.Bundle.Compression))
		outputFile, err := narPath.Create()
		if err != nil {
			l.Error("Could not create output file", zap.Error(err))
			return errors.Join(errors.New("could not create output file"), err)
		}
		defer outputFile.Close()

		// We need two hashes here: the filehash, and the NAR hash so we need several tees
		// NAR -> -> compressor -> file
		//        \-> narhasher \
		//						 \-> filehasher
		fileHasher := sha256.New()
		narHasher := sha256.New()

		fileWr := countwriter.NewWriter(io.MultiWriter(outputFile, fileHasher))
		compWr, err := compressor.OpenWriter(fileWr)
		if err != nil {
			l.Error("Could not create compression writer")
			return err
		}
		defer compWr.Close()

		narWr := countwriter.NewWriter(io.MultiWriter(compWr, narHasher))

		// Wire the nar stream to the start of the pipe
		if err := nar.DumpPath(narWr, nixRow.Path); err != nil {
			l.Error("Failed to dump path to NAR file", zap.Error(err))
			return err
		}

		narFileSize := narWr.Count()
		narHash := narHasher.Sum(nil)
		fileSize := fileWr.Count()
		fileHash := fileHasher.Sum(nil)

		l.Debug("Successfully wrote NAR file",
			zap.String("file", outputFile.Name()),
			zap.Uint64("file_size", fileSize),
			zap.String("file_hash", hex.EncodeToString(narHash)),
			zap.Uint64("nar_file_size", narFileSize),
			zap.String("nar_file_hash", hex.EncodeToString(fileHash)),
		)

		// Cross-check the narSize against the DB size
		if nixRow.NarSize != nil {
			if *nixRow.NarSize != narFileSize {
				l.Warn("Obtained NAR filesize does not match database",
					zap.Uint64("obtained_size", narFileSize), zap.Uint64("written_size", *nixRow.NarSize))
			}
		}

		// Decode the hash out of the database
		hashType, hashHex, found := strings.Cut(nixRow.Hash, ":")
		if !found {
			l.Error("Hash field does not look like a hash", zap.String("hash", nixRow.Hash))
			return errors.New("hash field can't be identified")
		}

		var hashBytes []byte
		switch hashType {
		case "sha256":
			hashBytes, err = hex.DecodeString(hashHex)
			if err != nil {
				l.Error("NAR hash could not be decoded", zap.String("hash", nixRow.Hash))
				return errors.New("hash was not a valid hex string")
			}
		default:
			l.Error("unknown hash type", zap.String("hashtype", hashType))
			return errors.New("unknown hash type")
		}

		sig := make([]nixtypes.NixSignature, 0)
		if nixRow.Sigs != nil {
			for _, sigString := range strings.Split(*nixRow.Sigs, " ") {
				s := nixtypes.NixSignature{}
				if err := s.UnmarshalText([]byte(sigString)); err != nil {
					l.Error("Could not unmarshal a signature on the row", zap.String("sig_string", sigString))
					return errors.New("unparseable signature")
				}
				sig = append(sig, s)
			}
		}

		deriver := ""
		if nixRow.Deriver != nil {
			deriver = *nixRow.Deriver
		}

		// Get references
		referenceRows := make([]NixDBValidPaths, 0)

		if err := db.Select(&referenceRows, "SELECT * FROM ValidPaths WHERE id in (SELECT reference FROM Refs WHERE referrer = ?);", nixRow.ID); err != nil {
			l.Warn("Failed to query references", zap.String("path", path.String()))
			return err
		}

		references := []string{}
		for _, row := range referenceRows {
			references = append(references, filepath.Base(row.Path))
		}

		extra := map[string]string{}
		if nixRow.Ca != nil {
			extra["CA"] = *nixRow.Ca
		}

		ninfoPath := outputDir.Join(fmt.Sprintf("%s.narinfo", narId))
		// Try and figure out the URL of the nar file relative to us
		relNarPath, err := narPath.RelativeTo(ninfoPath.Parent())
		if err != nil {
			l.Error("Cannot determine relative path of NAR from Ninfo", zap.Error(err))
			return errors.New("No sane nar URL can be determined")
		}

		// Populate the ninfo file
		ninfo := nixtypes.NarInfo{
			StorePath:   nixRow.Path,
			URL:         relNarPath.String(),
			Compression: CLI.Bundle.Compression,
			FileHash:    nixtypes.TypedNixHash{"sha256", fileHasher.Sum(nil)},
			FileSize:    fileSize,
			NarHash:     nixtypes.TypedNixHash{hashType, hashBytes},
			NarSize:     narFileSize,
			References:  references,
			Deriver:     filepath.Base(deriver),
			Sig:         sig,
			Extra:       extra,
		}

		if err := writeNInfo(l, ninfoPath, ninfo); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		l.Error("Error during path processing")
		return errors.Join(&ErrCommand{}, err)
	}

	l.Debug("Writing the nix cache info file")
	metadata := fmt.Sprintf(
		`StoreDir: %s
WantMassQuery: 1
Priority: 10
`, *nixStore,
	)

	err = outputDir.Join(NixCacheInfoName).WriteFileMode([]byte(metadata), os.FileMode(0644))
	if err != nil {
		l.Error("Failed to write the nix-cache-info file", zap.Error(err))
		return errors.Join(&ErrCommand{}, err)
	}

	return err
}
