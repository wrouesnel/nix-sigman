package entrypoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/chigopher/pathlib"
	"github.com/deckarep/golang-set/v2"
	"github.com/goccy/go-yaml"
	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/wrouesnel/nix-sigman/pkg/nixconsts"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

//nolint:gochecknoglobals
type DerivationsConfig struct {
	StoreRoot string `help:"Path to the store root to search for dependencies" type:"path" default:"/"`
	//DrvFiles  []string `arg:"" help:"Derivation paths"`
	Show struct {
		Recurse    bool     `help:"Follow input derivations"`
		OutputRoot *string  `help:"Write outputs to a directory instead of stdout" type:"path"`
		Format     string   `help:"format" enum:"json,json-compact,yaml" default:"json"`
		Paths      []string `arg:"" help:"Derivation paths"`
	} `cmd:"" help:"JSON format a derivation"`
	Urls struct {
		Strict bool `help:"If true then abort if any derivation fails to parse"`
		//CombineEquivalents   bool     `help:"Combine substitutions which produce multiple paths onto a single space separated line"`
		EmitTarballCacheUrls bool     `help:"If a derivation includes a hash then emit a tarball hash URL as well"`
		TarballCacheBaseUrl  string   `default:"https://tarball.nixos.org/" help:"Tarball cache URL to generate"`
		GuessURLTypes        bool     `help:"Modify URLs with application hints e.g. git+https - this is heuristic"`
		Paths                []string `arg:"" help:"Derivation paths"`
	} `cmd:"" help:"Recursively follow derivations and extract source input URLs"`
}

// DerivationRecurse recursively follows a derivation until it find the
// source roots.
func DerivationShow(cmdCtx *CmdContext) error {
	outputRoot := CLI.Derivations.Show.OutputRoot
	if outputRoot != nil {
		if err := os.MkdirAll(*outputRoot, os.FileMode(0755)); err != nil {
			cmdCtx.logger.Error("Could not make output directory", zap.Error(err))
			return err
		}
	}

	err := recurseDerivations(cmdCtx.logger, cmdCtx, CLI.Derivations.Show.Paths, CLI.Derivations.Show.Recurse, true,
		CLI.Derivations.StoreRoot, func(cmdCtx *CmdContext, path *pathlib.Path, drv *derivation.Derivation) error {
			l := cmdCtx.logger
			outputFormat := CLI.Derivations.Show.Format
			var output []byte
			var err error
			switch outputFormat {
			case "json":
				output, err = json.MarshalIndent(&drv, "", "  ")
			case "json-compact":
				output, err = json.Marshal(&drv)
			case "yaml":
				output, err = yaml.Marshal(&drv)
			default:
				l.Error("BUG: unknown format", zap.String("format", outputFormat))
				return errors.New("unknown output format")
			}

			if err != nil {
				return err
			}

			if outputRoot != nil {
				extension, _ := strings.CutPrefix(outputFormat, "-")
				filename := fmt.Sprintf("%s.%s", path.Name(), extension)

				if err := os.WriteFile(filepath.Join(*outputRoot, filename), output, os.FileMode(0644)); err != nil {
					l.Error("could not write file", zap.Error(err))
					return err
				}
			} else {
				cmdCtx.stdOut.Write(output)
				cmdCtx.stdOut.Write([]byte("\n"))
			}
			return nil
		})

	return err
}

// DerivationUrls recursively follows the provided paths, resolves all URLs and writes them
// stdout. This allows it to provide a BOM for a given nix build.
func DerivationUrls(cmdCtx *CmdContext) error {
	inputUrls := mapset.NewSet[string]()
	err := recurseDerivations(cmdCtx.logger, cmdCtx, CLI.Derivations.Urls.Paths, true, CLI.Derivations.Urls.Strict,
		CLI.Derivations.StoreRoot, func(cmdCtx *CmdContext, path *pathlib.Path, drv *derivation.Derivation) error {
			// As far as we know, there's only two possible types of inputs: "url" and "urls", stored
			// under the env key. urls is spaced separated.
			inputUris := []*url.URL{}
			if urlStr, found := drv.Env["url"]; found && urlStr != "" {
				uri, err := url.Parse(urlStr)
				if err != nil {
					return err
				}
				inputUris = append(inputUris, uri)
			}
			if urlsStr, found := drv.Env["urls"]; found && urlsStr != "" {
				for _, urlStr := range strings.Split(urlsStr, " ") {
					if strings.TrimSpace(urlStr) == "" {
						continue
					}
					uri, err := url.Parse(strings.TrimSpace(urlStr))
					if err != nil {
						return err
					}
					inputUris = append(inputUris, uri)
				}
			}

			derivUrls := []string{}
			for _, uri := range inputUris {
				subUrls := nixconsts.SubstituteUrl(uri)

				for _, subUri := range subUrls {
					if CLI.Derivations.Urls.GuessURLTypes {
						if fetcher, found := drv.Env["fetcher"]; found {
							if strings.HasSuffix(fetcher, "git") {
								// Looks like a git URL
								subUri.Scheme = fmt.Sprintf("%s+%s", "git", subUri.Scheme)
							}
						}
					}

					stringUrl := subUri.String()

					derivUrls = append(derivUrls, stringUrl)
				}
			}

			if CLI.Derivations.Urls.EmitTarballCacheUrls {
				if output, found := drv.Outputs["out"]; found {
					// We need to ignore r: since it's for recursive derivations we can't calculate.
					if output.HashAlgorithm != "" && output.Hash != "" && !strings.HasPrefix(output.Hash, "r:") {
						derivUrls = append(derivUrls, fmt.Sprintf("%v/%v/%v", CLI.Derivations.Urls.TarballCacheBaseUrl, output.HashAlgorithm, output.Hash))
					}
				}
			}

			inputUrls.Add(strings.Join(derivUrls, " "))

			return nil
		})

	urlList := inputUrls.ToSlice()
	sort.Strings(urlList)

	for _, subUrl := range urlList {
		cmdCtx.stdOut.Write([]byte(subUrl))
		cmdCtx.stdOut.Write([]byte("\n"))
	}

	return err
}

type ErrDerivation struct {
	Path *pathlib.Path
}

func (e ErrDerivation) Error() string {
	return fmt.Sprintf("error while processing derivation: %v", e.Path.String())
}

// recurseDerivations follows derivations and calls a function against each one.
func recurseDerivations(l *zap.Logger, cmdCtx *CmdContext, paths []string, recurse bool, strict bool, drvRoot string,
	cb func(cmdCtx *CmdContext, path *pathlib.Path, drv *derivation.Derivation) error) error {
	nextPaths := paths[:]
	seenPaths := map[string]struct{}{}
	seenPathsMtx := new(sync.Mutex)
	sem := semaphore.NewWeighted(int64(runtime.NumCPU()))

	hadErrors := new(bool)

	for len(nextPaths) > 0 {
		wg := new(sync.WaitGroup)
		currentPaths := nextPaths[:]
		nextPaths = []string{}
		errCh := make(chan error)
		ctx, cancelFn := context.WithCancel(cmdCtx.ctx)
		go func() {
			for err := range errCh {
				if err != nil {
					*hadErrors = true
					cmdCtx.logger.Error(err.Error())
					if ctx.Err() == nil && strict {
						cancelFn()
					}
				}
			}
		}()
		err := readPaths(cmdCtx, currentPaths, func(path *pathlib.Path) error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer sem.Release(1)
				l := cmdCtx.logger

				fh, err := path.Open()
				if err != nil {
					l.Warn("Could not read file", zap.Error(err))
					errCh <- errors.Join(&ErrDerivation{path}, err)
					return
				}
				drv, err := derivation.ReadDerivation(fh)
				if err != nil {
					errCh <- err
					return
				}

				if err := cb(cmdCtx, path, drv); err != nil {
					errCh <- errors.Join(&ErrDerivation{path}, err)
					return
				}

				if err != nil {
					errCh <- errors.Join(&ErrDerivation{path}, err)
					return
				}

				if recurse {
					for inputDrvPath, _ := range drv.InputDerivations {
						drvPath := filepath.Join(drvRoot, inputDrvPath)
						seenPathsMtx.Lock()
						if _, found := seenPaths[drvPath]; !found {
							seenPaths[drvPath] = struct{}{}
							nextPaths = append(nextPaths, drvPath)
						}
						seenPathsMtx.Unlock()
					}
				}

				errCh <- nil
			}()
			return nil
		})
		cmdCtx.logger.Info("Recursed Paths", zap.Int("next_paths", len(nextPaths)))
		wg.Wait()
		// Read paths should never fail
		close(errCh)
		if err != nil {
			cmdCtx.logger.Error("Error while processing paths", zap.Error(err))
			break
		}
	}

	cmdCtx.logger.Info("Processed derivation paths", zap.Int("seen_paths", len(seenPaths)))
	if *hadErrors {
		return errors.New("encountered errors while processing paths")
	}
	return nil
}
