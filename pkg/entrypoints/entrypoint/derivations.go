package entrypoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/goccy/go-yaml"
	"github.com/nix-community/go-nix/pkg/derivation"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
}

// DerivationRecurse recursively follows a derivation until it find the
// source roots.
func DerivationShow(cmdCtx CmdContext) error {
	outputRoot := CLI.Derivations.Show.OutputRoot
	if outputRoot != nil {
		if err := os.MkdirAll(*outputRoot, os.FileMode(0755)); err != nil {
			cmdCtx.logger.Error("Could not make output directory", zap.Error(err))
			return err
		}
	}

	nextPaths := CLI.Derivations.Show.Paths[:]
	seenPaths := map[string]struct{}{}
	seenPathsMtx := new(sync.Mutex)
	sem := semaphore.NewWeighted(int64(runtime.NumCPU()))

	for len(nextPaths) > 0 {
		wg := new(sync.WaitGroup)
		currentPaths := nextPaths[:]
		nextPaths = []string{}
		errCh := make(chan error)
		cancelableCtx := cmdCtx
		ctx, cancelFn := context.WithCancel(cmdCtx.ctx)
		cancelableCtx.ctx = ctx
		go func() {
			for err := range errCh {
				if err != nil {
					cmdCtx.logger.Error(err.Error())
					if ctx.Err() == nil {
						cancelFn()
					}
				}
			}
		}()
		err := readPaths(cmdCtx, currentPaths, func(path string) error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer sem.Release(1)
				l := cmdCtx.logger

				fh, err := os.Open(path)
				if err != nil {
					l.Warn("Could not read file", zap.Error(err))
					errCh <- err
				}
				drv, err := derivation.ReadDerivation(fh)
				if err != nil {
					errCh <- err
				}

				outputFormat := CLI.Derivations.Show.Format
				var output []byte
				switch outputFormat {
				case "json":
					output, err = json.MarshalIndent(&drv, "", "  ")
				case "json-compact":
					output, err = json.Marshal(&drv)
				case "yaml":
					output, err = yaml.Marshal(&drv)
				default:
					l.Error("BUG: unknown format", zap.String("format", outputFormat))
					errCh <- errors.New("unknown output format")
				}
				if err != nil {
					errCh <- err
				}

				if outputRoot != nil {
					extension, _ := strings.CutPrefix(outputFormat, "-")
					filename := fmt.Sprintf("%s.%s", filepath.Base(path), extension)

					if err := os.WriteFile(filepath.Join(*outputRoot, filename), output, os.FileMode(0644)); err != nil {
						l.Error("could not write file", zap.Error(err))
						errCh <- err
					}
				} else {
					cmdCtx.stdOut.Write(output)
					cmdCtx.stdOut.Write([]byte("\n"))
				}

				if CLI.Derivations.Show.Recurse {
					for inputDrvPath, _ := range drv.InputDerivations {
						drvPath := filepath.Join(CLI.Derivations.StoreRoot, inputDrvPath)
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
		close(errCh)
		if err != nil {
			cmdCtx.logger.Error("Error while processing paths", zap.Error(err))
			break
		}
		err = <-errCh
		if err != nil {
			cmdCtx.logger.Error("Error while processing paths", zap.Error(err))
			break
		}
	}

	cmdCtx.logger.Info("Processed derivation paths", zap.Int("seen_paths", len(seenPaths)))

	return nil
}
