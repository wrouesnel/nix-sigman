package entrypoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"github.com/chigopher/pathlib"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/wrouesnel/nix-sigman/pkg/nixtypes"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

type RealizationsConfig struct {
	StoreRoot string `help:"Path to the store root to search for dependencies" type:"path" default:"/nix/store"`
	List      struct {
		Strict bool     `help:"If true then abort if any derivation fails to parse"`
		Paths  []string `arg:"" help:"Nix Paths"`
	} `cmd:"" help:"List all dependencies of the given package"`
}

func RealizationsList(cmdCtx *CmdContext) error {
	inputUrls := mapset.NewSet[string]()
	err := recurseRealizations(cmdCtx.logger, cmdCtx, CLI.Realizations.List.Paths, true, CLI.Realizations.List.Strict,
		CLI.Realizations.StoreRoot, func(cmdCtx *CmdContext, path *pathlib.Path, ninfo *nixtypes.NarInfo) error {
			inputUrls.Add(path.String())
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

type ErrNinfo struct {
	Path *pathlib.Path
}

func (e ErrNinfo) Error() string {
	return fmt.Sprintf("error while processing derivation: %v", e.Path.String())
}

// recurseRealizations follows derivations and calls a function against each one.
func recurseRealizations(l *zap.Logger, cmdCtx *CmdContext, paths []string, recurse bool, strict bool, storeRoot string,
	cb func(cmdCtx *CmdContext, path *pathlib.Path, ninfo *nixtypes.NarInfo) error) error {
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

				ninfoPath := pathlib.NewPath(path.String()+".narinfo", pathlib.PathWithAfero(path.Fs()))

				fh, err := ninfoPath.Open()
				if err != nil {
					l.Warn("Could not read file", zap.Error(err))
					errCh <- errors.Join(&ErrNinfo{ninfoPath}, err)
					return
				}

				ninfoBytes, err := io.ReadAll(fh)
				if err != nil {
					l.Warn("Could not read file", zap.Error(err))
					errCh <- errors.Join(&ErrNinfo{ninfoPath}, err)
					return
				}

				ninfo := nixtypes.NarInfo{}
				if err := ninfo.UnmarshalText(ninfoBytes); err != nil {
					l.Warn("Could not unmarshal NAR info", zap.Error(err))
					errCh <- errors.Join(&ErrNinfo{ninfoPath}, err)
					return
				}

				if err := cb(cmdCtx, path, &ninfo); err != nil {
					errCh <- errors.Join(&ErrNinfo{ninfoPath}, err)
					return
				}

				if err != nil {
					errCh <- errors.Join(&ErrNinfo{ninfoPath}, err)
					return
				}

				if recurse {
					for _, referencePath := range ninfo.References {
						refPath := filepath.Join(storeRoot, referencePath)
						seenPathsMtx.Lock()
						if _, found := seenPaths[refPath]; !found {
							seenPaths[refPath] = struct{}{}
							nextPaths = append(nextPaths, refPath)
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

	cmdCtx.logger.Info("Processed realization paths", zap.Int("seen_paths", len(seenPaths)))
	if *hadErrors {
		return errors.New("encountered errors while processing paths")
	}
	return nil
}
