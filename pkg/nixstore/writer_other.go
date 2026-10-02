//go:build !unix

package nixstore

import (
	"errors"
	"os"
	"time"
)

var errUnsupported = errors.New("writing to a Nix store is not supported on this platform")

func checkWritable(paths ...string) error {
	return errUnsupported
}

func lockFile(path string, exclusive bool) (*os.File, error) {
	return nil, errUnsupported
}

func closeLock(fh *os.File) {}

func lockStorePath(realPath string) (func(), error) {
	return nil, errUnsupported
}

func lchtimes(path string, t time.Time) error {
	return errUnsupported
}
