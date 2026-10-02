//go:build unix

package nixstore

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// checkWritable verifies the process can write to all of the given paths.
func checkWritable(paths ...string) error {
	for _, path := range paths {
		if err := unix.Access(path, unix.W_OK); err != nil {
			return fmt.Errorf("%s is not writable: %w", path, err)
		}
	}
	return nil
}

// lockFile opens (creating if needed) and takes an fcntl lock on path, blocking until
// it is acquired. Nix uses fcntl locks so these interoperate with a running nix-daemon.
func lockFile(path string, exclusive bool) (*os.File, error) {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	lockType := int16(unix.F_RDLCK)
	if exclusive {
		lockType = unix.F_WRLCK
	}
	lk := unix.Flock_t{Type: lockType, Whence: 0, Start: 0, Len: 0}
	for {
		err = unix.FcntlFlock(fh.Fd(), unix.F_SETLKW, &lk)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		fh.Close()
		return nil, err
	}
	return fh, nil
}

func closeLock(fh *os.File) {
	if fh != nil {
		_ = fh.Close()
	}
}

// lockStorePath takes the per-path lock Nix uses (<path>.lock), following Nix's
// PathLocks protocol: a non-empty lock file has been deleted by its owner and
// must be reopened.
func lockStorePath(realPath string) (func(), error) {
	lockPath := realPath + ".lock"
	for {
		fh, err := lockFile(lockPath, true)
		if err != nil {
			return nil, err
		}
		info, err := fh.Stat()
		if err != nil {
			fh.Close()
			return nil, err
		}
		if info.Size() != 0 {
			// Stale lock file - the previous owner deleted it after we opened it.
			fh.Close()
			continue
		}
		return func() {
			// Mark as deleted for anyone waiting on it, then remove it.
			_ = os.Remove(lockPath)
			_, _ = fh.Write([]byte("d"))
			_ = fh.Close()
		}, nil
	}
}

func lchtimes(path string, t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
}
