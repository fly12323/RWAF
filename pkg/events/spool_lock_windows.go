//go:build windows

package events

import (
	"golang.org/x/sys/windows"
	"os"
)

func lockSpool(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Windows cannot fsync directory handles with os.File.Sync. Record data is
// flushed before rename; Linux deployment additionally flushes the directory.
func syncSpoolDir(string) error { return nil }
