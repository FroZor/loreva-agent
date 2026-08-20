//go:build linux

package state

import (
	"os"

	"golang.org/x/sys/unix"
)

func commitState(tempPath, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}

func replaceState(tempPath, destination string) error {
	return os.Rename(tempPath, destination)
}
