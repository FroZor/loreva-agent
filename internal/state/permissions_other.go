//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
)

func secureDirectory(path string) error {
	return os.Chmod(path, 0o700)
}

func secureFile(path string) error {
	return os.Chmod(path, 0o600)
}

func ensureSecureFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state file permissions %o are too broad; require 0600", info.Mode().Perm())
	}

	return nil
}

func syncDirectory(path string) (resultErr error) {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close state directory after sync: %w", err))
		}
	}()

	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}

	return nil
}
