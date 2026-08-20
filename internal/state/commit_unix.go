//go:build !windows && !linux

package state

import (
	"fmt"
	"os"
)

func commitState(tempPath, destination string) error {
	if err := os.Link(tempPath, destination); err != nil {
		return fmt.Errorf("filesystem must support atomic hard-link state commits: %w", err)
	}
	_ = os.Remove(tempPath)
	return nil
}

func replaceState(tempPath, destination string) error {
	return os.Rename(tempPath, destination)
}
