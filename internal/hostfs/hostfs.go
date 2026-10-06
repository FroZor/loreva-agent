// Package hostfs maps host paths into the agent's file system. When the agent
// runs in a container with the host root mounted read-only, the variables
// gopsutil also reads (HOST_ROOT, HOST_PROC, HOST_SYS, HOST_ETC) point at the
// host's copies; without them every path is the agent's own.
package hostfs

import (
	"os"
	"path/filepath"
)

// Proc returns a path below the host's /proc.
func Proc(elem ...string) string {
	return join("HOST_PROC", "/proc", elem)
}

// Sys returns a path below the host's /sys.
func Sys(elem ...string) string {
	return join("HOST_SYS", "/sys", elem)
}

// Etc returns a path below the host's /etc.
func Etc(elem ...string) string {
	return join("HOST_ETC", "/etc", elem)
}

// Root maps an absolute host path below HOST_ROOT. Relative or unclean
// paths are returned unchanged, so a value read from the host cannot climb
// out of the mounted root.
func Root(path string) string {
	root := os.Getenv("HOST_ROOT")
	if root == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return path
	}

	return filepath.Join(root, path)
}

// Containerized reports whether the agent reads the host through mounted
// copies rather than its own /proc.
func Containerized() bool {
	return os.Getenv("HOST_PROC") != ""
}

func join(variable, fallback string, elem []string) string {
	base := os.Getenv(variable)
	if base == "" {
		base = fallback
	}

	return filepath.Join(append([]string{base}, elem...)...)
}
