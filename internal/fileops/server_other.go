//go:build !linux

package fileops

import (
	"errors"
	"io"
)

// Serve fails outside Linux. The file helper always runs in a Linux
// container, and the agent's other platforms only need the client side.
func Serve(io.Reader, io.Writer) error {
	return errors.New("the file helper runs only on Linux")
}
