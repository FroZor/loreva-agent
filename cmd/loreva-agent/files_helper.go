package main

import (
	"bufio"
	"errors"
	"log/slog"
	"os"

	"github.com/FroZor/loreva-agent/internal/fileops"
)

// runFilesHelper serves file operations inside a helper container. The
// agent starts it through Docker; it is not meant to be run by hand.
func runFilesHelper(arguments []string, _ *slog.Logger) error {
	if len(arguments) != 0 {
		return errors.New("files-helper does not accept arguments")
	}

	return fileops.Serve(bufio.NewReaderSize(os.Stdin, 64*1024), os.Stdout)
}
