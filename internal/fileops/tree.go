package fileops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
)

// maxTreeDepth bounds how deep a recursive operation descends.
const maxTreeDepth = 256

// visitFunc is called for every object of a tree. rel is the object's path
// in its root and name its path relative to the tree's parent.
type visitFunc func(rel, name string, info fs.FileInfo) error

// walk visits rel and everything below it, parents before children and
// children in name order. Symbolic links are reported, never followed.
func walk(ctx context.Context, root *os.Root, rel, name string, visit visitFunc) error {
	return walkDepth(ctx, root, rel, name, visit, 0)
}

func walkDepth(ctx context.Context, root *os.Root, rel, name string, visit visitFunc, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maxTreeDepth {
		return codedError(CodeTooLarge, fmt.Sprintf("folders are nested deeper than %d levels", maxTreeDepth))
	}

	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if err := visit(rel, name, info); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}

	children, err := readNames(root, rel)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := walkDepth(ctx, root, path.Join(rel, child), path.Join(name, child), visit, depth+1); err != nil {
			return err
		}
	}

	return nil
}

func readNames(root *os.Root, rel string) ([]string, error) {
	directory, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	var names []string
	for {
		batch, err := directory.Readdirnames(1024)
		names = append(names, batch...)
		if len(names) > maxDirectoryEntries {
			return nil, codedError(CodeTooLarge, fmt.Sprintf("a folder has more than %d entries", maxDirectoryEntries))
		}
		if errors.Is(err, io.EOF) || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(names)

	return names, nil
}

// openRegular opens a file for reading and checks that it is a regular
// file. O_NONBLOCK keeps a file swapped for a FIFO from blocking the open.
func openRegular(root *os.Root, rel string) (*os.File, fs.FileInfo, error) {
	file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, codedError(CodeNotRegularFile, rel+" is not a regular file")
	}

	return file, info, nil
}

// contextReader stops a copy when its context is cancelled.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.Read(buffer)
}

// ownerOf returns the owner of an object, or false when it is unknown.
func ownerOf(info fs.FileInfo) (int, int, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}

	return int(stat.Uid), int(stat.Gid), true
}

// uniqueName returns base, or base with " (n)" before its extension when
// that name is taken in dir.
func uniqueName(root *os.Root, dir, base string) (string, error) {
	if _, err := root.Lstat(path.Join(dir, base)); errors.Is(err, fs.ErrNotExist) {
		return base, nil
	}

	stem, ext := base, path.Ext(base)
	if ext == base || strings.HasSuffix(base, ".") {
		ext = ""
	}
	stem = strings.TrimSuffix(base, ext)
	for number := 1; number <= 1000; number++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, number, ext)
		if _, err := root.Lstat(path.Join(dir, candidate)); errors.Is(err, fs.ErrNotExist) {
			return candidate, nil
		}
	}

	return "", codedError(CodeAlreadyExists, "no free name for "+base)
}
