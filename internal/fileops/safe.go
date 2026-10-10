//go:build linux

package fileops

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// spaceCheckBytes is how much an operation writes between checks of
	// the free space.
	spaceCheckBytes = 64 * 1024 * 1024
	// maxSpaceReserve caps the free space an operation leaves untouched.
	maxSpaceReserve = 1 << 30
)

// errChanged reports an object that was replaced between its check and
// its use, typically by a symbolic link planted by a process in the
// container.
var errChanged = codedError(CodeVersionConflict, "the file or folder was replaced while it was being changed")

// openSame opens rel and checks that the descriptor refers to the object
// want describes. os.Root keeps every access inside the mount but follows
// a final symbolic link, so a name swapped for a link after Lstat would
// otherwise redirect the change to another file of the mount.
func openSame(root *os.Root, rel string, flag int, want fs.FileInfo) (*os.File, fs.FileInfo, error) {
	file, err := root.OpenFile(rel, flag|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !os.SameFile(info, want) {
		file.Close()
		return nil, nil, errChanged
	}

	return file, info, nil
}

// setMetadata changes an open object, never a name that may have been
// swapped. A negative uid leaves the owner unchanged; a zero mtime leaves
// the modification time unchanged.
func setMetadata(file *os.File, perm fs.FileMode, uid, gid int, mtime time.Time) error {
	if uid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			return err
		}
	}
	// Chmod after Chown: changing the owner clears set-ID bits.
	if err := file.Chmod(perm); err != nil {
		return err
	}
	if mtime.IsZero() {
		return nil
	}

	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	times := []syscall.Timeval{syscall.NsecToTimeval(mtime.UnixNano()), syscall.NsecToTimeval(mtime.UnixNano())}
	var futimesErr error
	if err := raw.Control(func(fd uintptr) { futimesErr = syscall.Futimes(int(fd), times) }); err != nil {
		return err
	}

	return futimesErr
}

// renameNoReplace renames within one mount and fails with already_exists
// instead of replacing an object that appeared after the caller checked.
// Both names are resolved to their parent folder first, so the rename
// itself only sees final components.
func renameNoReplace(root *os.Root, from, to string) error {
	fromDir, err := root.Open(path.Dir(from))
	if err != nil {
		return err
	}
	defer fromDir.Close()
	toDir, err := root.Open(path.Dir(to))
	if err != nil {
		return err
	}
	defer toDir.Close()

	err = unix.Renameat2(int(fromDir.Fd()), path.Base(from), int(toDir.Fd()), path.Base(to), unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		// The file system cannot refuse to replace; check, then rename.
		if _, statErr := root.Lstat(to); statErr == nil {
			return codedError(CodeAlreadyExists, "the destination already exists")
		}
		return root.Rename(from, to)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}

	return nil
}

// spaceGuard stops a write before it leaves less than a reserve free on
// the volume, so an archive bomb or a runaway copy cannot fill the disk
// the node and its other containers share.
type spaceGuard struct {
	dir     *os.File
	written int64
	next    int64
}

func newSpaceGuard(root *os.Root, dir string) (*spaceGuard, error) {
	opened, err := root.Open(dir)
	if err != nil {
		return nil, err
	}

	guard := &spaceGuard{dir: opened}
	if err := guard.check(); err != nil {
		opened.Close()
		return nil, err
	}

	return guard, nil
}

func (g *spaceGuard) close() {
	g.dir.Close()
}

// add accounts for bytes about to be written.
func (g *spaceGuard) add(bytes int64) error {
	g.written += bytes
	if g.written < g.next {
		return nil
	}
	g.next = g.written + spaceCheckBytes

	return g.check()
}

func (g *spaceGuard) check() error {
	var stats syscall.Statfs_t
	raw, err := g.dir.SyscallConn()
	if err != nil {
		return err
	}
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = syscall.Fstatfs(int(fd), &stats) }); err != nil {
		return err
	}
	if statErr != nil {
		return statErr
	}

	blockSize := uint64(stats.Bsize)
	total, available := stats.Blocks*blockSize, stats.Bavail*blockSize
	reserve := min(total/20, maxSpaceReserve)
	if available < reserve {
		return codedError(CodeNoSpace, fmt.Sprintf("the volume has %d MiB free; the operation stops before the last %d MiB so the node's disk does not fill", available>>20, reserve>>20))
	}

	return nil
}

// writer wraps w so every write is checked against the reserve first.
func (g *spaceGuard) writer(w io.Writer) io.Writer {
	return guardedWriter{writer: w, guard: g}
}

type guardedWriter struct {
	writer io.Writer
	guard  *spaceGuard
}

func (w guardedWriter) Write(data []byte) (int, error) {
	if err := w.guard.add(int64(len(data))); err != nil {
		return 0, err
	}

	return w.writer.Write(data)
}
