package fileops

import (
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// copyPaths copies objects into a folder, possibly in another mount. A name
// that is taken gets a " (n)" suffix, as file managers do on paste. Copies
// keep mode, owner, and modification time; special files are skipped.
func (m *mounts) copyPaths(current *call, paths []string, rawTo string) (Response, error) {
	sources, err := m.resolveSources(paths)
	if err != nil {
		return Response{}, err
	}
	to, err := m.resolveWritable(rawTo)
	if err != nil {
		return Response{}, err
	}
	toInfo, err := to.mount.root.Stat(to.rel)
	if err != nil {
		return Response{}, err
	}
	if !toInfo.IsDir() {
		return Response{}, codedError(CodeNotADirectory, to.path+" is not a folder")
	}
	for _, source := range sources {
		if source.mount == to.mount && (to.rel == source.rel || strings.HasPrefix(to.rel, source.rel+"/") || source.rel == ".") {
			return Response{}, codedError(CodeInvalidPath, "a folder cannot be copied into itself")
		}
	}

	copier := &copier{call: current, tracker: &progress{call: current}}
	var created []Entry
	for _, source := range sources {
		name, err := uniqueName(to.mount.root, to.rel, path.Base(source.path))
		if err != nil {
			return Response{}, err
		}
		destination := target{path: path.Join(to.path, name), mount: to.mount, rel: path.Join(to.rel, name)}
		if err := copier.tree(source, destination); err != nil {
			return Response{}, err
		}
		if entry, err := m.entryAt(destination.path); err == nil {
			created = append(created, entry)
		}
	}

	return Response{Entries: created, Skipped: copier.skipped, Progress: &copier.tracker.state}, nil
}

type copier struct {
	call    *call
	tracker *progress
	skipped int64
}

func (c *copier) tree(source, destination target) error {
	from, to := source.mount.root, destination.mount.root
	var directories []string

	err := walk(c.call.ctx, from, source.rel, ".", func(rel, name string, info fs.FileInfo) error {
		destRel := path.Join(destination.rel, name)
		switch {
		case info.IsDir():
			// Folders stay writable until their content is in place.
			if err := to.Mkdir(destRel, 0o700); err != nil {
				return err
			}
			directories = append(directories, name)
			c.tracker.add(1, 0)
		case info.Mode().IsRegular():
			if err := c.file(from, rel, to, destRel); err != nil {
				return err
			}
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := from.Readlink(rel)
			if err != nil {
				return err
			}
			if err := to.Symlink(link, destRel); err != nil {
				return err
			}
			if uid, gid, ok := ownerOf(info); ok {
				_ = to.Lchown(destRel, uid, gid)
			}
			c.tracker.add(1, 0)
		default:
			c.skipped++
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Children first, so a read-only folder does not block its content.
	for index := len(directories) - 1; index >= 0; index-- {
		name := directories[index]
		info, err := from.Lstat(path.Join(source.rel, name))
		if err != nil {
			continue
		}
		copyMetadata(to, path.Join(destination.rel, name), info)
	}

	return nil
}

func (c *copier) file(from *os.Root, rel string, to *os.Root, destRel string) error {
	source, info, err := openRegular(from, rel)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := to.OpenFile(destRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	copied, err := io.CopyBuffer(destination, contextReader{ctx: c.call.ctx, reader: source}, make([]byte, 256*1024))
	closeErr := destination.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = to.Remove(destRel)
		return err
	}

	copyMetadata(to, destRel, info)
	c.tracker.add(1, copied)

	return nil
}

// copyMetadata gives a copy the permissions, owner, and modification time
// of its source. Set-user-ID and set-group-ID bits are not copied.
func copyMetadata(root *os.Root, rel string, info fs.FileInfo) {
	if uid, gid, ok := ownerOf(info); ok {
		_ = root.Lchown(rel, uid, gid)
	}
	_ = root.Chmod(rel, info.Mode().Perm())
	_ = root.Chtimes(rel, info.ModTime(), info.ModTime())
}
