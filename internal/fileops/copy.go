//go:build linux

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
		inside, err := copiesIntoItself(source, to)
		if err != nil {
			return Response{}, err
		}
		if inside {
			return Response{}, codedError(CodeInvalidPath, "a folder cannot be copied into itself")
		}
	}

	guard, err := newSpaceGuard(to.mount.root, to.rel)
	if err != nil {
		return Response{}, err
	}
	defer guard.close()

	copier := &copier{call: current, guard: guard, tracker: &progress{call: current}}
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

// copiesIntoItself reports a destination folder inside the source folder,
// either by its path (also across nested mounts) or because a symbolic
// link on the way to the destination leads into the source. A walk would
// otherwise keep finding its own copies and nest them until the disk is
// full.
func copiesIntoItself(source, to target) (bool, error) {
	if to.path == source.path || strings.HasPrefix(to.path, strings.TrimSuffix(source.path, "/")+"/") {
		return true, nil
	}
	if source.mount != to.mount {
		return false, nil
	}

	sourceInfo, err := source.mount.root.Lstat(source.rel)
	if err != nil || !sourceInfo.IsDir() {
		return false, err
	}
	rootInfo, err := to.mount.root.Stat(".")
	if err != nil {
		return false, err
	}

	// os.Root resolves ".." after following links, so this climbs the
	// folders the destination really is in.
	current := to.rel
	for range maxTreeDepth {
		info, err := to.mount.root.Stat(current)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, sourceInfo) {
			return true, nil
		}
		if os.SameFile(info, rootInfo) {
			return false, nil
		}
		// Not path.Join: it would drop ".." before any link is followed.
		current += "/.."
	}

	return false, codedError(CodeTooLarge, "the destination is nested too deeply")
}

type copier struct {
	call    *call
	guard   *spaceGuard
	tracker *progress
	skipped int64
}

// createdDirectory is a folder whose metadata is set after its content.
type createdDirectory struct {
	rel     string
	source  fs.FileInfo
	created fs.FileInfo
}

func (c *copier) tree(source, destination target) error {
	from, to := source.mount.root, destination.mount.root
	var directories []createdDirectory

	err := walk(c.call.ctx, from, source.rel, ".", func(rel, name string, info fs.FileInfo) error {
		destRel := path.Join(destination.rel, name)
		switch {
		case info.IsDir():
			// Folders stay writable until their content is in place.
			if err := to.Mkdir(destRel, 0o700); err != nil {
				return err
			}
			created, err := to.Lstat(destRel)
			if err != nil {
				return err
			}
			directories = append(directories, createdDirectory{rel: destRel, source: info, created: created})
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
		directory := directories[index]
		opened, _, err := openSame(to, directory.rel, os.O_RDONLY, directory.created)
		if err != nil {
			continue
		}
		copyMetadata(opened, directory.source)
		opened.Close()
	}

	return nil
}

func (c *copier) file(from *os.Root, rel string, to *os.Root, destRel string) error {
	source, info, err := openRegular(from, rel)
	if err != nil {
		return err
	}
	defer source.Close()

	// O_EXCL never follows a symbolic link, so the copy lands in a new file.
	destination, err := to.OpenFile(destRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	copied, err := io.CopyBuffer(c.guard.writer(destination), contextReader{ctx: c.call.ctx, reader: source}, make([]byte, 256*1024))
	if err == nil {
		copyMetadata(destination, info)
	}
	closeErr := destination.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = to.Remove(destRel)
		return err
	}
	c.tracker.add(1, copied)

	return nil
}

// copyMetadata gives an open copy the permissions, owner, and modification
// time of its source. Set-user-ID and set-group-ID bits are not copied.
func copyMetadata(file *os.File, source fs.FileInfo) {
	uid, gid, ok := ownerOf(source)
	if !ok {
		uid = -1
	}
	_ = setMetadata(file, source.Mode().Perm(), uid, gid, source.ModTime())
}
