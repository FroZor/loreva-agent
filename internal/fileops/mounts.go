package fileops

import (
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

const (
	// maxPathBytes bounds a path in a request.
	maxPathBytes = 4096
	// maxDirectoryEntries bounds the directory size the helper lists.
	maxDirectoryEntries = 100_000
	// listPageEntries is the number of entries one list response holds.
	listPageEntries = 500
	// maxBatchPaths bounds the paths one delete, copy, or archive names.
	maxBatchPaths = 1000
)

// mounts resolves container paths to the mounts the helper shares. Every
// file system access goes through an os.Root, so neither ".." nor a
// symbolic link can lead out of a mount.
type mounts struct {
	// byLength lists mounts with the longest path first, so the first
	// match is the innermost mount.
	byLength []*mount
}

type mount struct {
	path     string
	readOnly bool
	root     *os.Root
	// file marks a bind mount of a single file: root is its parent
	// directory and only name may be used in it.
	file bool
	name string
}

// target is a resolved path.
type target struct {
	path  string
	mount *mount
	// rel is the path inside the mount root, "." for the root itself.
	rel string
	// virtual marks a directory that only leads to mounts.
	virtual bool
}

func openMounts(list []Mount) (*mounts, error) {
	if len(list) == 0 {
		return nil, codedError(CodeOutsideMounts, "the container has no volumes or mounted folders")
	}

	result := &mounts{}
	for _, item := range list {
		clean, err := cleanPath(item.Path)
		if err != nil || clean == "/" {
			result.close()
			return nil, codedError(CodeInvalidPath, fmt.Sprintf("mount path %q is not usable", item.Path))
		}

		opened, err := openMount(clean, item.ReadOnly)
		if err != nil {
			result.close()
			return nil, err
		}
		result.byLength = append(result.byLength, opened)
	}
	slices.SortFunc(result.byLength, func(a, b *mount) int { return len(b.path) - len(a.path) })

	return result, nil
}

func openMount(clean string, readOnly bool) (*mount, error) {
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		root, err := os.OpenRoot(clean)
		if err != nil {
			return nil, err
		}
		return &mount{path: clean, readOnly: readOnly, root: root}, nil
	}

	root, err := os.OpenRoot(path.Dir(clean))
	if err != nil {
		return nil, err
	}

	return &mount{path: clean, readOnly: readOnly, root: root, file: true, name: path.Base(clean)}, nil
}

func (m *mounts) close() {
	for _, item := range m.byLength {
		item.root.Close()
	}
}

func cleanPath(raw string) (string, error) {
	if raw == "" || len(raw) > maxPathBytes || !strings.HasPrefix(raw, "/") || strings.ContainsRune(raw, 0) {
		return "", codedError(CodeInvalidPath, "a path must be absolute and at most 4096 bytes")
	}

	return path.Clean(raw), nil
}

func (m *mounts) resolve(raw string) (target, error) {
	clean, err := cleanPath(raw)
	if err != nil {
		return target{}, err
	}

	for _, item := range m.byLength {
		switch {
		case clean == item.path:
			rel := "."
			if item.file {
				rel = item.name
			}
			return target{path: clean, mount: item, rel: rel}, nil
		case !item.file && strings.HasPrefix(clean, item.path+"/"):
			return target{path: clean, mount: item, rel: strings.TrimPrefix(clean, item.path+"/")}, nil
		}
	}
	if len(m.virtualChildren(clean)) > 0 {
		return target{path: clean, virtual: true}, nil
	}

	return target{}, codedError(CodeOutsideMounts, clean+" is not inside a volume or mounted folder of the container")
}

// virtualChildren names the next path component of every mount below dir.
func (m *mounts) virtualChildren(dir string) []string {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var names []string
	for _, item := range m.byLength {
		if !strings.HasPrefix(item.path, prefix) {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(item.path, prefix), "/")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	return names
}

func (m *mounts) isMountRoot(clean string) bool {
	for _, item := range m.byLength {
		if item.path == clean {
			return true
		}
	}

	return false
}

// resolveWritable resolves a path that an operation changes; mount roots
// and virtual directories cannot be changed themselves.
func (m *mounts) resolveWritable(raw string) (target, error) {
	resolved, err := m.resolve(raw)
	if err != nil {
		return target{}, err
	}
	if resolved.virtual {
		return target{}, codedError(CodeOutsideMounts, "only volumes and mounted folders can be changed")
	}
	if resolved.mount.readOnly {
		return target{}, codedError(CodeReadOnly, resolved.mount.path+" is mounted read-only")
	}

	return resolved, nil
}

// resolveChild resolves a path whose object is created, renamed, or
// removed: it must lie strictly inside a writable mount.
func (m *mounts) resolveChild(raw string) (target, error) {
	resolved, err := m.resolveWritable(raw)
	if err != nil {
		return target{}, err
	}
	if m.isMountRoot(resolved.path) {
		return target{}, codedError(CodeMountRoot, resolved.path+" is a mount and cannot be replaced, renamed, or removed")
	}

	return resolved, nil
}

func (m *mounts) list(raw, after string) (Response, error) {
	resolved, err := m.resolve(raw)
	if err != nil {
		return Response{}, err
	}

	var entries []Entry
	if resolved.virtual {
		entries, err = m.listVirtual(resolved.path)
	} else {
		entries, err = m.listMount(resolved)
	}
	if err != nil {
		return Response{}, err
	}

	start := 0
	if after != "" {
		start, _ = slices.BinarySearchFunc(entries, after, func(entry Entry, name string) int { return strings.Compare(entry.Name, name) })
		if start < len(entries) && entries[start].Name == after {
			start++
		}
	}
	end := min(start+listPageEntries, len(entries))

	return Response{Entries: entries[start:end], More: end < len(entries)}, nil
}

func (m *mounts) listVirtual(dir string) ([]Entry, error) {
	var entries []Entry
	for _, name := range m.virtualChildren(dir) {
		child := path.Join(dir, name)
		entry, err := m.entryAt(child)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (m *mounts) listMount(resolved target) ([]Entry, error) {
	if resolved.mount.file {
		return nil, codedError(CodeNotADirectory, resolved.path+" is a file")
	}

	directory, err := resolved.mount.root.Open(resolved.rel)
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	info, err := directory.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, codedError(CodeNotADirectory, resolved.path+" is not a directory")
	}

	var entries []Entry
	for {
		batch, err := directory.ReadDir(1024)
		for _, item := range batch {
			itemInfo, infoErr := item.Info()
			if infoErr != nil {
				// The entry was removed while the directory was read.
				continue
			}
			child := target{path: path.Join(resolved.path, item.Name()), mount: resolved.mount, rel: path.Join(resolved.rel, item.Name())}
			entries = append(entries, m.entry(child, itemInfo))
		}
		if len(entries) > maxDirectoryEntries {
			return nil, codedError(CodeTooLarge, fmt.Sprintf("the directory has more than %d entries", maxDirectoryEntries))
		}
		if errors.Is(err, io.EOF) || (err == nil && len(batch) == 0) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })

	return entries, nil
}

func (m *mounts) statEntry(raw string) (Response, error) {
	clean, err := cleanPath(raw)
	if err != nil {
		return Response{}, err
	}

	entry, err := m.entryAt(clean)
	if err != nil {
		return Response{}, err
	}

	return Response{Entry: &entry}, nil
}

// entryAt describes a path without following a final symbolic link.
func (m *mounts) entryAt(clean string) (Entry, error) {
	resolved, err := m.resolve(clean)
	if err != nil {
		return Entry{}, err
	}
	if resolved.virtual {
		return Entry{Name: path.Base(clean), Type: TypeDirectory, Mode: 0o755, Virtual: true, ReadOnly: true}, nil
	}

	info, err := resolved.mount.root.Lstat(resolved.rel)
	if err != nil {
		return Entry{}, err
	}

	return m.entry(resolved, info), nil
}

func (m *mounts) entry(resolved target, info fs.FileInfo) Entry {
	entry := Entry{
		Name:       path.Base(resolved.path),
		Type:       entryType(info.Mode()),
		Size:       info.Size(),
		Mode:       unixMode(info.Mode()),
		ModifiedAt: info.ModTime().UTC(),
		Version:    version(info),
		Mount:      m.isMountRoot(resolved.path),
		ReadOnly:   resolved.mount.readOnly,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.UID = int(stat.Uid)
		entry.GID = int(stat.Gid)
	}
	if entry.Type == TypeSymlink {
		entry.LinkTarget, _ = resolved.mount.root.Readlink(resolved.rel)
	}
	if entry.Type == TypeDirectory {
		entry.Size = 0
	}

	return entry
}

func entryType(mode fs.FileMode) string {
	switch {
	case mode.IsRegular():
		return TypeFile
	case mode.IsDir():
		return TypeDirectory
	case mode&fs.ModeSymlink != 0:
		return TypeSymlink
	default:
		return TypeOther
	}
}

// unixMode returns the permission bits as chmod takes them.
func unixMode(mode fs.FileMode) uint32 {
	bits := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		bits |= 0o1000
	}

	return bits
}

func version(info fs.FileInfo) string {
	return fmt.Sprintf("%d-%d", info.ModTime().UnixNano(), info.Size())
}

func (m *mounts) mkdir(raw string) (Response, error) {
	resolved, err := m.resolveChild(raw)
	if err != nil {
		return Response{}, err
	}

	if err := resolved.mount.root.Mkdir(resolved.rel, 0o755); err != nil {
		return Response{}, err
	}
	inheritOwner(resolved.mount.root, resolved.rel)

	return m.statEntry(resolved.path)
}

func (m *mounts) rename(rawFrom, rawTo string) (Response, error) {
	from, err := m.resolveChild(rawFrom)
	if err != nil {
		return Response{}, err
	}
	to, err := m.resolveChild(rawTo)
	if err != nil {
		return Response{}, err
	}
	if from.mount != to.mount {
		return Response{}, codedError(CodeCrossDevice, "moving between volumes needs a copy and a delete")
	}
	if to.rel == from.rel || strings.HasPrefix(to.rel, from.rel+"/") {
		return Response{}, codedError(CodeInvalidPath, "a folder cannot be moved into itself")
	}
	// Rename would silently replace an existing file.
	if _, err := from.mount.root.Lstat(to.rel); err == nil {
		return Response{}, codedError(CodeAlreadyExists, to.path+" already exists")
	}

	if err := from.mount.root.Rename(from.rel, to.rel); err != nil {
		return Response{}, err
	}

	return m.statEntry(to.path)
}

func (m *mounts) chmod(raw string, mode uint32) (Response, error) {
	if mode > 0o777 {
		return Response{}, codedError(CodeInvalidRequest, "mode may only carry the read, write, and execute bits (0 to 0777)")
	}

	resolved, err := m.resolveWritable(raw)
	if err != nil {
		return Response{}, err
	}
	info, err := resolved.mount.root.Lstat(resolved.rel)
	if err != nil {
		return Response{}, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return Response{}, codedError(CodeNotRegularFile, "the mode of a symbolic link cannot be changed")
	}

	if err := resolved.mount.root.Chmod(resolved.rel, fs.FileMode(mode)); err != nil {
		return Response{}, err
	}

	return m.statEntry(resolved.path)
}

func (m *mounts) delete(current *call, paths []string) (Response, error) {
	if len(paths) == 0 || len(paths) > maxBatchPaths {
		return Response{}, codedError(CodeInvalidRequest, fmt.Sprintf("name 1 to %d paths", maxBatchPaths))
	}

	resolved := make([]target, 0, len(paths))
	for _, raw := range paths {
		item, err := m.resolveChild(raw)
		if err != nil {
			return Response{}, err
		}
		resolved = append(resolved, item)
	}

	tracker := &progress{call: current}
	for _, item := range resolved {
		if err := current.ctx.Err(); err != nil {
			return Response{}, err
		}
		if err := item.mount.root.RemoveAll(item.rel); err != nil {
			return Response{}, err
		}
		tracker.add(1, 0)
	}

	return Response{Progress: &tracker.state}, nil
}

// inheritOwner gives a new object the owner of its parent directory, so a
// container that runs as an unprivileged user can still change it. It is
// best effort: a failure leaves the object owned by root.
func inheritOwner(root *os.Root, rel string) {
	parent, err := root.Stat(path.Dir(rel))
	if err != nil {
		return
	}
	if stat, ok := parent.Sys().(*syscall.Stat_t); ok {
		_ = root.Lchown(rel, int(stat.Uid), int(stat.Gid))
	}
}
