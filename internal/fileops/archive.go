package fileops

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// maxExtractEntries and maxExtractBytes bound what one extraction
	// creates, so a crafted archive cannot fill the volume unnoticed.
	maxExtractEntries = 100_000
	maxExtractBytes   = 64 << 30
)

// archiveSink writes one archive format.
type archiveSink interface {
	add(name string, info fs.FileInfo, link string, content io.Reader) error
	// skips reports whether the format cannot hold an object of this kind.
	skips(info fs.FileInfo) bool
	close() error
}

// archive packs paths that share one folder into a new zip or tar.gz file.
func (m *mounts) archive(current *call, paths []string, rawTo, format string) (Response, error) {
	if format != FormatZip && format != FormatTarGz {
		return Response{}, codedError(CodeUnsupported, "format must be zip or tar.gz")
	}
	sources, err := m.resolveSources(paths)
	if err != nil {
		return Response{}, err
	}
	to, err := m.resolveChild(rawTo)
	if err != nil {
		return Response{}, err
	}
	if _, err := to.mount.root.Lstat(to.rel); err == nil {
		return Response{}, codedError(CodeAlreadyExists, to.path+" already exists")
	}

	temp := path.Join(path.Dir(to.rel), tempName())
	file, err := to.mount.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Response{}, err
	}
	done := false
	defer func() {
		file.Close()
		if !done {
			_ = to.mount.root.Remove(temp)
		}
	}()

	guard, err := newSpaceGuard(to.mount.root, path.Dir(to.rel))
	if err != nil {
		return Response{}, err
	}
	defer guard.close()
	buffered := bufio.NewWriterSize(guard.writer(file), 256*1024)
	sink := newArchiveSink(buffered, format)
	tracker := &progress{call: current}
	var skipped int64
	for _, source := range sources {
		err := walk(current.ctx, source.mount.root, source.rel, path.Base(source.path), func(rel, name string, info fs.FileInfo) error {
			if source.mount == to.mount && rel == temp {
				return nil
			}
			if sink.skips(info) {
				skipped++
				return nil
			}
			return addToArchive(current, sink, source.mount.root, rel, name, info, tracker)
		})
		if err != nil {
			return Response{}, err
		}
	}
	if err := sink.close(); err != nil {
		return Response{}, err
	}
	if err := buffered.Flush(); err != nil {
		return Response{}, err
	}
	if err := file.Sync(); err != nil {
		return Response{}, err
	}

	applyMetadata(to.mount.root, file, to.rel, nil, 0)
	if err := renameNoReplace(to.mount.root, temp, to.rel); err != nil {
		return Response{}, err
	}
	done = true

	entry, err := m.entryAt(to.path)
	if err != nil {
		return Response{}, err
	}

	return Response{Entry: &entry, Skipped: skipped, Progress: &tracker.state}, nil
}

// resolveSources resolves the paths of a batch operation; they must name
// real objects in one folder.
func (m *mounts) resolveSources(paths []string) ([]target, error) {
	if len(paths) == 0 || len(paths) > maxBatchPaths {
		return nil, codedError(CodeInvalidRequest, fmt.Sprintf("name 1 to %d paths", maxBatchPaths))
	}

	sources := make([]target, 0, len(paths))
	for _, raw := range paths {
		source, err := m.resolve(raw)
		if err != nil {
			return nil, err
		}
		if source.virtual {
			return nil, codedError(CodeOutsideMounts, source.path+" only leads to mounts; choose a volume or something inside one")
		}
		if len(sources) > 0 && path.Dir(source.path) != path.Dir(sources[0].path) {
			return nil, codedError(CodeInvalidRequest, "all paths must be in the same folder")
		}
		sources = append(sources, source)
	}

	return sources, nil
}

func addToArchive(current *call, sink archiveSink, root *os.Root, rel, name string, info fs.FileInfo, tracker *progress) error {
	switch {
	case info.Mode().IsRegular():
		file, opened, err := openRegular(root, rel)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := sink.add(name, opened, "", io.LimitReader(contextReader{ctx: current.ctx, reader: file}, opened.Size())); err != nil {
			return err
		}
		tracker.add(1, opened.Size())
	case info.Mode()&fs.ModeSymlink != 0:
		link, err := root.Readlink(rel)
		if err != nil {
			return err
		}
		if err := sink.add(name, info, link, nil); err != nil {
			return err
		}
		tracker.add(1, 0)
	default:
		if err := sink.add(name, info, "", nil); err != nil {
			return err
		}
		tracker.add(1, 0)
	}

	return nil
}

func newArchiveSink(writer io.Writer, format string) archiveSink {
	if format == FormatZip {
		return &zipSink{writer: zip.NewWriter(writer)}
	}

	compressed := gzip.NewWriter(writer)

	return &tarSink{writer: tar.NewWriter(compressed), compressed: compressed}
}

type zipSink struct {
	writer *zip.Writer
}

// skips drops symbolic links and special files: zip has no portable way to
// store them.
func (s *zipSink) skips(info fs.FileInfo) bool {
	return !info.Mode().IsRegular() && !info.IsDir()
}

func (s *zipSink) add(name string, info fs.FileInfo, _ string, content io.Reader) error {
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	if info.IsDir() {
		header.Name += "/"
	} else {
		header.Method = zip.Deflate
	}

	writer, err := s.writer.CreateHeader(header)
	if err != nil || content == nil {
		return err
	}
	_, err = io.Copy(writer, content)

	return err
}

func (s *zipSink) close() error { return s.writer.Close() }

type tarSink struct {
	writer     *tar.Writer
	compressed *gzip.Writer
}

// skips drops special files; tar keeps folders, files, and symbolic links.
func (s *tarSink) skips(info fs.FileInfo) bool {
	return !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&fs.ModeSymlink == 0
}

func (s *tarSink) add(name string, info fs.FileInfo, link string, content io.Reader) error {
	return addTarEntry(s.writer, name, info, link, content)
}

func (s *tarSink) close() error {
	if err := s.writer.Close(); err != nil {
		return err
	}

	return s.compressed.Close()
}

func addTarEntry(writer *tar.Writer, name string, info fs.FileInfo, link string, content io.Reader) error {
	header, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	header.Name = name
	if info.IsDir() {
		header.Name += "/"
	}
	// Names of users inside the container mean nothing elsewhere.
	header.Uname, header.Gname = "", ""

	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	if content == nil {
		return nil
	}
	copied, err := io.Copy(writer, content)
	if err == nil && copied != header.Size {
		err = fmt.Errorf("%s changed size while it was read", name)
	}

	return err
}

// writeTar writes a tree as tar entries named under prefix and reports how
// many special files it left out.
func writeTar(current *call, writer *tar.Writer, root *os.Root, rel, prefix string) (int64, error) {
	var skipped int64
	err := walk(current.ctx, root, rel, prefix, func(rel, name string, info fs.FileInfo) error {
		switch {
		case info.Mode().IsRegular():
			file, opened, err := openRegular(root, rel)
			if err != nil {
				return err
			}
			defer file.Close()
			return addTarEntry(writer, name, opened, "", io.LimitReader(file, opened.Size()))
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := root.Readlink(rel)
			if err != nil {
				return err
			}
			return addTarEntry(writer, name, info, link, nil)
		case info.IsDir():
			return addTarEntry(writer, name, info, "", nil)
		default:
			skipped++
			return nil
		}
	})

	return skipped, err
}

// extract unpacks a zip, tar, or tar.gz archive into a folder. It creates
// only folders and regular files, never overwrites what exists, and drops
// set-user-ID and set-group-ID bits.
func (m *mounts) extract(current *call, rawArchive, rawTo string) (Response, error) {
	source, err := m.resolve(rawArchive)
	if err != nil {
		return Response{}, err
	}
	if source.virtual {
		return Response{}, codedError(CodeNotRegularFile, source.path+" is not an archive")
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

	file, info, err := openRegular(source.mount.root, source.rel)
	if err != nil {
		return Response{}, err
	}
	defer file.Close()

	guard, err := newSpaceGuard(to.mount.root, to.rel)
	if err != nil {
		return Response{}, err
	}
	defer guard.close()

	extractor := &extractor{
		call:    current,
		root:    to.mount.root,
		base:    to.rel,
		owner:   toInfo,
		guard:   guard,
		tracker: &progress{call: current},
	}
	if err := extractor.run(file, info.Size()); err != nil {
		return Response{}, err
	}

	return Response{Skipped: extractor.skipped, Progress: &extractor.tracker.state}, nil
}

type extractor struct {
	call    *call
	root    *os.Root
	base    string
	owner   fs.FileInfo
	guard   *spaceGuard
	tracker *progress
	entries int
	written int64
	skipped int64
}

func (e *extractor) run(file *os.File, size int64) error {
	magic := make([]byte, 4)
	count, _ := file.ReadAt(magic, 0)
	magic = magic[:count]

	switch {
	case bytes.HasPrefix(magic, []byte("PK\x03\x04")) || bytes.HasPrefix(magic, []byte("PK\x05\x06")):
		return e.zip(file, size)
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		compressed, err := gzip.NewReader(io.NewSectionReader(file, 0, size))
		if err != nil {
			return codedError(CodeUnsupported, "the gzip data is damaged: "+err.Error())
		}
		defer compressed.Close()
		return e.tar(compressed)
	default:
		return e.tar(io.NewSectionReader(file, 0, size))
	}
}

func (e *extractor) zip(file *os.File, size int64) error {
	reader, err := zip.NewReader(file, size)
	if err != nil {
		return codedError(CodeUnsupported, "not a readable zip archive: "+err.Error())
	}

	for _, item := range reader.File {
		mode := item.Mode()
		switch {
		case mode.IsDir():
			if err := e.directory(item.Name, mode); err != nil {
				return err
			}
		case mode.IsRegular():
			content, err := item.Open()
			if err != nil {
				return err
			}
			err = e.file(item.Name, mode, content)
			content.Close()
			if err != nil {
				return err
			}
		default:
			e.skipped++
		}
	}

	return nil
}

func (e *extractor) tar(source io.Reader) error {
	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return codedError(CodeUnsupported, "not a readable tar archive: "+err.Error())
		}

		mode := header.FileInfo().Mode()
		switch header.Typeflag {
		case tar.TypeDir:
			err = e.directory(header.Name, mode)
		case tar.TypeReg:
			err = e.file(header.Name, mode, reader)
		default:
			e.skipped++
		}
		if err != nil {
			return err
		}
	}
}

// localName returns the path of an entry below the destination, or false
// when the name is absolute or climbs out with "..".
func (e *extractor) localName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.TrimPrefix(name, "./"), "/")
	if name == "" || strings.ContainsRune(name, 0) || !filepath.IsLocal(name) {
		return "", false
	}

	return path.Join(e.base, path.Clean(name)), true
}

func (e *extractor) count() error {
	if err := e.call.ctx.Err(); err != nil {
		return err
	}
	e.entries++
	if e.entries > maxExtractEntries {
		return codedError(CodeTooLarge, fmt.Sprintf("the archive has more than %d entries", maxExtractEntries))
	}

	return nil
}

func (e *extractor) directory(name string, mode fs.FileMode) error {
	if err := e.count(); err != nil {
		return err
	}
	rel, ok := e.localName(name)
	if !ok {
		e.skipped++
		return nil
	}

	if err := e.mkdirAll(rel, mode.Perm()|0o700); err != nil {
		return err
	}
	e.tracker.add(1, 0)

	return nil
}

func (e *extractor) file(name string, mode fs.FileMode, content io.Reader) error {
	if err := e.count(); err != nil {
		return err
	}
	rel, ok := e.localName(name)
	if !ok {
		e.skipped++
		return nil
	}
	if _, err := e.root.Lstat(rel); err == nil {
		e.skipped++
		return nil
	}
	if err := e.mkdirAll(path.Dir(rel), 0o755); err != nil {
		return err
	}

	file, err := e.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	budget := maxExtractBytes - e.written
	copied, err := io.Copy(e.guard.writer(file), io.LimitReader(contextReader{ctx: e.call.ctx, reader: content}, budget+1))
	e.written += copied
	if err == nil && copied > budget {
		err = codedError(CodeTooLarge, fmt.Sprintf("the archive unpacks to more than %d bytes", int64(maxExtractBytes)))
	}
	if err == nil {
		if uid, gid, ok := ownerOf(e.owner); ok {
			err = file.Chown(uid, gid)
		}
	}
	if err == nil {
		// Chown cleared nothing worth keeping; set the mode after it.
		err = file.Chmod(mode.Perm())
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = e.root.Remove(rel)
		return err
	}
	e.tracker.add(1, copied)

	return nil
}

// mkdirAll creates the missing folders of rel below the destination,
// owned like the destination. Every existing component must be a real
// folder: a symbolic link in the way is refused rather than followed.
func (e *extractor) mkdirAll(rel string, perm fs.FileMode) error {
	if rel == e.base {
		return nil
	}

	inside := rel
	if e.base != "." {
		inside = strings.TrimPrefix(rel, e.base+"/")
	}
	current := e.base
	for _, part := range strings.Split(inside, "/") {
		current = path.Join(current, part)
		info, err := e.root.Lstat(current)
		switch {
		case err == nil && info.IsDir():
			continue
		case err == nil:
			return codedError(CodeNotADirectory, path.Base(current)+" is in the way and is not a folder")
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}

		if err := e.root.Mkdir(current, perm); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		e.chown(current)
	}

	return nil
}

func (e *extractor) chown(rel string) {
	if uid, gid, ok := ownerOf(e.owner); ok {
		_ = e.root.Lchown(rel, uid, gid)
	}
}
