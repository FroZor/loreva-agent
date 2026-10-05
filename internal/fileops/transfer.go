package fileops

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

const (
	// uploadPrefix names the partial files of uploads that can resume.
	uploadPrefix = ".loreva-upload-"
	// tempPrefix names the files an archive is written to before it is
	// renamed into place.
	tempPrefix = ".loreva-tmp-"
	// staleUploadAge is when an abandoned partial upload is removed.
	staleUploadAge = 7 * 24 * time.Hour
	// maxFileMountWrite bounds a write to a bind-mounted single file, which
	// is buffered in memory because it cannot be replaced by a rename.
	maxFileMountWrite = 16 * 1024 * 1024
)

// read sends a file from offset, or a directory as a tar stream. The first
// response describes what is sent; the final one follows the data.
func (m *mounts) read(current *call, raw string, offset int64) (Response, error) {
	resolved, err := m.resolve(raw)
	if err != nil {
		return Response{}, err
	}
	if resolved.virtual {
		return Response{}, codedError(CodeOutsideMounts, "only volumes and mounted folders can be read")
	}
	if offset < 0 {
		return Response{}, codedError(CodeInvalidRequest, "offset must not be negative")
	}

	info, err := resolved.mount.root.Lstat(resolved.rel)
	if err != nil {
		return Response{}, err
	}
	switch {
	case info.IsDir():
		if offset != 0 {
			return Response{}, codedError(CodeInvalidRequest, "a folder is sent as a whole")
		}
		return m.readTree(current, resolved, info)
	case !info.Mode().IsRegular():
		return Response{}, codedError(CodeNotRegularFile, resolved.path+" is not a regular file")
	}

	file, info, err := openRegular(resolved.mount.root, resolved.rel)
	if err != nil {
		return Response{}, err
	}
	defer file.Close()

	if offset > info.Size() {
		return Response{}, codedError(CodeInvalidRequest, "offset is past the end of the file")
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return Response{}, err
	}

	entry := m.entry(resolved, info)
	if err := current.server.respond(current.id, Response{OK: true, Entry: &entry, Offset: offset}); err != nil {
		return Response{}, err
	}
	// Only the size announced in the entry is sent, even if the file grows.
	content := io.LimitReader(file, info.Size()-offset)
	if _, err := io.CopyBuffer(dataWriter{call: current}, content, make([]byte, DataChunkBytes)); err != nil {
		return Response{}, err
	}

	return Response{}, nil
}

// readTree sends a directory as an uncompressed tar stream, so a folder of
// many small files arrives as one transfer.
func (m *mounts) readTree(current *call, resolved target, info fs.FileInfo) (Response, error) {
	entry := m.entry(resolved, info)
	if err := current.server.respond(current.id, Response{OK: true, Entry: &entry}); err != nil {
		return Response{}, err
	}

	writer := tar.NewWriter(dataWriter{call: current})
	skipped, err := writeTar(current, writer, resolved.mount.root, resolved.rel, path.Base(resolved.path))
	if err != nil {
		return Response{}, err
	}
	if err := writer.Close(); err != nil {
		return Response{}, err
	}

	return Response{Skipped: skipped}, nil
}

// write receives a file and replaces the target atomically: content goes to
// a partial file next to it, is checked against the digest, and is renamed
// over the target. A partial file survives a broken connection, so the same
// upload resumes where it stopped.
func (m *mounts) write(current *call, request Request) (Response, error) {
	if request.Size < 0 {
		return Response{}, codedError(CodeInvalidRequest, "size must not be negative")
	}
	digest, err := hex.DecodeString(request.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return Response{}, codedError(CodeInvalidRequest, "sha256 must be 64 hex characters")
	}
	if request.Mode > 0o777 {
		return Response{}, codedError(CodeInvalidRequest, "mode may only carry the read, write, and execute bits (0 to 0777)")
	}

	resolved, err := m.resolveWritable(request.Path)
	if err != nil {
		return Response{}, err
	}
	existing, err := resolved.mount.root.Lstat(resolved.rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		existing = nil
	case err != nil:
		return Response{}, err
	case existing.IsDir():
		return Response{}, codedError(CodeIsADirectory, resolved.path+" is a folder")
	case !existing.Mode().IsRegular():
		return Response{}, codedError(CodeNotRegularFile, resolved.path+" is not a regular file")
	}
	if err := checkVersion(existing, request.ExpectedVersion); err != nil {
		return Response{}, err
	}

	if resolved.mount.file {
		return m.writeInPlace(current, resolved, request, digest)
	}
	if m.isMountRoot(resolved.path) {
		return Response{}, codedError(CodeMountRoot, resolved.path+" is a mount")
	}

	return m.writeReplace(current, resolved, request, digest, existing)
}

func (m *mounts) writeReplace(current *call, resolved target, request Request, digest []byte, existing fs.FileInfo) (Response, error) {
	root := resolved.mount.root
	dir := path.Dir(resolved.rel)
	removeStaleUploads(root, dir)

	partial := path.Join(dir, uploadName(resolved.path, request.SHA256, request.Size))
	file, offset, err := openPartial(root, partial, request.Size)
	if err != nil {
		return Response{}, err
	}
	keep := true
	defer func() {
		file.Close()
		if !keep {
			_ = root.Remove(partial)
		}
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, offset)); err != nil {
		return Response{}, err
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return Response{}, err
	}
	if err := current.server.respond(current.id, Response{OK: true, Offset: offset}); err != nil {
		return Response{}, err
	}

	if err := receive(current, io.MultiWriter(file, hash), request.Size-offset); err != nil {
		return Response{}, err
	}
	if !equalDigest(hash.Sum(nil), digest) {
		keep = false
		return Response{}, codedError(CodeChecksumMismatch, "the received file does not match sha256")
	}
	if err := file.Sync(); err != nil {
		return Response{}, err
	}

	// The target may have changed while the content was on its way.
	latest, err := root.Lstat(resolved.rel)
	if errors.Is(err, fs.ErrNotExist) {
		latest = nil
	} else if err != nil {
		return Response{}, err
	}
	if err := checkVersion(latest, request.ExpectedVersion); err != nil {
		keep = false
		return Response{}, err
	}

	applyMetadata(root, partial, resolved.rel, latest, request.Mode)
	if err := root.Rename(partial, resolved.rel); err != nil {
		return Response{}, err
	}

	entry, err := m.entryAt(resolved.path)
	if err != nil {
		return Response{}, err
	}

	return Response{Entry: &entry}, nil
}

// writeInPlace writes a bind-mounted single file, which cannot be renamed
// over: the content is collected and checked first, then written.
func (m *mounts) writeInPlace(current *call, resolved target, request Request, digest []byte) (Response, error) {
	if request.Size > maxFileMountWrite {
		return Response{}, codedError(CodeTooLarge, fmt.Sprintf("a mounted single file can be written up to %d bytes", maxFileMountWrite))
	}
	if err := current.server.respond(current.id, Response{OK: true}); err != nil {
		return Response{}, err
	}

	var content strings.Builder
	if err := receive(current, &content, request.Size); err != nil {
		return Response{}, err
	}
	sum := sha256.Sum256([]byte(content.String()))
	if !equalDigest(sum[:], digest) {
		return Response{}, codedError(CodeChecksumMismatch, "the received file does not match sha256")
	}

	file, err := resolved.mount.root.OpenFile(resolved.rel, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return Response{}, err
	}
	defer file.Close()
	if _, err := io.WriteString(file, content.String()); err != nil {
		return Response{}, err
	}
	if err := file.Sync(); err != nil {
		return Response{}, err
	}

	entry, err := m.entryAt(resolved.path)
	if err != nil {
		return Response{}, err
	}

	return Response{Entry: &entry}, nil
}

// receive copies exactly size bytes of content from the agent.
func receive(current *call, writer io.Writer, size int64) error {
	reader := &dataReader{call: current}
	copied, err := io.CopyBuffer(writer, io.LimitReader(reader, size), make([]byte, DataChunkBytes))
	if err != nil {
		return err
	}
	if copied < size {
		return codedError(CodeInvalidRequest, fmt.Sprintf("the content ended after %d of %d bytes", copied, size))
	}

	return nil
}

func checkVersion(info fs.FileInfo, expected string) error {
	switch {
	case expected == "":
		return nil
	case expected == VersionAbsent && info == nil:
		return nil
	case expected == VersionAbsent:
		return codedError(CodeVersionConflict, "the file already exists")
	case info == nil:
		return codedError(CodeVersionConflict, "the file no longer exists")
	case version(info) != expected:
		return codedError(CodeVersionConflict, "the file changed since it was opened")
	default:
		return nil
	}
}

// uploadName derives the partial file name from what is uploaded, so only
// a retry of the same upload resumes it.
func uploadName(target, digest string, size int64) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d", target, strings.ToLower(digest), size))

	return uploadPrefix + hex.EncodeToString(sum[:12])
}

func openPartial(root *os.Root, partial string, size int64) (*os.File, int64, error) {
	info, err := root.Lstat(partial)
	if err == nil && info.Mode().IsRegular() && info.Size() <= size {
		file, err := root.OpenFile(partial, os.O_RDWR, 0)
		if err == nil {
			return file, info.Size(), nil
		}
	}
	if err == nil {
		// Not resumable: replace it.
		if err := root.Remove(partial); err != nil {
			return nil, 0, err
		}
	}

	file, err := root.OpenFile(partial, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)

	return file, 0, err
}

// removeStaleUploads drops partial uploads abandoned in dir long ago.
func removeStaleUploads(root *os.Root, dir string) {
	directory, err := root.Open(dir)
	if err != nil {
		return
	}
	defer directory.Close()

	entries, err := directory.ReadDir(maxDirectoryEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	for _, item := range entries {
		if !strings.HasPrefix(item.Name(), uploadPrefix) && !strings.HasPrefix(item.Name(), tempPrefix) {
			continue
		}
		info, err := item.Info()
		if err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) > staleUploadAge {
			_ = root.Remove(path.Join(dir, item.Name()))
		}
	}
}

// applyMetadata gives a new file the mode and owner of the file it replaces,
// or of its parent directory when it is new.
func applyMetadata(root *os.Root, name, target string, replaced fs.FileInfo, mode uint32) {
	perm := fs.FileMode(0o644)
	owner := replaced
	switch {
	case mode != 0:
		perm = fs.FileMode(mode)
	case replaced != nil:
		perm = replaced.Mode().Perm()
	}
	if owner == nil {
		owner, _ = root.Stat(path.Dir(target))
	}

	_ = root.Chmod(name, perm)
	if owner != nil {
		if stat, ok := owner.Sys().(*syscall.Stat_t); ok {
			_ = root.Lchown(name, int(stat.Uid), int(stat.Gid))
		}
	}
}

func equalDigest(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func tempName() string {
	return tempPrefix + rand.Text()
}
