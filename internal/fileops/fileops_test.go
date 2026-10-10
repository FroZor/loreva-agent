//go:build linux

package fileops

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	client *Client
	base   string
	data   string
	config string
}

// newFixture serves a read-write mount data, a read-only mount config, and
// a file outside both, over in-memory pipes.
func newFixture(t *testing.T) *fixture {
	t.Helper()

	base := t.TempDir()
	data := filepath.Join(base, "srv", "data")
	config := filepath.Join(base, "srv", "config")
	for _, dir := range []string{data, config} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(base, "secret.txt"), "outside")
	writeFile(t, filepath.Join(config, "app.yml"), "port: 1")

	client := serve(t, []Mount{{Path: data}, {Path: config, ReadOnly: true}})

	return &fixture{client: client, base: base, data: data, config: config}
}

// serve runs a helper for mounts over in-memory pipes.
func serve(t *testing.T, mounts []Mount) *Client {
	t.Helper()

	helperIn, agentOut := io.Pipe()
	agentIn, helperOut := io.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- Serve(helperIn, helperOut)
		helperOut.Close()
	}()
	client := NewClient(agentIn, agentOut)
	t.Cleanup(func() {
		agentOut.Close()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Init(ctx, mounts); err != nil {
		t.Fatalf("Init: %v", err)
	}

	return client
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	return ctx
}

func (f *fixture) do(t *testing.T, request Request) Response {
	t.Helper()

	response, err := f.client.Do(testContext(t), request)
	if err != nil {
		t.Fatalf("%s: %v", request.Op, err)
	}

	return response
}

func (f *fixture) mustOK(t *testing.T, request Request) Response {
	t.Helper()

	response := f.do(t, request)
	if !response.OK {
		t.Fatalf("%s %s: %s: %s", request.Op, request.Path, response.Code, response.Message)
	}

	return response
}

func (f *fixture) mustFail(t *testing.T, request Request, code string) {
	t.Helper()

	response := f.do(t, request)
	if response.OK || response.Code != code {
		t.Fatalf("%s %s = ok %v code %q (%s), want code %q", request.Op, request.Path, response.OK, response.Code, response.Message, code)
	}
}

// upload writes content with the write operation.
func (f *fixture) upload(t *testing.T, target, content, expected string) Response {
	t.Helper()

	sum := sha256.Sum256([]byte(content))
	call, err := f.client.Start(Request{Op: OpWrite, Path: target, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), ExpectedVersion: expected})
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()

	ctx := testContext(t)
	ready, err := call.Response(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ready.OK {
		return ready
	}
	if err := call.Write(ctx, []byte(content[ready.Offset:])); err != nil {
		t.Fatal(err)
	}
	final, err := call.Response(ctx)
	if err != nil {
		t.Fatal(err)
	}

	return final
}

// download reads a file or folder with the read operation.
func (f *fixture) download(t *testing.T, target string, offset int64) (Response, []byte) {
	t.Helper()

	call, err := f.client.Start(Request{Op: OpRead, Path: target, Offset: offset})
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()

	ctx := testContext(t)
	opened, err := call.Response(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.OK {
		return opened, nil
	}

	var content bytes.Buffer
	buffer := make([]byte, 64*1024)
	for {
		count, err := call.Read(ctx, buffer)
		content.Write(buffer[:count])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read %s: %v", target, err)
		}
	}
	final, err := call.Response(ctx)
	if err != nil || !final.OK {
		t.Fatalf("read %s final = %+v, %v", target, final, err)
	}

	return opened, content.Bytes()
}

func names(entries []Entry) []string {
	var result []string
	for _, entry := range entries {
		result = append(result, entry.Name)
	}

	return result
}

func TestListShowsOnlyMounts(t *testing.T) {
	f := newFixture(t)

	response := f.mustOK(t, Request{Op: OpList, Path: f.base})
	if got := names(response.Entries); !slices.Equal(got, []string{"srv"}) {
		t.Fatalf("list base = %v, want only the folder leading to mounts", got)
	}
	if !response.Entries[0].Virtual {
		t.Fatal("srv is not marked virtual")
	}

	response = f.mustOK(t, Request{Op: OpList, Path: filepath.Join(f.base, "srv")})
	if got := names(response.Entries); !slices.Equal(got, []string{"config", "data"}) {
		t.Fatalf("list srv = %v", got)
	}
	for _, entry := range response.Entries {
		if !entry.Mount {
			t.Fatalf("%s is not marked as a mount", entry.Name)
		}
	}
	if !response.Entries[0].ReadOnly {
		t.Fatal("config is not marked read-only")
	}
}

func TestListPages(t *testing.T) {
	f := newFixture(t)
	for index := range listPageEntries + 5 {
		writeFile(t, filepath.Join(f.data, fmt.Sprintf("file-%04d", index)), "")
	}

	first := f.mustOK(t, Request{Op: OpList, Path: f.data})
	if len(first.Entries) != listPageEntries || !first.More {
		t.Fatalf("first page = %d entries, more %v", len(first.Entries), first.More)
	}
	second := f.mustOK(t, Request{Op: OpList, Path: f.data, After: first.Entries[len(first.Entries)-1].Name})
	if len(second.Entries) != 5 || second.More {
		t.Fatalf("second page = %d entries, more %v", len(second.Entries), second.More)
	}
}

func TestPathsCannotLeaveMounts(t *testing.T) {
	f := newFixture(t)
	if err := os.Symlink("/etc", filepath.Join(f.data, "absolute")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../..", filepath.Join(f.data, "relative")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		code string
	}{
		{"file outside mounts", filepath.Join(f.base, "secret.txt"), CodeOutsideMounts},
		{"dot-dot out of the mount", filepath.Join(f.data, "..", "..", "secret.txt"), CodeOutsideMounts},
		{"absolute symbolic link", filepath.Join(f.data, "absolute", "passwd"), CodeOutsideMounts},
		{"relative symbolic link", filepath.Join(f.data, "relative", "secret.txt"), CodeOutsideMounts},
		{"relative path", "data/file", CodeInvalidPath},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response, _ := f.download(t, test.path, 0)
			if response.OK || response.Code != test.code {
				t.Fatalf("read = ok %v code %q (%s), want %q", response.OK, response.Code, response.Message, test.code)
			}
		})
	}
}

func TestWriteAndReadBack(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.data, "server.properties")
	content := strings.Repeat("motd=hello\n", 50_000)

	written := f.upload(t, target, content, VersionAbsent)
	if !written.OK || written.Entry == nil || written.Entry.Size != int64(len(content)) {
		t.Fatalf("write = %+v", written)
	}

	opened, got := f.download(t, target, 0)
	if string(got) != content || opened.Entry.Version != written.Entry.Version {
		t.Fatalf("read back %d bytes with version %s, want %d bytes with %s", len(got), opened.Entry.Version, len(content), written.Entry.Version)
	}
	_, tail := f.download(t, target, int64(len(content)-11))
	if string(tail) != "motd=hello\n" {
		t.Fatalf("read from offset = %q", tail)
	}

	if response := f.upload(t, target, "changed", VersionAbsent); response.Code != CodeVersionConflict {
		t.Fatalf("write over an existing file with absent = %+v", response)
	}
	if response := f.upload(t, target, "changed", "1-1"); response.Code != CodeVersionConflict {
		t.Fatalf("write with a stale version = %+v", response)
	}
	if response := f.upload(t, target, "changed", written.Entry.Version); !response.OK {
		t.Fatalf("write with the current version = %+v", response)
	}

	partials, _ := filepath.Glob(filepath.Join(f.data, uploadPrefix+"*"))
	if len(partials) != 0 {
		t.Fatalf("partial files left behind: %v", partials)
	}
}

func TestWriteRejectsBadChecksum(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.data, "file.txt")

	call, err := f.client.Start(Request{Op: OpWrite, Path: target, Size: 5, SHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	ctx := testContext(t)
	if ready, err := call.Response(ctx); err != nil || !ready.OK {
		t.Fatalf("ready = %+v, %v", ready, err)
	}
	if err := call.Write(ctx, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	final, err := call.Response(ctx)
	if err != nil || final.Code != CodeChecksumMismatch {
		t.Fatalf("final = %+v, %v", final, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target exists after a failed write: %v", err)
	}
}

func TestWriteResumes(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.data, "world.bin")
	content := bytes.Repeat([]byte("0123456789abcdef"), 64*1024)
	sum := sha256.Sum256(content)
	request := Request{Op: OpWrite, Path: target, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	ctx := testContext(t)

	call, err := f.client.Start(request)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := call.Response(ctx); err != nil || !ready.OK || ready.Offset != 0 {
		t.Fatalf("first ready = %+v, %v", ready, err)
	}
	half := len(content) / 2
	if err := call.Write(ctx, content[:half]); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(f.data, uploadName(target, request.SHA256, request.Size))
	waitFor(t, func() bool {
		info, err := os.Stat(partial)
		return err == nil && info.Size() == int64(half)
	})
	call.Close()

	call, err = f.client.Start(request)
	if err != nil {
		t.Fatal(err)
	}
	defer call.Close()
	ready, err := call.Response(ctx)
	if err != nil || !ready.OK || ready.Offset != int64(half) {
		t.Fatalf("resumed ready = %+v, %v, want offset %d", ready, err, half)
	}
	if err := call.Write(ctx, content[half:]); err != nil {
		t.Fatal(err)
	}
	if final, err := call.Response(ctx); err != nil || !final.OK {
		t.Fatalf("resumed final = %+v, %v", final, err)
	}

	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("resumed file differs: %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadOnlyMountRefusesChanges(t *testing.T) {
	f := newFixture(t)
	file := filepath.Join(f.config, "app.yml")

	if response := f.upload(t, file, "port: 2", ""); response.Code != CodeReadOnly {
		t.Fatalf("write = %+v", response)
	}
	f.mustFail(t, Request{Op: OpDelete, Paths: []string{file}}, CodeReadOnly)
	f.mustFail(t, Request{Op: OpMkdir, Path: filepath.Join(f.config, "new")}, CodeReadOnly)
	_, content := f.download(t, file, 0)
	if string(content) != "port: 1" {
		t.Fatalf("read-only file = %q", content)
	}
}

func TestMountRootsStay(t *testing.T) {
	f := newFixture(t)

	f.mustFail(t, Request{Op: OpDelete, Paths: []string{f.data}}, CodeMountRoot)
	f.mustFail(t, Request{Op: OpRename, Path: f.data, To: f.data + "2"}, CodeMountRoot)
	f.mustFail(t, Request{Op: OpMkdir, Path: filepath.Join(f.base, "srv", "new")}, CodeOutsideMounts)
}

func TestManageFiles(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "a.txt"), "a")

	folder := filepath.Join(f.data, "plugins")
	created := f.mustOK(t, Request{Op: OpMkdir, Path: folder})
	if created.Entry.Type != TypeDirectory {
		t.Fatalf("mkdir entry = %+v", created.Entry)
	}
	f.mustFail(t, Request{Op: OpMkdir, Path: folder}, CodeAlreadyExists)

	f.mustOK(t, Request{Op: OpRename, Path: filepath.Join(f.data, "a.txt"), To: filepath.Join(folder, "b.txt")})
	f.mustFail(t, Request{Op: OpRename, Path: folder, To: filepath.Join(folder, "inner")}, CodeInvalidPath)

	chmod := f.mustOK(t, Request{Op: OpChmod, Path: filepath.Join(folder, "b.txt"), Mode: 0o600})
	if chmod.Entry.Mode != 0o600 {
		t.Fatalf("mode = %o", chmod.Entry.Mode)
	}
	f.mustFail(t, Request{Op: OpChmod, Path: filepath.Join(folder, "b.txt"), Mode: 0o4755}, CodeInvalidRequest)

	copied := f.mustOK(t, Request{Op: OpCopy, Paths: []string{folder}, To: f.data})
	if got := names(copied.Entries); !slices.Equal(got, []string{"plugins (1)"}) {
		t.Fatalf("copy created %v", got)
	}
	again := f.mustOK(t, Request{Op: OpCopy, Paths: []string{filepath.Join(folder, "b.txt")}, To: folder})
	if got := names(again.Entries); !slices.Equal(got, []string{"b (1).txt"}) {
		t.Fatalf("copy of a file created %v", got)
	}
	f.mustFail(t, Request{Op: OpCopy, Paths: []string{folder}, To: folder}, CodeInvalidPath)
	if content, err := os.ReadFile(filepath.Join(f.data, "plugins (1)", "b.txt")); err != nil || string(content) != "a" {
		t.Fatalf("copied file = %q, %v", content, err)
	}

	f.mustOK(t, Request{Op: OpDelete, Paths: []string{folder, filepath.Join(f.data, "plugins (1)")}})
	if list := f.mustOK(t, Request{Op: OpList, Path: f.data}); len(list.Entries) != 0 {
		t.Fatalf("after delete: %v", names(list.Entries))
	}
}

func TestArchiveAndExtract(t *testing.T) {
	for _, format := range []string{FormatZip, FormatTarGz} {
		t.Run(format, func(t *testing.T) {
			f := newFixture(t)
			world := filepath.Join(f.data, "world")
			if err := os.MkdirAll(filepath.Join(world, "region"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(world, "level.dat"), "level")
			writeFile(t, filepath.Join(world, "region", "r.0.0.mca"), strings.Repeat("x", 100_000))
			writeFile(t, filepath.Join(f.data, "ops.json"), "[]")

			archivePath := filepath.Join(f.data, "backup."+format)
			packed := f.mustOK(t, Request{Op: OpArchive, Paths: []string{world, filepath.Join(f.data, "ops.json")}, To: archivePath, Format: format})
			if packed.Entry == nil || packed.Entry.Size == 0 {
				t.Fatalf("archive entry = %+v", packed.Entry)
			}
			f.mustFail(t, Request{Op: OpArchive, Paths: []string{world}, To: archivePath, Format: format}, CodeAlreadyExists)

			restore := filepath.Join(f.data, "restore")
			f.mustOK(t, Request{Op: OpMkdir, Path: restore})
			f.mustOK(t, Request{Op: OpExtract, Path: archivePath, To: restore})
			for name, want := range map[string]string{
				"world/level.dat":        "level",
				"world/region/r.0.0.mca": strings.Repeat("x", 100_000),
				"ops.json":               "[]",
			} {
				got, err := os.ReadFile(filepath.Join(restore, name))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %d bytes, %v", name, len(got), err)
				}
			}

			again := f.mustOK(t, Request{Op: OpExtract, Path: archivePath, To: restore})
			if again.Skipped != 3 {
				t.Fatalf("second extraction skipped %d files, want 3 existing ones", again.Skipped)
			}
		})
	}
}

func TestExtractRefusesEscapes(t *testing.T) {
	f := newFixture(t)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	entries := []struct {
		header  tar.Header
		content string
	}{
		{tar.Header{Name: "../escape.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}, "x"},
		{tar.Header{Name: "/abs.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}, "x"},
		{tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}, ""},
		{tar.Header{Name: "setuid", Mode: 0o4755, Size: 2, Typeflag: tar.TypeReg}, "ok"},
	}
	for _, entry := range entries {
		if err := writer.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	writer.Close()
	if err := os.WriteFile(filepath.Join(f.data, "evil.tar"), archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.data, "out")
	f.mustOK(t, Request{Op: OpMkdir, Path: target})

	response := f.mustOK(t, Request{Op: OpExtract, Path: filepath.Join(f.data, "evil.tar"), To: target})
	if response.Skipped != 3 {
		t.Fatalf("skipped %d entries, want 3", response.Skipped)
	}
	if _, err := os.Stat(filepath.Join(f.data, "escape.txt")); err == nil {
		t.Fatal("an entry escaped the destination")
	}
	info, err := os.Stat(filepath.Join(target, "setuid"))
	if err != nil || info.Mode()&os.ModeSetuid != 0 {
		t.Fatalf("setuid file = %v, %v", info, err)
	}
}

func TestReadFolderAsTar(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "one.txt"), "1")
	if err := os.Mkdir(filepath.Join(f.data, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.data, "sub", "two.txt"), "22")

	_, content := f.download(t, f.data, 0)
	reader := tar.NewReader(bytes.NewReader(content))
	var got []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, header.Name)
	}
	want := []string{"data/", "data/one.txt", "data/sub/", "data/sub/two.txt"}
	if !slices.Equal(got, want) {
		t.Fatalf("tar entries = %v, want %v", got, want)
	}
}

func TestZipSkipsSymlinks(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "real.txt"), "r")
	if err := os.Symlink("real.txt", filepath.Join(f.data, "link.txt")); err != nil {
		t.Fatal(err)
	}

	response := f.mustOK(t, Request{Op: OpArchive, Paths: []string{filepath.Join(f.data, "real.txt"), filepath.Join(f.data, "link.txt")}, To: filepath.Join(f.data, "out.zip"), Format: FormatZip})
	if response.Skipped != 1 {
		t.Fatalf("skipped = %d, want the symbolic link", response.Skipped)
	}
	reader, err := zip.OpenReader(filepath.Join(f.data, "out.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 1 || reader.File[0].Name != "real.txt" {
		t.Fatalf("zip holds %d files", len(reader.File))
	}
}
