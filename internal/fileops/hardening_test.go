package fileops

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCopyIntoItselfThroughLinkIsRefused(t *testing.T) {
	f := newFixture(t)
	source := filepath.Join(f.data, "a")
	if err := os.MkdirAll(filepath.Join(source, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a/b", filepath.Join(f.data, "link")); err != nil {
		t.Fatal(err)
	}

	f.mustFail(t, Request{Op: OpCopy, Paths: []string{source}, To: filepath.Join(f.data, "link")}, CodeInvalidPath)
	f.mustOK(t, Request{Op: OpCopy, Paths: []string{filepath.Join(source, "b")}, To: f.data})
}

func TestNestedMounts(t *testing.T) {
	base := t.TempDir()
	outer := filepath.Join(base, "data")
	inner := filepath.Join(outer, "dir", "db")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(inner, "table"), "rows")
	f := &fixture{client: serve(t, []Mount{{Path: outer}, {Path: inner}}), base: base, data: outer}

	f.mustFail(t, Request{Op: OpDelete, Paths: []string{filepath.Join(outer, "dir")}}, CodeMountRoot)
	f.mustFail(t, Request{Op: OpRename, Path: filepath.Join(outer, "dir"), To: filepath.Join(outer, "moved")}, CodeMountRoot)
	f.mustFail(t, Request{Op: OpCopy, Paths: []string{outer}, To: inner}, CodeInvalidPath)
	if content, err := os.ReadFile(filepath.Join(inner, "table")); err != nil || string(content) != "rows" {
		t.Fatalf("nested mount content = %q, %v", content, err)
	}
}

func TestUploadIgnoresPlantedPartialLink(t *testing.T) {
	f := newFixture(t)
	victim := filepath.Join(f.data, "victim.txt")
	writeFile(t, victim, "keep")
	target := filepath.Join(f.data, "upload.txt")
	content := "new content"
	sum := sha256Hex(content)
	if err := os.Symlink("victim.txt", filepath.Join(f.data, uploadName(target, sum, int64(len(content))))); err != nil {
		t.Fatal(err)
	}

	if response := f.upload(t, target, content, ""); !response.OK {
		t.Fatalf("upload = %+v", response)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Fatalf("victim = %q, the upload followed a planted link", got)
	}
	if got, _ := os.ReadFile(target); string(got) != content {
		t.Fatalf("target = %q", got)
	}
}

func TestChmodRefusesLinks(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "real"), "x")
	if err := os.Symlink("real", filepath.Join(f.data, "link")); err != nil {
		t.Fatal(err)
	}

	f.mustFail(t, Request{Op: OpChmod, Path: filepath.Join(f.data, "link"), Mode: 0o777}, CodeNotRegularFile)
	if info, _ := os.Stat(filepath.Join(f.data, "real")); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode through link = %o", info.Mode().Perm())
	}
}

func TestExtractRefusesLinkInTheWay(t *testing.T) {
	f := newFixture(t)
	world := filepath.Join(f.data, "world")
	if err := os.MkdirAll(world, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(world, "level.dat"), "level")
	archive := filepath.Join(f.data, "world.tar.gz")
	f.mustOK(t, Request{Op: OpArchive, Paths: []string{world}, To: archive, Format: FormatTarGz})

	out := filepath.Join(f.data, "out")
	elsewhere := filepath.Join(f.data, "elsewhere")
	for _, dir := range []string{out, elsewhere} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../elsewhere", filepath.Join(out, "world")); err != nil {
		t.Fatal(err)
	}

	f.mustFail(t, Request{Op: OpExtract, Path: archive, To: out}, CodeNotADirectory)
	if _, err := os.Stat(filepath.Join(elsewhere, "level.dat")); err == nil {
		t.Fatal("extraction followed a link in the way")
	}
}

func TestVersionNoticesRestoredModificationTime(t *testing.T) {
	f := newFixture(t)
	name := filepath.Join(f.data, "config.yml")
	writeFile(t, name, "a: 1")
	before := f.mustOK(t, Request{Op: OpStat, Path: name}).Entry

	info, _ := os.Stat(name)
	time.Sleep(10 * time.Millisecond)
	writeFile(t, name, "a: 2")
	if err := os.Chtimes(name, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}

	if response := f.upload(t, name, "a: 3", before.Version); response.Code != CodeVersionConflict {
		t.Fatalf("save over a same-size edit with restored mtime = %+v", response)
	}
}

func TestRenameDoesNotReplace(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.data, "a"), "a")
	writeFile(t, filepath.Join(f.data, "b"), "b")

	f.mustFail(t, Request{Op: OpRename, Path: filepath.Join(f.data, "a"), To: filepath.Join(f.data, "b")}, CodeAlreadyExists)
	if got, _ := os.ReadFile(filepath.Join(f.data, "b")); string(got) != "b" {
		t.Fatalf("b = %q", got)
	}
}

func TestInboxDropsDataAfterClose(t *testing.T) {
	inbox := NewInbox(4)
	inbox.Close(nil)
	if err := inbox.Put([]byte("x")); err == ErrWindowExceeded {
		t.Fatal("a closed inbox reports a window violation")
	}
	if err := NewInbox(1).Put([]byte("xx")); err != ErrWindowExceeded {
		t.Fatalf("overflow = %v", err)
	}
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))

	return hex.EncodeToString(sum[:])
}
