//go:build !windows

package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClaimTakesOverStateOfAnotherUserWithoutFollowingLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("taking over state needs root")
	}

	base := t.TempDir()
	dir := filepath.Join(base, "state")
	outside := filepath.Join(base, "outside")
	writeOwned(t, outside, 0o600, 65532)
	if err := os.MkdirAll(filepath.Join(dir, "metrics"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeOwned(t, filepath.Join(dir, "identity.json"), 0o600, 65532)
	writeOwned(t, filepath.Join(dir, "metrics", "hour.bin"), 0o600, 65532)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"metrics", "link", "."} {
		if err := os.Lchown(filepath.Join(dir, name), 65532, 65532); err != nil {
			t.Fatal(err)
		}
	}

	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Claim(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{".", "identity.json", "metrics", "metrics/hour.bin", "link"} {
		if uid, gid := ownerIDs(t, filepath.Join(dir, name)); uid != 0 || gid != 0 {
			t.Fatalf("%s is owned by %d:%d after Claim", name, uid, gid)
		}
	}
	if uid, _ := ownerIDs(t, outside); uid != 65532 {
		t.Fatalf("Claim followed a link out of the state directory: outside owner %d", uid)
	}
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Claim changed the file mode to %v", info.Mode().Perm())
	}
}

func TestClaimAcceptsMissingDirectory(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Claim(); err != nil {
		t.Fatal(err)
	}
}

func writeOwned(t *testing.T, path string, mode os.FileMode, uid int) {
	t.Helper()

	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, uid); err != nil {
		t.Fatal(err)
	}
}

func ownerIDs(t *testing.T, path string) (uint32, uint32) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)

	return stat.Uid, stat.Gid
}
