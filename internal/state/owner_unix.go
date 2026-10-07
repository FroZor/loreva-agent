//go:build !windows

package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Claim makes the state directory usable by the current process. Root takes
// over every entry that belongs to another user, as official database images
// do with their data on start: state written by an earlier release that ran
// as a dedicated user stays readable without a manual step. Root needs only
// CAP_CHOWN for that, because each directory is handed over before it is read.
// Any other user gets an error when the directory belongs to someone else, so
// it never creates state files the service cannot read.
func (s *Store) Claim() error {
	info, err := os.Stat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("state directory %s is not a directory", s.dir)
	}

	uid := os.Geteuid()
	owner, ok := ownerOf(info)
	if uid != 0 {
		if !ok || owner == uid {
			return nil
		}

		return foreignOwnerError(s.dir, owner)
	}

	return s.claimAsRoot(info)
}

func (s *Store) claimAsRoot(info os.FileInfo) error {
	if err := claimEntry(s.dir, info, os.Chown); err != nil {
		return fmt.Errorf("take over state directory %s: %w", s.dir, err)
	}

	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer root.Close()

	// os.Root keeps every step inside the state directory, so a symbolic
	// link planted by the previous owner cannot redirect the walk or the
	// ownership change. WalkDir visits a directory before reading it, which
	// lets root read a directory that was private to the previous owner.
	err = fs.WalkDir(root.FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}

		info, err := root.Lstat(name)
		if err != nil {
			return err
		}

		return claimEntry(name, info, root.Lchown)
	})
	if err != nil {
		return fmt.Errorf("take over state directory %s: %w", s.dir, err)
	}

	return nil
}

// claimEntry gives one entry to root unless it already belongs to root.
func claimEntry(name string, info os.FileInfo, lchown func(string, int, int) error) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && stat.Uid == 0 && stat.Gid == 0 {
		return nil
	}

	return lchown(name, 0, 0)
}

func ownerOf(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}

	return int(stat.Uid), true
}

func foreignOwnerError(dir string, uid int) error {
	owner := strconv.Itoa(uid)
	if account, err := user.LookupId(owner); err == nil {
		owner = account.Username
	}

	return fmt.Errorf("state directory %s belongs to user %s; run the command as that user or as root, for example: sudo loreva-agent <command> --state-dir %s",
		dir, owner, dir)
}
