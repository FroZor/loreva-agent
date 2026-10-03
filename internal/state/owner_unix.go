//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// CheckOwner fails when the state directory exists and belongs to another
// user. It stops root from creating state files the service cannot read.
func (s *Store) CheckOwner() error {
	info, err := os.Stat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) == os.Geteuid() {
		return nil
	}

	owner := strconv.FormatUint(uint64(stat.Uid), 10)
	if account, err := user.LookupId(owner); err == nil {
		owner = account.Username
	}

	return fmt.Errorf("state directory %s belongs to user %s; run the command as that user, for example: sudo -u %s loreva-agent <command> --state-dir %s",
		s.dir, owner, owner, s.dir)
}
