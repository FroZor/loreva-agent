//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type platformEnrollmentLock struct {
	file *os.File
}

func tryLockEnrollment(path string) (platformEnrollmentLock, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return platformEnrollmentLock{}, fmt.Errorf("open enrollment lock: %w", err)
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		closeErr := unix.Close(fd)
		return platformEnrollmentLock{}, errors.Join(errors.New("open enrollment lock handle"), closeErr)
	}

	closeOnError := func(lockErr error) (platformEnrollmentLock, error) {
		return platformEnrollmentLock{}, errors.Join(lockErr, file.Close())
	}

	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return closeOnError(fmt.Errorf("inspect enrollment lock: %w", err))
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG {
		return closeOnError(errors.New("enrollment lock must be a regular file, not a link"))
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return closeOnError(fmt.Errorf("secure enrollment lock: %w", err))
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return closeOnError(ErrEnrollmentLocked)
		}

		return closeOnError(fmt.Errorf("lock enrollment state: %w", err))
	}

	return platformEnrollmentLock{file: file}, nil
}

func (l platformEnrollmentLock) close() error {
	if l.file == nil {
		return nil
	}

	unlockErr := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()

	return errors.Join(unlockErr, closeErr)
}
