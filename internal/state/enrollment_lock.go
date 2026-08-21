package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const enrollmentLockName = ".enrollment.lock"

// ErrEnrollmentLocked indicates that another process is enrolling this state directory.
var ErrEnrollmentLocked = errors.New("agent enrollment is already running")

// EnrollmentLock serializes enrollment transactions that use the same state directory.
type EnrollmentLock struct {
	platform platformEnrollmentLock
	closed   bool
}

// TryLockEnrollment acquires the enrollment lock without waiting.
func (s *Store) TryLockEnrollment() (*EnrollmentLock, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := secureDirectory(s.dir); err != nil {
		return nil, fmt.Errorf("secure state directory: %w", err)
	}

	platform, err := tryLockEnrollment(filepath.Join(s.dir, enrollmentLockName))
	if err != nil {
		return nil, err
	}

	return &EnrollmentLock{platform: platform}, nil
}

// Close releases the enrollment lock. The lock file remains to prevent inode races.
func (l *EnrollmentLock) Close() error {
	if l == nil || l.closed {
		return nil
	}

	l.closed = true
	return l.platform.close()
}
