package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	enrollmentLockName = ".enrollment.lock"
	connectionLockName = ".connection.lock"
	processLockName    = ".process.lock"
)

// ErrEnrollmentLocked indicates that another process is enrolling this state directory.
var ErrEnrollmentLocked = errors.New("agent enrollment is already running")

// ErrConnectionActive indicates that an agent process is using the persisted
// identity for a portal connection.
var ErrConnectionActive = errors.New("agent connection is active")

// ErrAgentRunning indicates that another agent process owns this state directory.
var ErrAgentRunning = errors.New("agent process is already running")

// Lock is an exclusive process lock scoped to one agent state directory.
type Lock struct {
	platform platformEnrollmentLock
	closed   bool
}

// TryLockEnrollment acquires the enrollment lock without waiting.
func (s *Store) TryLockEnrollment() (*Lock, error) {
	return s.tryLock(enrollmentLockName, ErrEnrollmentLocked)
}

// TryLockConnection prevents identity replacement while a runner is using it.
func (s *Store) TryLockConnection() (*Lock, error) {
	return s.tryLock(connectionLockName, ErrConnectionActive)
}

// TryLockProcess prevents two agent supervisors from using the same state directory.
func (s *Store) TryLockProcess() (*Lock, error) {
	return s.tryLock(processLockName, ErrAgentRunning)
}

func (s *Store) tryLock(name string, lockedErr error) (*Lock, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := secureDirectory(s.dir); err != nil {
		return nil, fmt.Errorf("secure state directory: %w", err)
	}

	platform, err := tryLockFile(filepath.Join(s.dir, name), lockedErr)
	if err != nil {
		return nil, err
	}

	return &Lock{platform: platform}, nil
}

// Close releases the lock. The lock file remains to prevent inode races.
func (l *Lock) Close() error {
	if l == nil || l.closed {
		return nil
	}

	l.closed = true
	return l.platform.close()
}
