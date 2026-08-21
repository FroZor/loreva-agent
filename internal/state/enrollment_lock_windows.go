//go:build windows

package state

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

type platformEnrollmentLock struct {
	handle     windows.Handle
	overlapped windows.Overlapped
}

func tryLockEnrollment(path string) (platformEnrollmentLock, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return platformEnrollmentLock{}, fmt.Errorf("encode enrollment lock path: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return platformEnrollmentLock{}, fmt.Errorf("open enrollment lock: %w", err)
	}

	closeOnError := func(lockErr error) (platformEnrollmentLock, error) {
		return platformEnrollmentLock{}, errors.Join(lockErr, windows.CloseHandle(handle))
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return closeOnError(fmt.Errorf("inspect enrollment lock: %w", err))
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return closeOnError(errors.New("enrollment lock must be a regular file, not a link"))
	}
	if err := applyRestrictedACL(path); err != nil {
		return closeOnError(fmt.Errorf("secure enrollment lock: %w", err))
	}

	lock := platformEnrollmentLock{handle: handle}
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&lock.overlapped,
	); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return closeOnError(ErrEnrollmentLocked)
		}

		return closeOnError(fmt.Errorf("lock enrollment state: %w", err))
	}

	return lock, nil
}

func (l platformEnrollmentLock) close() error {
	if l.handle == 0 || l.handle == windows.InvalidHandle {
		return nil
	}

	unlockErr := windows.UnlockFileEx(l.handle, 0, 1, 0, &l.overlapped)
	closeErr := windows.CloseHandle(l.handle)

	return errors.Join(unlockErr, closeErr)
}
