package fileops

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// Error codes a response carries.
const (
	CodeInvalidRequest   = "invalid_request"
	CodeInvalidPath      = "invalid_path"
	CodeOutsideMounts    = "outside_mounts"
	CodeMountRoot        = "mount_root"
	CodeNotFound         = "not_found"
	CodeAlreadyExists    = "already_exists"
	CodeNotADirectory    = "not_a_directory"
	CodeIsADirectory     = "is_a_directory"
	CodeNotRegularFile   = "not_regular_file"
	CodeNotEmpty         = "not_empty"
	CodePermissionDenied = "permission_denied"
	CodeReadOnly         = "read_only"
	CodeCrossDevice      = "cross_device"
	CodeVersionConflict  = "version_conflict"
	CodeChecksumMismatch = "checksum_mismatch"
	CodeTooLarge         = "too_large"
	CodeNoSpace          = "no_space"
	CodeUnsupported      = "unsupported_format"
	CodeBusy             = "busy"
	CodeCancelled        = "cancelled"
	CodeFailed           = "failed"
)

// opError is a failure with a protocol code.
type opError struct {
	code    string
	message string
}

func (e *opError) Error() string { return e.message }

func codedError(code, message string) error {
	return &opError{code: code, message: message}
}

// failure turns an error into a response, naming what went wrong without
// the helper's own paths.
func failure(err error) Response {
	if coded, ok := errors.AsType[*opError](err); ok {
		return Response{Code: coded.code, Message: coded.message}
	}

	code := classify(err)
	message := err.Error()
	if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
		message = pathErr.Op + ": " + pathErr.Err.Error()
	}
	if linkErr, ok := errors.AsType[*os.LinkError](err); ok {
		message = linkErr.Op + ": " + linkErr.Err.Error()
	}

	return Response{Code: code, Message: message}
}

func classify(err error) string {
	// os.Root reports a path that leaves the mount with an unexported
	// error, so only its text identifies it.
	if strings.Contains(err.Error(), "path escapes from parent") {
		return CodeOutsideMounts
	}

	codes := []struct {
		err  error
		code string
	}{
		{fs.ErrNotExist, CodeNotFound},
		{fs.ErrExist, CodeAlreadyExists},
		{syscall.ENOTEMPTY, CodeNotEmpty},
		{syscall.ENOTDIR, CodeNotADirectory},
		{syscall.EISDIR, CodeIsADirectory},
		{syscall.EROFS, CodeReadOnly},
		{syscall.EXDEV, CodeCrossDevice},
		{syscall.ENOSPC, CodeNoSpace},
		{syscall.EDQUOT, CodeNoSpace},
		{syscall.EFBIG, CodeTooLarge},
		{syscall.ELOOP, CodeInvalidPath},
		{syscall.EINVAL, CodeInvalidPath},
		{fs.ErrPermission, CodePermissionDenied},
	}
	for _, known := range codes {
		if errors.Is(err, known.err) {
			return known.code
		}
	}

	return CodeFailed
}
