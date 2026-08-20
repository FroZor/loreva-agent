//go:build windows

package state

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func secureDirectory(path string) error { return applyRestrictedACL(path) }
func secureFile(path string) error      { return applyRestrictedACL(path) }

func ensureSecureFile(path string, _ os.FileInfo) error {
	return applyRestrictedACL(path)
}

func syncDirectory(string) error { return nil }

func commitState(tempPath, destination string) error {
	return moveState(tempPath, destination, windows.MOVEFILE_WRITE_THROUGH)
}

func replaceState(tempPath, destination string) error {
	return moveState(tempPath, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func moveState(tempPath, destination string, flags uint32) error {
	from, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return err
	}

	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(from, to, flags)
}

func applyRestrictedACL(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current Windows identity: %w", err)
	}

	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"

	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("create restricted Windows ACL: %w", err)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read restricted Windows ACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply restricted Windows ACL: %w", err)
	}

	return nil
}
