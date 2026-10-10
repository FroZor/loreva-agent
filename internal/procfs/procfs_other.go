//go:build !linux

package procfs

import "time"

// Scan is not available outside Linux.
func Scan() ([]Process, error) {
	return nil, ErrUnsupported
}

// BootTime is not available outside Linux.
func BootTime() (time.Time, error) {
	return time.Time{}, ErrUnsupported
}

// ReadIdentity is not available outside Linux.
func ReadIdentity(int32, map[uint32]string) Identity {
	return Identity{}
}

// ReadUsage is not available outside Linux.
func ReadUsage(int32) Usage {
	return Usage{}
}

// Read is not available outside Linux.
func Read(int32) (Process, error) {
	return Process{}, ErrUnsupported
}

// CommandLine is not available outside Linux.
func CommandLine(int32) ([]string, bool) {
	return []string{}, false
}

// Users is not available outside Linux.
func Users() map[uint32]string {
	return map[uint32]string{}
}

// SocketOwners is not available outside Linux.
func SocketOwners() (map[uint64]int32, bool) {
	return map[uint64]int32{}, false
}

// Name is not available outside Linux.
func Name(int32) string {
	return ""
}
