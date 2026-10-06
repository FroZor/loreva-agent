// Package procfs reads the host's process table from /proc. One pass reads
// only each process's stat file, so the whole table stays cheap to scan every
// second; details that cost more reads are fetched for chosen processes only.
package procfs

import (
	"errors"
	"time"
)

// ErrUnsupported is returned on systems without a Linux /proc.
var ErrUnsupported = errors.New("process table is not available on this system")

// Process states, normalized from the kernel's one-letter codes.
const (
	StateRunning  = "running"
	StateSleeping = "sleeping"
	StateBlocked  = "blocked"
	StateStopped  = "stopped"
	StateZombie   = "zombie"
	StateIdle     = "idle"
)

// Process is one entry of the process table.
type Process struct {
	PID        int32
	ParentPID  int32
	Name       string
	State      string
	StartedAt  time.Time
	CPUSeconds float64
	Threads    int32
	RSSBytes   uint64
	VMSBytes   uint64
}

// Identity is who runs a process and where. It does not change while the
// process lives. Fields the agent may not read stay empty.
type Identity struct {
	UID         *uint32
	User        string
	ContainerID string
}

// Usage is the I/O a process has done so far. Reading another user's
// counters needs privileges; unreadable values stay nil.
type Usage struct {
	ReadBytes       *uint64
	WriteBytes      *uint64
	FileDescriptors *int32
}
