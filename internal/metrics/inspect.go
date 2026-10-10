package metrics

import (
	"errors"
	"time"

	"github.com/FroZor/loreva-agent/internal/procfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// startTolerance absorbs the rounding of start times to clock ticks.
const startTolerance = 10 * time.Millisecond

// ErrProcessNotFound means no process with that PID and start time runs.
var ErrProcessNotFound = errors.New("process not found")

// InspectProcess returns the details of the process with this PID that
// started at startedAt.
func (collector *Collector) InspectProcess(pid int32, startedAt time.Time) (protocol.ProcessDetails, error) {
	process, err := procfs.Read(pid)
	if errors.Is(err, procfs.ErrUnsupported) {
		return protocol.ProcessDetails{}, err
	}
	if err != nil || process.StartedAt.Sub(startedAt).Abs() > startTolerance {
		return protocol.ProcessDetails{}, ErrProcessNotFound
	}

	identity := procfs.ReadIdentity(pid, collector.users.get())
	commandLine, truncated := procfs.CommandLine(pid)

	return protocol.ProcessDetails{
		PID:                  process.PID,
		ParentPID:            process.ParentPID,
		StartedAt:            process.StartedAt,
		Name:                 sanitize(process.Name, 256),
		State:                process.State,
		UID:                  identity.UID,
		User:                 sanitize(identity.User, 64),
		ContainerID:          identity.ContainerID,
		CommandLine:          commandLine,
		CommandLineTruncated: truncated,
	}, nil
}
