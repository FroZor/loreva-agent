package protocol

import "time"

// Process inspection message types.
const (
	NodeProcessInspectType       = "node.process.inspect"
	NodeProcessInspectResultType = "node.process.inspect.result"
)

// NodeProcessInspect asks for the details of one process of a metrics
// sample. PID and StartedAt together identify it, so a reused PID is not
// mistaken for the process the client saw.
type NodeProcessInspect struct {
	Type      string    `json:"type"`
	RequestID string    `json:"request_id"`
	PID       int32     `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

// NodeProcessInspectResult answers node.process.inspect.
type NodeProcessInspectResult struct {
	Type      string         `json:"type"`
	RequestID string         `json:"request_id"`
	Process   ProcessDetails `json:"process"`
}

// ProcessDetails are the details of one process that are too large to send
// every second. CommandLine is complete unless CommandLineTruncated is set;
// it is empty for kernel threads.
type ProcessDetails struct {
	PID                  int32     `json:"pid"`
	ParentPID            int32     `json:"parent_pid"`
	StartedAt            time.Time `json:"started_at"`
	Name                 string    `json:"name"`
	State                string    `json:"state,omitempty"`
	UID                  *uint32   `json:"uid,omitempty"`
	User                 string    `json:"user,omitempty"`
	ContainerID          string    `json:"container_id,omitempty"`
	CommandLine          []string  `json:"command_line"`
	CommandLineTruncated bool      `json:"command_line_truncated"`
}
