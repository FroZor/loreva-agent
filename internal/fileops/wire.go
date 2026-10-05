// Package fileops runs file operations inside a helper container that sees
// only the volumes and bind mounts of one workload container. The agent
// drives the helper over its stdin and stdout with the framing in this file:
// every frame carries the id of the call it belongs to, so one helper serves
// many calls at once.
package fileops

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Frame kinds between the agent and the helper.
const (
	// FrameRequest starts a call (agent to helper, JSON Request).
	FrameRequest byte = 1
	// FrameResponse answers a call (helper to agent, JSON Response). A call
	// may get progress responses before its final one.
	FrameResponse byte = 2
	// FrameData carries file content in either direction.
	FrameData byte = 3
	// FrameEnd ends the content of a call.
	FrameEnd byte = 4
	// FrameCancel cancels a call (agent to helper).
	FrameCancel byte = 5
	// FrameCredit lets the other side send more data bytes; the payload is
	// a big-endian uint32 byte count.
	FrameCredit byte = 6
)

const (
	frameHeaderBytes = 9
	// MaxFramePayload bounds one frame.
	MaxFramePayload = 1024 * 1024
	// DataChunkBytes bounds the content of one data frame.
	DataChunkBytes = 32 * 1024
	// WindowBytes is how much content one call may have in flight in each
	// direction before the receiver returns credit.
	WindowBytes = 2 * 1024 * 1024
)

// Operations.
const (
	OpInit    = "init"
	OpList    = "list"
	OpStat    = "stat"
	OpMkdir   = "mkdir"
	OpRename  = "rename"
	OpChmod   = "chmod"
	OpCopy    = "copy"
	OpDelete  = "delete"
	OpArchive = "archive"
	OpExtract = "extract"
	OpRead    = "read"
	OpWrite   = "write"
)

// Archive formats.
const (
	FormatZip   = "zip"
	FormatTarGz = "tar.gz"
)

// Entry types.
const (
	TypeFile      = "file"
	TypeDirectory = "directory"
	TypeSymlink   = "symlink"
	TypeOther     = "other"
)

// Mount is a path of the workload container that the helper shares.
type Mount struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only"`
}

// Request is one operation. Paths are absolute paths as the workload
// container sees them.
type Request struct {
	Op     string   `json:"op"`
	Mounts []Mount  `json:"mounts,omitempty"`
	Path   string   `json:"path,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	To     string   `json:"to,omitempty"`
	After  string   `json:"after,omitempty"`
	Format string   `json:"format,omitempty"`
	Mode   uint32   `json:"mode,omitempty"`
	Offset int64    `json:"offset,omitempty"`
	Size   int64    `json:"size,omitempty"`
	// SHA256 is the hex digest of the whole file a write delivers.
	SHA256 string `json:"sha256,omitempty"`
	// ExpectedVersion makes a write fail unless the file still has this
	// version; "absent" requires that no file exists yet.
	ExpectedVersion string `json:"expected_version,omitempty"`
}

// VersionAbsent is the expected version of a file that must not exist yet.
const VersionAbsent = "absent"

// Response answers a request. Long operations send responses with only
// Progress set before the final one.
type Response struct {
	OK       bool      `json:"ok"`
	Code     string    `json:"code,omitempty"`
	Message  string    `json:"message,omitempty"`
	Entry    *Entry    `json:"entry,omitempty"`
	Entries  []Entry   `json:"entries,omitempty"`
	More     bool      `json:"more,omitempty"`
	Offset   int64     `json:"offset,omitempty"`
	Skipped  int64     `json:"skipped,omitempty"`
	Progress *Progress `json:"progress,omitempty"`
}

// Entry describes a file system object.
type Entry struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	ModifiedAt time.Time `json:"modified_at"`
	LinkTarget string    `json:"link_target,omitempty"`
	// Version changes whenever the content may have changed: modification
	// time in nanoseconds and size.
	Version string `json:"version,omitempty"`
	// Mount marks the root of a shared mount; Virtual marks a directory
	// that only leads to mounts.
	Mount    bool `json:"mount,omitempty"`
	Virtual  bool `json:"virtual,omitempty"`
	ReadOnly bool `json:"read_only,omitempty"`
}

// Progress reports a long operation.
type Progress struct {
	Items int64 `json:"items"`
	Bytes int64 `json:"bytes"`
}

// Frame is one decoded frame.
type Frame struct {
	Kind    byte
	Call    uint32
	Payload []byte
}

// WriteFrame writes one frame with a single Write call, so concurrent
// writers only need to serialize calls.
func WriteFrame(writer io.Writer, kind byte, call uint32, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("frame payload of %d bytes exceeds %d", len(payload), MaxFramePayload)
	}

	frame := make([]byte, frameHeaderBytes+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], call)
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
	copy(frame[frameHeaderBytes:], payload)

	_, err := writer.Write(frame)

	return err
}

// ReadFrame reads one frame.
func ReadFrame(reader io.Reader) (Frame, error) {
	header := make([]byte, frameHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, err
	}

	length := binary.BigEndian.Uint32(header[5:9])
	if length > MaxFramePayload {
		return Frame{}, fmt.Errorf("frame payload of %d bytes exceeds %d", length, MaxFramePayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}

	return Frame{Kind: header[0], Call: binary.BigEndian.Uint32(header[1:5]), Payload: payload}, nil
}

// CreditPayload encodes a credit frame payload.
func CreditPayload(bytes int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(bytes))

	return payload
}

// ParseCredit decodes a credit frame payload.
func ParseCredit(payload []byte) (int, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("credit payload must be 4 bytes, got %d", len(payload))
	}
	credit := binary.BigEndian.Uint32(payload)
	if credit == 0 || credit > WindowBytes {
		return 0, fmt.Errorf("credit must be between 1 and %d bytes", WindowBytes)
	}

	return int(credit), nil
}
