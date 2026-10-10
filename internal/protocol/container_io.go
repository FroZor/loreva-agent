package protocol

import "time"

// Container log and console message types of the direct session.
const (
	ContainerLogsOpenType          = "container.logs.open"
	ContainerLogsOpenedType        = "container.logs.opened"
	ContainerConsoleInfoType       = "container.console.info"
	ContainerConsoleInfoResultType = "container.console.info.result"
	ContainerConsoleSendType       = "container.console.send"
	ContainerConsoleSendResultType = "container.console.send.result"
	StreamCreditType               = "stream.credit"
	StreamCloseType                = "stream.close"
)

// Stream limits. A stream starts with StreamWindowBytes of credit; the
// receiver grants more with stream.credit as it consumes data.
const (
	StreamWindowBytes    = 2 * 1024 * 1024
	MaxStreamChunkBytes  = 32 * 1024
	MaxStreamsPerSession = 8
	MaxStreamID          = 1<<31 - 1
)

// Binary stream frame layout: one channel byte, the stream ID as a
// big-endian uint32, then 1 to MaxStreamChunkBytes of data.
const (
	StreamFrameHeaderBytes = 5
	StreamChannelStdout    = 1
	StreamChannelStderr    = 2
)

// Stream close reasons.
const (
	StreamEnded     = "ended"
	StreamFailed    = "failed"
	StreamCancelled = "cancelled"
)

// ContainerLogsOpen asks for a container's log as a binary stream.
type ContainerLogsOpen struct {
	Type        string     `json:"type"`
	RequestID   string     `json:"request_id"`
	StreamID    uint32     `json:"stream_id"`
	ContainerID string     `json:"container_id"`
	Tail        int        `json:"tail"`
	Since       *time.Time `json:"since,omitempty"`
	Follow      bool       `json:"follow"`
	Timestamps  bool       `json:"timestamps"`
}

// ContainerLogsOpened confirms a log stream. TTY means stdout and stderr are
// merged on the stdout channel and may carry terminal control sequences.
type ContainerLogsOpened struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	StreamID  uint32 `json:"stream_id"`
	TTY       bool   `json:"tty"`
}

// StreamCredit lets the sender of a stream send Bytes more data.
type StreamCredit struct {
	Type     string `json:"type"`
	StreamID uint32 `json:"stream_id"`
	Bytes    int64  `json:"bytes"`
}

// StreamClose ends a stream. The node sends ended or failed; a device
// cancels a stream it no longer wants.
type StreamClose struct {
	Type     string `json:"type"`
	StreamID uint32 `json:"stream_id"`
	Reason   string `json:"reason"`
	Code     string `json:"code,omitempty"`
}

// ContainerConsoleInfo asks which console a container offers.
type ContainerConsoleInfo struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
}

// ContainerConsoleInfoResult names the console adapter: stdin, rcon,
// telnet, or none.
type ContainerConsoleInfoResult struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Adapter     string `json:"adapter"`
}

// ContainerConsoleSend delivers one console command line.
type ContainerConsoleSend struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Command     string `json:"command"`
}

// ContainerConsoleSendResult confirms delivery. Output is the reply of an
// RCON or telnet console; stdin output appears in the container log.
type ContainerConsoleSendResult struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id"`
	ContainerID string `json:"container_id"`
	Adapter     string `json:"adapter"`
	Output      string `json:"output"`
}
