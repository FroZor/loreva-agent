// Package nodeapi serves the node protocol that the portal session and
// direct device sessions share: node reports, metrics with their
// acknowledgements, node requests, and container logs, consoles, and files.
// The portal and direct packages own the connection, authenticate the peer,
// and run the loop around a Peer; this package never knows which peer it
// serves.
package nodeapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/workload"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	// WriteTimeout bounds one frame written to the peer.
	WriteTimeout = 10 * time.Second
	// uploadIdleTimeout ends a file upload whose next chunk does not arrive.
	uploadIdleTimeout = 30 * time.Second
	pingInterval      = 30 * time.Second
	pingJitter        = 5 * time.Second
	pongTimeout       = 10 * time.Second
	// maxErrorMessage bounds the text of an error frame.
	maxErrorMessage = 512
)

// Collectors provide bounded system snapshots after a connection is accepted.
type Collectors struct {
	Specifications func(context.Context) (specifications.Snapshot, error)
	Network        func(context.Context) (networkinfo.Snapshot, error)
	Metrics        MetricsSource
	// Processes returns the details of one process; nil when the node
	// cannot read its process table.
	Processes func(pid int32, startedAt time.Time) (protocol.ProcessDetails, error)
	Workloads WorkloadController
	// Containers serves container logs and consoles; it may be nil when
	// the node has no container runtime.
	Containers ContainerIO
	// Files serves the file manager in container volumes; it may be nil
	// when the node has no container runtime.
	Files ContainerFiles
	// Inventory lists and inspects containers; it may be nil when the
	// node has no container runtime.
	Inventory ContainerInventory
	// Logger receives the audit log of console commands; nil discards it.
	Logger *slog.Logger
}

// WorkloadController accepts authenticated commands and returns asynchronous
// protocol responses per controller (the portal_id of the command). The
// session remains the only writer of its WebSocket.
type WorkloadController interface {
	Submit(protocol.WorkloadCommand, workload.ArtifactSource) error
	Results(controller string) <-chan any
	StoreArtifact(protocol.ArtifactReference, io.Reader) error
}

// Events receives synchronous notifications. Handlers must return promptly.
type Events struct {
	ReportRejected func(NodeReportRejection)
}

// NodeReportRejection describes a correlated report rejection from the peer.
type NodeReportRejection struct {
	Type      string
	Code      string
	RetryIn   time.Duration
	Retryable bool
}

// IdentityRejection means the peer no longer recognizes this node.
type IdentityRejection struct{ Err error }

func (rejection *IdentityRejection) Error() string { return rejection.Err.Error() }
func (rejection *IdentityRejection) Unwrap() error { return rejection.Err }

// RejectFunc answers a request the node cannot accept with an error frame.
type RejectFunc func(ctx context.Context, requestID, code, message string) error

// WriteFrame writes one JSON frame to the peer within WriteTimeout.
func WriteFrame(ctx context.Context, conn *websocket.Conn, frame any) error {
	writeCtx, cancel := context.WithTimeout(ctx, WriteTimeout)
	defer cancel()

	return wsframe.WriteJSON(writeCtx, conn, frame)
}

// Reject returns a RejectFunc that writes a bounded protocol.Error frame
// to conn.
func Reject(conn *websocket.Conn) RejectFunc {
	return func(ctx context.Context, requestID, code, message string) error {
		// Echo only a well-formed request ID, so the frame stays bounded.
		if !agentcrypto.ValidUUID(requestID) {
			requestID = ""
		}

		return WriteFrame(ctx, conn, protocol.Error{
			Type:      protocol.ErrorType,
			RequestID: requestID,
			Code:      code,
			Message:   BoundedMessage(message),
		})
	}
}

// BoundedMessage keeps error text short; it never carries secrets, but a
// peer should not receive unbounded internal detail.
func BoundedMessage(message string) string {
	if len(message) > maxErrorMessage {
		return message[:maxErrorMessage]
	}

	return message
}

// WriteWorkloadRejected answers a command the agent could not queue.
func WriteWorkloadRejected(
	ctx context.Context,
	conn *websocket.Conn,
	command protocol.WorkloadCommand,
	code string,
) error {
	return WriteFrame(ctx, conn, protocol.WorkloadOperationResult{
		Type:          protocol.WorkloadOperationResultType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload: protocol.WorkloadOperationResultPayload{
			State: "rejected", Code: code,
		},
	})
}

// Frame is one frame read from the peer, or the error that ended reading.
type Frame struct {
	Data []byte
	// Binary marks a binary stream frame; every other frame is JSON text.
	Binary bool
	Err    error
}

// ReadFrames reads frames from conn until ctx ends or a read fails; the
// failing read is the last Frame sent.
func ReadFrames(ctx context.Context, conn *websocket.Conn) <-chan Frame {
	frames := make(chan Frame, 1)

	go func() {
		for {
			messageType, data, err := conn.Read(ctx)
			if err != nil {
				sendFrame(ctx, frames, Frame{Err: err})
				return
			}
			if !sendFrame(ctx, frames, Frame{Data: data, Binary: messageType == websocket.MessageBinary}) {
				return
			}
		}
	}()

	return frames
}

func sendFrame(ctx context.Context, frames chan<- Frame, frame Frame) bool {
	select {
	case frames <- frame:
		return true
	case <-ctx.Done():
		return false
	}
}

// Ping checks that the peer still answers.
func Ping(ctx context.Context, conn *websocket.Conn) error {
	pingCtx, cancel := context.WithTimeout(ctx, pongTimeout)
	err := conn.Ping(pingCtx)
	cancel()

	if err != nil {
		return fmt.Errorf("portal heartbeat failed: %w", err)
	}

	return nil
}

// NextPingDelay is the jittered delay until the next Ping.
func NextPingDelay() time.Duration {
	return pingInterval - pingJitter + RandomDuration(2*pingJitter+1)
}

// NewStoppedTimer returns a timer that fires only after a Reset.
func NewStoppedTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	StopTimer(timer)

	return timer
}

// StopTimer stops timer and drains a fire that was not received.
func StopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
