package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	// maxContainerRequests bounds console and log-open requests that wait
	// on Docker or a console port at the same time in one session.
	maxContainerRequests = 4
	// commandWindow and maxCommandsPerWindow rate-limit console commands.
	commandWindow        = 10 * time.Second
	maxCommandsPerWindow = 20
	// auditCommandBytes bounds the command text kept in the audit log.
	auditCommandBytes = 256
)

// ContainerIO reads container logs and delivers console commands.
type ContainerIO interface {
	Logs(ctx context.Context, containerID string, options containerio.LogOptions) (containerio.LogStream, error)
	ConsoleAdapter(ctx context.Context, containerID string) (containerio.Adapter, error)
	SendCommand(ctx context.Context, containerID, command string) (containerio.CommandResult, error)
}

// containerStreams serves container logs and consoles for one session. The
// session loop owns streams and commands; the goroutines it starts only
// write frames, which the WebSocket connection allows concurrently.
type containerStreams struct {
	// ctx bounds every goroutine the session starts here.
	ctx      context.Context
	cancel   context.CancelFunc
	io       ContainerIO
	conn     *websocket.Conn
	logger   *slog.Logger
	streams  map[uint32]*outStream
	finished chan uint32
	requests chan struct{}
	commands []time.Time
	wait     sync.WaitGroup
}

func newContainerStreams(ctx context.Context, io ContainerIO, conn *websocket.Conn, logger *slog.Logger) *containerStreams {
	ctx, cancel := context.WithCancel(ctx)

	return &containerStreams{
		ctx:      ctx,
		cancel:   cancel,
		io:       io,
		conn:     conn,
		logger:   logger,
		streams:  make(map[uint32]*outStream),
		finished: make(chan uint32, protocol.MaxStreamsPerSession),
		requests: make(chan struct{}, maxContainerRequests),
	}
}

// close cancels every stream and request and waits for the goroutines to
// stop writing.
func (c *containerStreams) close() {
	c.cancel()
	c.wait.Wait()
}

// streamFinished forgets a stream whose goroutine has ended.
func (c *containerStreams) streamFinished(id uint32) {
	delete(c.streams, id)
}

func (c *containerStreams) handleLogsOpen(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.ContainerLogsOpen
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "container.logs.open does not match the protocol")
	}
	if request.StreamID == 0 || request.StreamID > protocol.MaxStreamID {
		return reject(ctx, request.RequestID, "invalid_stream_id", "stream_id must be between 1 and 2147483647")
	}
	if c.io == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}
	if _, exists := c.streams[request.StreamID]; exists {
		return reject(ctx, request.RequestID, "stream_id_in_use", "stream_id is already open")
	}
	if len(c.streams) >= protocol.MaxStreamsPerSession {
		return reject(ctx, request.RequestID, "too_many_streams", fmt.Sprintf("at most %d streams can be open", protocol.MaxStreamsPerSession))
	}

	options := containerio.LogOptions{Tail: request.Tail, Follow: request.Follow, Timestamps: request.Timestamps}
	if request.Since != nil {
		options.Since = *request.Since
	}

	streamCtx, cancel := context.WithCancel(c.ctx)
	stream := newOutStream(request.StreamID, cancel)
	c.streams[request.StreamID] = stream
	c.wait.Add(1)
	go c.runLogs(streamCtx, stream, request, options)

	return nil
}

func (c *containerStreams) runLogs(ctx context.Context, stream *outStream, request protocol.ContainerLogsOpen, options containerio.LogOptions) {
	defer c.wait.Done()
	defer func() { c.finished <- stream.id }()
	defer stream.cancel()

	log, err := c.io.Logs(ctx, request.ContainerID, options)
	if err != nil {
		code, message := containerErrorCode(err)
		c.writeFrame(ctx, protocol.Error{Type: protocol.ErrorType, RequestID: request.RequestID, Code: code, Message: boundedMessage(message)})
		return
	}
	defer log.Close()

	c.logger.Info("container log stream opened", "container_id", request.ContainerID, "stream_id", stream.id, "follow", request.Follow)
	if !c.writeFrame(ctx, protocol.ContainerLogsOpened{
		Type:      protocol.ContainerLogsOpenedType,
		RequestID: request.RequestID,
		StreamID:  stream.id,
		TTY:       log.TTY(),
	}) {
		return
	}

	err = log.Copy(func(source containerio.Stream, data []byte) error {
		if err := stream.take(ctx, int64(len(data))); err != nil {
			return err
		}

		return c.writeChunk(ctx, stream.id, source, data)
	})
	if ctx.Err() != nil {
		// The device cancelled the stream or the session ended.
		return
	}

	closing := protocol.StreamClose{Type: protocol.StreamCloseType, StreamID: stream.id, Reason: protocol.StreamEnded}
	if err != nil {
		closing.Reason = protocol.StreamFailed
		closing.Code = "logs_failed"
		c.logger.Warn("container log stream failed", "container_id", request.ContainerID, "error", err)
	}
	c.writeFrame(ctx, closing)
}

func (c *containerStreams) handleCredit(ctx context.Context, data []byte, reject rejectFunc) error {
	var credit protocol.StreamCredit
	if err := protocol.DecodeStrict(data, &credit); err != nil {
		return reject(ctx, "", "invalid_message", "stream.credit does not match the protocol")
	}

	stream, ok := c.streams[credit.StreamID]
	if !ok {
		// The stream may have ended while the credit was on its way.
		return nil
	}
	if err := stream.grant(credit.Bytes); err != nil {
		return reject(ctx, "", "invalid_credit", err.Error())
	}

	return nil
}

func (c *containerStreams) handleClose(ctx context.Context, data []byte, reject rejectFunc) error {
	var closing protocol.StreamClose
	if err := protocol.DecodeStrict(data, &closing); err != nil || closing.Reason != protocol.StreamCancelled {
		return reject(ctx, "", "invalid_message", "a device closes a stream with reason cancelled")
	}

	if stream, ok := c.streams[closing.StreamID]; ok {
		stream.cancel()
	}

	return nil
}

func (c *containerStreams) handleConsoleInfo(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.ContainerConsoleInfo
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "container.console.info does not match the protocol")
	}
	if c.io == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}
	if !c.startRequest() {
		return reject(ctx, request.RequestID, "busy", "too many container requests are in progress")
	}

	go func(ctx context.Context) {
		defer c.endRequest()

		adapter, err := c.io.ConsoleAdapter(ctx, request.ContainerID)
		if err != nil {
			c.writeError(ctx, request.RequestID, err)
			return
		}

		c.writeFrame(ctx, protocol.ContainerConsoleInfoResult{
			Type:        protocol.ContainerConsoleInfoResultType,
			RequestID:   request.RequestID,
			ContainerID: request.ContainerID,
			Adapter:     string(adapter),
		})
	}(c.ctx)

	return nil
}

func (c *containerStreams) handleConsoleSend(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.ContainerConsoleSend
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "container.console.send does not match the protocol")
	}
	if c.io == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}
	if err := containerio.ValidateCommand(request.Command); err != nil {
		return reject(ctx, request.RequestID, "invalid_command", err.Error())
	}
	if !c.allowCommand(time.Now()) {
		return reject(ctx, request.RequestID, "rate_limited", fmt.Sprintf("at most %d commands per %s", maxCommandsPerWindow, commandWindow))
	}
	if !c.startRequest() {
		return reject(ctx, request.RequestID, "busy", "too many container requests are in progress")
	}

	go func(ctx context.Context) {
		defer c.endRequest()

		result, err := c.io.SendCommand(ctx, request.ContainerID, request.Command)
		c.logger.Info("container console command",
			"container_id", request.ContainerID,
			"adapter", string(result.Adapter),
			"command", truncate(request.Command, auditCommandBytes),
			"delivered", err == nil,
		)
		if err != nil {
			c.writeError(ctx, request.RequestID, err)
			return
		}

		c.writeFrame(ctx, protocol.ContainerConsoleSendResult{
			Type:        protocol.ContainerConsoleSendResultType,
			RequestID:   request.RequestID,
			ContainerID: request.ContainerID,
			Adapter:     string(result.Adapter),
			Output:      result.Output,
		})
	}(c.ctx)

	return nil
}

// allowCommand applies the sliding-window command rate limit.
func (c *containerStreams) allowCommand(now time.Time) bool {
	recent := c.commands[:0]
	for _, at := range c.commands {
		if now.Sub(at) < commandWindow {
			recent = append(recent, at)
		}
	}
	c.commands = recent
	if len(c.commands) >= maxCommandsPerWindow {
		return false
	}

	c.commands = append(c.commands, now)

	return true
}

func (c *containerStreams) startRequest() bool {
	select {
	case c.requests <- struct{}{}:
		c.wait.Add(1)
		return true
	default:
		return false
	}
}

func (c *containerStreams) endRequest() {
	<-c.requests
	c.wait.Done()
}

func (c *containerStreams) writeError(ctx context.Context, requestID string, err error) {
	code, message := containerErrorCode(err)
	c.writeFrame(ctx, protocol.Error{Type: protocol.ErrorType, RequestID: requestID, Code: code, Message: boundedMessage(message)})
}

// writeFrame writes a JSON frame and reports whether it was written. A
// failed write ends the stream; the session loop notices the broken
// connection on its next read.
func (c *containerStreams) writeFrame(ctx context.Context, frame any) bool {
	return writeDeviceFrame(ctx, c.conn, frame) == nil
}

func (c *containerStreams) writeChunk(ctx context.Context, id uint32, source containerio.Stream, data []byte) error {
	frame := make([]byte, protocol.StreamFrameHeaderBytes+len(data))
	frame[0] = protocol.StreamChannelStdout
	if source == containerio.Stderr {
		frame[0] = protocol.StreamChannelStderr
	}
	binary.BigEndian.PutUint32(frame[1:protocol.StreamFrameHeaderBytes], id)
	copy(frame[protocol.StreamFrameHeaderBytes:], data)

	writeCtx, cancel := context.WithTimeout(ctx, deviceWriteTimeout)
	defer cancel()

	return c.conn.Write(writeCtx, websocket.MessageBinary, frame)
}

func containerErrorCode(err error) (string, string) {
	codes := []struct {
		err  error
		code string
	}{
		{containerio.ErrInvalidContainerID, "invalid_container_id"},
		{containerio.ErrNotFound, "container_not_found"},
		{containerio.ErrNotRunning, "container_not_running"},
		{containerio.ErrNoConsole, "console_unavailable"},
		{containerio.ErrConsoleMisconfigured, "console_misconfigured"},
		{containerio.ErrConsoleUnreachable, "console_unreachable"},
		{containerio.ErrConsoleAuthFailed, "console_auth_failed"},
		{containerio.ErrInvalidCommand, "invalid_command"},
	}
	for _, known := range codes {
		if errors.Is(err, known.err) {
			return known.code, err.Error()
		}
	}

	return "container_io_failed", err.Error()
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}

	return text[:limit]
}

type rejectFunc func(ctx context.Context, requestID, code, message string) error

// outStream is a node-to-device stream with credit-based flow control.
type outStream struct {
	id     uint32
	cancel context.CancelFunc

	mu     sync.Mutex
	window int64
	notify chan struct{}
}

func newOutStream(id uint32, cancel context.CancelFunc) *outStream {
	return &outStream{
		id:     id,
		cancel: cancel,
		window: protocol.StreamWindowBytes,
		notify: make(chan struct{}, 1),
	}
}

// grant adds credit; the outstanding window never exceeds its initial size.
func (s *outStream) grant(bytes int64) error {
	if bytes <= 0 || bytes > protocol.StreamWindowBytes {
		return fmt.Errorf("credit must be between 1 and %d bytes", protocol.StreamWindowBytes)
	}

	s.mu.Lock()
	if s.window+bytes > protocol.StreamWindowBytes {
		s.mu.Unlock()
		return fmt.Errorf("credit would exceed the %d-byte window", protocol.StreamWindowBytes)
	}
	s.window += bytes
	s.mu.Unlock()

	select {
	case s.notify <- struct{}{}:
	default:
	}

	return nil
}

// take waits until bytes of credit are available and uses them.
func (s *outStream) take(ctx context.Context, bytes int64) error {
	for {
		s.mu.Lock()
		if s.window >= bytes {
			s.window -= bytes
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()

		select {
		case <-s.notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
