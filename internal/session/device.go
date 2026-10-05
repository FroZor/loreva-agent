package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/workload"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	deviceWriteTimeout = 10 * time.Second
	// uploadIdleTimeout ends an upload whose next chunk does not arrive.
	uploadIdleTimeout = 30 * time.Second
)

// ErrDeviceNotFound is returned by a DeviceDirectory for an unknown device.
var ErrDeviceNotFound = errors.New("device not found")

// DeviceDirectory lists and revokes the node's paired devices. currentID is
// the device of the calling session.
type DeviceDirectory interface {
	List(currentID string) []protocol.Device
	Remove(currentID, deviceID string) error
}

// DeviceConfig is what a direct device session needs from the node.
type DeviceConfig struct {
	// Hello is the first frame; it identifies the node and the device.
	Hello protocol.SessionHello
	// NodeID is the controller scope of every workload command the device sends.
	NodeID     string
	Collectors Collectors
	// Workloads may be nil when the node has no workload runtime.
	Workloads WorkloadController
	// WorkloadResults carries responses to commands of the node's devices.
	WorkloadResults <-chan any
	Devices         DeviceDirectory
	// Containers may be nil when the node has no container runtime.
	Containers ContainerIO
	Logger     *slog.Logger
}

// ServeDevice runs the node protocol for one paired device until the device
// disconnects or ctx is cancelled. The device receives the same node
// reports, metrics, and workload responses as the portal and acknowledges
// them the same way. Instead of signed portal commands it sends workload
// requests directly, uploads artifacts, and manages paired devices.
func ServeDevice(ctx context.Context, conn *websocket.Conn, config DeviceConfig) error {
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}

	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()

	if err := writeDeviceFrame(readCtx, conn, config.Hello); err != nil {
		return fmt.Errorf("write session hello: %w", err)
	}

	reads := startFrameReader(readCtx, conn)

	data := newExchange(readCtx, config.Collectors, &nodeReportState{}, "device:"+config.Hello.DeviceID)
	defer data.stop()

	pingTimer := time.NewTimer(nextPingDelay())
	defer pingTimer.Stop()

	uploadTimer := newStoppedTimer()
	defer uploadTimer.Stop()

	session := &deviceSession{
		config:      config,
		conn:        conn,
		exchange:    data,
		uploadTimer: uploadTimer,
		containers:  newContainerStreams(readCtx, config.Containers, conn, config.Logger),
	}
	defer session.cancelUpload()
	defer session.containers.close()

	events := Events{ReportRejected: func(rejection NodeReportRejection) {
		config.Logger.Warn("device rejected a node report", "type", rejection.Type, "code", rejection.Code)
	}}

	for {
		select {
		case <-ctx.Done():
			closeErr := conn.Close(websocket.StatusNormalClosure, "shutdown")
			return errors.Join(ctx.Err(), closeErr)
		case result := <-reads:
			if result.err != nil {
				return result.err
			}

			if err := session.handle(readCtx, result.data, events); err != nil {
				return err
			}
		case id := <-session.containers.finished:
			session.containers.streamFinished(id)
		case response := <-config.WorkloadResults:
			if err := writeDeviceFrame(readCtx, conn, response); err != nil {
				return fmt.Errorf("write workload response: %w", err)
			}
		case report := <-data.reports.results:
			if err := data.reportCollected(readCtx, conn, report); err != nil {
				return err
			}
		case <-data.reportReplyTimer.C:
			data.scheduleNodeReportRetry(events, "ack_timeout")
		case <-data.reportRetryTimer.C:
			if err := data.retryReport(readCtx, conn); err != nil {
				return err
			}
		case <-data.metrics.wake:
			if err := data.metricsStored(readCtx, conn); err != nil {
				return err
			}
		case <-data.metricsReplyTimer.C:
			data.scheduleMetricsRetry(events, "ack_timeout")
		case <-data.metricsRetryTimer.C:
			if err := data.retryMetrics(readCtx, conn); err != nil {
				return err
			}
		case <-pingTimer.C:
			if err := ping(ctx, conn); err != nil {
				return err
			}

			pingTimer.Reset(nextPingDelay())
		case <-uploadTimer.C:
			if session.upload != nil {
				if err := session.failUpload(readCtx, "upload_timeout", errors.New("no chunk arrived in time")); err != nil {
					return err
				}
			}
		}
	}
}

type deviceSession struct {
	config      DeviceConfig
	conn        *websocket.Conn
	exchange    *exchange
	upload      *artifactUpload
	uploadTimer *time.Timer
	containers  *containerStreams
}

// artifactUpload streams announced chunks into the workload artifact cache.
type artifactUpload struct {
	requestID string
	size      int64
	next      int64
	writer    *io.PipeWriter
	stored    chan error
}

// handle processes one frame. A returned error ends the session; requests
// the agent cannot accept are answered with an error frame instead.
func (s *deviceSession) handle(ctx context.Context, data []byte, events Events) error {
	messageType, err := protocol.MessageType(data)
	if err != nil {
		return errors.New("device sent a message that is not valid JSON")
	}

	handled, err := s.exchange.handleAcknowledgement(ctx, s.conn, messageType, data, events)
	if handled {
		return err
	}

	switch messageType {
	case protocol.WorkloadPlanRequestType,
		protocol.WorkloadExecuteRequestType,
		protocol.WorkloadStopRequestType,
		protocol.WorkloadRestartRequestType,
		protocol.WorkloadDeleteRequestType:
		return s.handleWorkload(ctx, data)
	case protocol.MetricsQueryType:
		return s.handleMetricsQuery(ctx, data)
	case protocol.DevicesListType:
		return s.handleDevicesList(ctx, data)
	case protocol.DeviceRemoveType:
		return s.handleDeviceRemove(ctx, data)
	case protocol.ArtifactUploadRequestType:
		return s.handleUploadRequest(ctx, data)
	case protocol.ArtifactUploadChunkType:
		return s.handleUploadChunk(ctx, data)
	case protocol.ContainerLogsOpenType:
		return s.containers.handleLogsOpen(ctx, data, s.reject)
	case protocol.StreamCreditType:
		return s.containers.handleCredit(ctx, data, s.reject)
	case protocol.StreamCloseType:
		return s.containers.handleClose(ctx, data, s.reject)
	case protocol.ContainerConsoleInfoType:
		return s.containers.handleConsoleInfo(ctx, data, s.reject)
	case protocol.ContainerConsoleSendType:
		return s.containers.handleConsoleSend(ctx, data, s.reject)
	default:
		return s.reject(ctx, "", "unsupported_message", "unsupported message type "+messageType)
	}
}

func (s *deviceSession) handleWorkload(ctx context.Context, data []byte) error {
	var request protocol.DeviceWorkloadCommand
	if err := protocol.DecodeStrict(data, &request); err != nil {
		return s.reject(ctx, "", "invalid_message", "workload request does not match the protocol")
	}

	command, err := workload.DeviceCommand(request, s.config.NodeID, time.Now())
	if err != nil {
		return s.reject(ctx, request.RequestID, "invalid_command", err.Error())
	}
	if s.config.Workloads == nil {
		return writeWorkloadRejected(ctx, s.conn, command, "workload_runtime_unavailable")
	}
	if err := s.config.Workloads.Submit(command, nil); err != nil {
		return writeWorkloadRejected(ctx, s.conn, command, "workload_queue_full")
	}

	return nil
}

func (s *deviceSession) handleDevicesList(ctx context.Context, data []byte) error {
	var request protocol.DevicesList
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return s.reject(ctx, "", "invalid_message", "devices.list needs a UUID request_id")
	}

	return writeDeviceFrame(ctx, s.conn, protocol.DevicesListResult{
		Type:      protocol.DevicesListResultType,
		RequestID: request.RequestID,
		Devices:   s.config.Devices.List(s.config.Hello.DeviceID),
	})
}

func (s *deviceSession) handleDeviceRemove(ctx context.Context, data []byte) error {
	var request protocol.DeviceRemove
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return s.reject(ctx, "", "invalid_message", "device.remove needs a UUID request_id")
	}
	if !agentcrypto.ValidUUID(request.DeviceID) {
		return s.reject(ctx, request.RequestID, "not_found", "device not found")
	}

	if err := s.config.Devices.Remove(s.config.Hello.DeviceID, request.DeviceID); err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			return s.reject(ctx, request.RequestID, "not_found", "device not found")
		}

		return fmt.Errorf("remove device: %w", err)
	}

	return writeDeviceFrame(ctx, s.conn, protocol.DeviceRemoveResult{
		Type:      protocol.DeviceRemoveResultType,
		RequestID: request.RequestID,
		DeviceID:  request.DeviceID,
	})
}

func (s *deviceSession) handleUploadRequest(ctx context.Context, data []byte) error {
	var request protocol.ArtifactUploadRequest
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return s.reject(ctx, "", "invalid_message", "artifact.upload.request needs a UUID request_id")
	}
	if s.config.Workloads == nil {
		return s.uploadResult(ctx, request.RequestID, "workload_runtime_unavailable", nil)
	}
	if s.upload != nil {
		return s.uploadResult(ctx, request.RequestID, "upload_in_progress", nil)
	}
	if request.SizeBytes <= 0 || request.SizeBytes > workload.MaxArtifactBytes {
		return s.uploadResult(ctx, request.RequestID, "invalid_artifact",
			fmt.Errorf("size_bytes must be between 1 and %d", workload.MaxArtifactBytes))
	}

	reference := protocol.ArtifactReference{
		ArtifactID: request.ArtifactID,
		SHA256:     request.SHA256,
		SizeBytes:  request.SizeBytes,
	}
	reader, writer := io.Pipe()
	upload := &artifactUpload{
		requestID: request.RequestID,
		size:      request.SizeBytes,
		writer:    writer,
		stored:    make(chan error, 1),
	}
	go func() {
		err := s.config.Workloads.StoreArtifact(reference, reader)
		reader.CloseWithError(errors.Join(err, io.ErrClosedPipe))
		upload.stored <- err
	}()
	s.upload = upload
	s.uploadTimer.Reset(uploadIdleTimeout)

	return nil
}

func (s *deviceSession) handleUploadChunk(ctx context.Context, data []byte) error {
	var chunk protocol.ArtifactUploadChunk
	if err := protocol.DecodeStrict(data, &chunk); err != nil {
		return s.reject(ctx, "", "invalid_message", "artifact.upload.chunk does not match the protocol")
	}

	upload := s.upload
	if upload == nil || chunk.RequestID != upload.requestID {
		return s.reject(ctx, chunk.RequestID, "unknown_upload", "no upload with this request_id is in progress")
	}

	decoded, err := base64.StdEncoding.Strict().DecodeString(chunk.Data)
	switch {
	case err != nil:
		err = errors.New("chunk data must be standard Base64")
	case len(decoded) == 0 || len(decoded) > protocol.MaxArtifactChunkBytes:
		err = fmt.Errorf("chunk data must be 1 to %d bytes", protocol.MaxArtifactChunkBytes)
	case chunk.Offset != upload.next:
		err = fmt.Errorf("chunk offset must be %d", upload.next)
	case upload.next+int64(len(decoded)) > upload.size:
		err = errors.New("chunks exceed the announced size")
	}
	if err != nil {
		return s.failUpload(ctx, "invalid_chunk", err)
	}

	if _, err := upload.writer.Write(decoded); err != nil {
		return s.failUpload(ctx, "invalid_artifact", storedError(err))
	}
	upload.next += int64(len(decoded))
	if upload.next < upload.size {
		stopTimer(s.uploadTimer)
		s.uploadTimer.Reset(uploadIdleTimeout)

		return nil
	}

	if err := upload.writer.Close(); err != nil {
		return s.failUpload(ctx, "invalid_artifact", storedError(err))
	}

	s.upload = nil
	stopTimer(s.uploadTimer)

	return s.uploadResult(ctx, upload.requestID, "invalid_artifact", storedError(<-upload.stored))
}

// failUpload aborts the active upload and reports why.
func (s *deviceSession) failUpload(ctx context.Context, code string, cause error) error {
	upload := s.upload
	s.upload = nil
	stopTimer(s.uploadTimer)
	upload.writer.CloseWithError(cause)

	// The store sees the closed pipe; the device learns the cause it caused.
	<-upload.stored

	return s.uploadResult(ctx, upload.requestID, code, cause)
}

// storedError turns a store failure into a message without local paths.
func storedError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, workload.ErrArtifactCacheFull):
		return workload.ErrArtifactCacheFull
	default:
		return errors.New("the artifact does not match its declared size and digest, or could not be stored")
	}
}

func (s *deviceSession) cancelUpload() {
	if s.upload != nil {
		s.upload.writer.CloseWithError(context.Canceled)
	}
}

// uploadResult reports a stored artifact when cause is nil and a rejection
// with code otherwise.
func (s *deviceSession) uploadResult(ctx context.Context, requestID, code string, cause error) error {
	result := protocol.ArtifactUploadResult{
		Type:      protocol.ArtifactUploadResultType,
		RequestID: requestID,
		State:     protocol.ArtifactStored,
	}
	if cause != nil {
		result.State = protocol.ArtifactRejected
		result.Code = code
		result.Message = boundedMessage(cause.Error())
	}

	return writeDeviceFrame(ctx, s.conn, result)
}

func (s *deviceSession) reject(ctx context.Context, requestID, code, message string) error {
	// Echo only a well-formed request ID, so the frame stays bounded.
	if !agentcrypto.ValidUUID(requestID) {
		requestID = ""
	}

	return writeDeviceFrame(ctx, s.conn, protocol.Error{
		Type:      protocol.ErrorType,
		RequestID: requestID,
		Code:      code,
		Message:   boundedMessage(message),
	})
}

func writeDeviceFrame(ctx context.Context, conn *websocket.Conn, frame any) error {
	writeCtx, cancel := context.WithTimeout(ctx, deviceWriteTimeout)
	defer cancel()

	return wsframe.WriteJSON(writeCtx, conn, frame)
}

// boundedMessage keeps error text short; it never carries secrets, but a
// device should not receive unbounded internal detail.
func boundedMessage(message string) string {
	const limit = 512
	if len(message) > limit {
		return message[:limit]
	}

	return message
}

// maxQueryRange bounds one metrics.query; the store keeps a week anyway.
const maxQueryRange = 8 * 24 * time.Hour

func (s *deviceSession) handleMetricsQuery(ctx context.Context, data []byte) error {
	var query protocol.MetricsQuery
	if err := protocol.DecodeStrict(data, &query); err != nil || !agentcrypto.ValidUUID(query.RequestID) {
		return s.reject(ctx, "", "invalid_message", "metrics.query needs a UUID request_id, from, and to")
	}
	if query.To.Before(query.From) || query.To.Sub(query.From) > maxQueryRange {
		return s.reject(ctx, query.RequestID, "invalid_range", "to must not be before from, and the range must be at most 8 days")
	}
	if s.config.Collectors.Metrics == nil {
		return s.reject(ctx, query.RequestID, "metrics_unavailable", "this node keeps no metrics")
	}

	result, err := queryResult(s.config.Collectors.Metrics, query.RequestID, query.From, query.To)
	if err != nil {
		return fmt.Errorf("answer metrics query: %w", err)
	}

	return writeDeviceFrame(ctx, s.conn, result)
}
