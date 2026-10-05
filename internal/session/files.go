package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/containerfiles"
	"github.com/FroZor/loreva-agent/internal/fileops"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	// fileCreditBytes is how much upload data the node forwards before it
	// returns credit to the device.
	fileCreditBytes = 256 * 1024
	// quickFileTimeout bounds a list, stat, mkdir, rename, or chmod,
	// including the start of the helper.
	quickFileTimeout = 2 * time.Minute
)

// ContainerFiles runs file operations in the volumes of a container.
type ContainerFiles interface {
	Start(ctx context.Context, containerID string, request fileops.Request) (containerfiles.Call, error)
}

// fileOperations tracks the long file operations of a session so fs.cancel
// can stop them.
type fileOperations struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func (o *fileOperations) add(requestID string, cancel context.CancelFunc) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.cancels == nil {
		o.cancels = make(map[string]context.CancelFunc)
	}
	if _, exists := o.cancels[requestID]; exists || len(o.cancels) >= protocol.MaxFSOperations {
		return false
	}
	o.cancels[requestID] = cancel

	return true
}

func (o *fileOperations) remove(requestID string) {
	o.mu.Lock()
	delete(o.cancels, requestID)
	o.mu.Unlock()
}

func (o *fileOperations) cancel(requestID string) {
	o.mu.Lock()
	cancel := o.cancels[requestID]
	o.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// inStream is a device-to-node upload. The session loop queues its binary
// frames; the upload goroutine forwards them to the helper.
type inStream struct {
	id     uint32
	cancel context.CancelFunc
	inbox  *fileops.Inbox
}

// handleFile serves a file manager frame and reports false for any other
// message type.
func (c *containerStreams) handleFile(ctx context.Context, messageType string, data []byte, reject rejectFunc) (bool, error) {
	switch messageType {
	case protocol.FSListType:
		return true, c.handleFSList(ctx, data, reject)
	case protocol.FSStatType, protocol.FSMkdirType:
		return true, c.handleFSPath(ctx, messageType, data, reject)
	case protocol.FSChmodType:
		return true, c.handleFSChmod(ctx, data, reject)
	case protocol.FSRenameType:
		return true, c.handleFSRename(ctx, data, reject)
	case protocol.FSDeleteType:
		return true, c.handleFSDelete(ctx, data, reject)
	case protocol.FSCopyType:
		return true, c.handleFSCopy(ctx, data, reject)
	case protocol.FSArchiveType:
		return true, c.handleFSArchive(ctx, data, reject)
	case protocol.FSExtractType:
		return true, c.handleFSExtract(ctx, data, reject)
	case protocol.FSCancelType:
		return true, c.handleFSCancel(ctx, data, reject)
	case protocol.FSReadOpenType:
		return true, c.handleFSReadOpen(ctx, data, reject)
	case protocol.FSWriteOpenType:
		return true, c.handleFSWriteOpen(ctx, data, reject)
	default:
		return false, nil
	}
}

func (c *containerStreams) handleFSList(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSList
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.list does not match the protocol")
	}

	return c.quickFileOp(ctx, request.RequestID, request.ContainerID, fileops.Request{Op: fileops.OpList, Path: request.Path, After: request.After}, reject,
		func(response fileops.Response) any {
			return protocol.FSListResult{
				Type:        protocol.FSListResultType,
				RequestID:   request.RequestID,
				ContainerID: request.ContainerID,
				Path:        request.Path,
				Entries:     fsEntries(response.Entries),
				More:        response.More,
			}
		})
}

func (c *containerStreams) handleFSPath(ctx context.Context, messageType string, data []byte, reject rejectFunc) error {
	var request protocol.FSPathRequest
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", messageType+" does not match the protocol")
	}

	if messageType == protocol.FSMkdirType {
		return c.quickFileOp(ctx, request.RequestID, request.ContainerID, fileops.Request{Op: fileops.OpMkdir, Path: request.Path}, reject, func(response fileops.Response) any {
			return fsResult(request.RequestID, request.ContainerID, response)
		})
	}

	return c.quickFileOp(ctx, request.RequestID, request.ContainerID, fileops.Request{Op: fileops.OpStat, Path: request.Path}, reject, func(response fileops.Response) any {
		result := protocol.FSStatResult{Type: protocol.FSStatResultType, RequestID: request.RequestID, ContainerID: request.ContainerID}
		if response.Entry != nil {
			result.Entry = fsEntry(*response.Entry)
		}
		return result
	})
}

func (c *containerStreams) handleFSChmod(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSChmod
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.chmod does not match the protocol")
	}

	operation := fileops.Request{Op: fileops.OpChmod, Path: request.Path, Mode: request.Mode}

	return c.quickFileOp(ctx, request.RequestID, request.ContainerID, operation, reject, func(response fileops.Response) any {
		return fsResult(request.RequestID, request.ContainerID, response)
	})
}

func (c *containerStreams) handleFSRename(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSRename
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.rename does not match the protocol")
	}

	operation := fileops.Request{Op: fileops.OpRename, Path: request.Path, To: request.To}

	return c.quickFileOp(ctx, request.RequestID, request.ContainerID, operation, reject, func(response fileops.Response) any {
		return fsResult(request.RequestID, request.ContainerID, response)
	})
}

func (c *containerStreams) handleFSDelete(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSDelete
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.delete does not match the protocol")
	}

	return c.longFileOp(ctx, request.RequestID, request.ContainerID, fileops.Request{Op: fileops.OpDelete, Paths: request.Paths}, reject)
}

func (c *containerStreams) handleFSCopy(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSCopy
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.copy does not match the protocol")
	}

	return c.longFileOp(ctx, request.RequestID, request.ContainerID, fileops.Request{Op: fileops.OpCopy, Paths: request.Paths, To: request.To}, reject)
}

func (c *containerStreams) handleFSArchive(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSArchive
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.archive does not match the protocol")
	}

	operation := fileops.Request{Op: fileops.OpArchive, Paths: request.Paths, To: request.To, Format: request.Format}

	return c.longFileOp(ctx, request.RequestID, request.ContainerID, operation, reject)
}

func (c *containerStreams) handleFSExtract(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSExtract
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.extract does not match the protocol")
	}

	operation := fileops.Request{Op: fileops.OpExtract, Path: request.Path, To: request.To}

	return c.longFileOp(ctx, request.RequestID, request.ContainerID, operation, reject)
}

func (c *containerStreams) handleFSCancel(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSCancel
	if err := protocol.DecodeStrict(data, &request); err != nil {
		return reject(ctx, "", "invalid_message", "fs.cancel does not match the protocol")
	}

	// An operation that already finished has nothing to cancel.
	c.operations.cancel(request.RequestID)

	return nil
}

// quickFileOp runs an operation that answers at once and writes the frame
// result builds from its response.
func (c *containerStreams) quickFileOp(ctx context.Context, requestID, containerID string, operation fileops.Request, reject rejectFunc, result func(fileops.Response) any) error {
	if c.files == nil {
		return reject(ctx, requestID, "containers_unavailable", "this node has no container runtime")
	}
	select {
	case c.fileRequests <- struct{}{}:
		c.wait.Add(1)
	default:
		return reject(ctx, requestID, "busy", "too many file requests are in progress")
	}

	go func() {
		defer c.wait.Done()
		defer func() { <-c.fileRequests }()

		// Starting a helper may take a while the first time, but a stuck
		// one must not hold the slot for the whole session.
		ctx, cancel := context.WithTimeout(c.ctx, quickFileTimeout)
		defer cancel()

		response, err := c.runFileOp(ctx, containerID, operation, nil)
		if err != nil {
			c.writeError(ctx, requestID, err)
			return
		}
		c.writeFrame(ctx, result(response))
	}()

	return nil
}

// longFileOp runs an operation that reports progress and can be cancelled.
func (c *containerStreams) longFileOp(ctx context.Context, requestID, containerID string, operation fileops.Request, reject rejectFunc) error {
	if c.files == nil {
		return reject(ctx, requestID, "containers_unavailable", "this node has no container runtime")
	}

	opCtx, cancel := context.WithCancel(c.ctx)
	if !c.operations.add(requestID, cancel) {
		cancel()
		return reject(ctx, requestID, "busy", fmt.Sprintf("at most %d file operations can run at once, each with its own request_id", protocol.MaxFSOperations))
	}
	c.wait.Add(1)

	go func() {
		defer c.wait.Done()
		defer c.operations.remove(requestID)
		defer cancel()

		response, err := c.runFileOp(opCtx, containerID, operation, func(progress fileops.Progress) {
			c.writeFrame(opCtx, protocol.FSProgress{Type: protocol.FSProgressType, RequestID: requestID, Items: progress.Items, Bytes: progress.Bytes})
		})
		if opCtx.Err() != nil && c.ctx.Err() == nil {
			err = &fileops.ResponseError{Code: fileops.CodeCancelled, Message: "the operation was cancelled"}
		}
		if err != nil {
			c.writeError(c.ctx, requestID, err)
			return
		}
		c.writeFrame(c.ctx, fsResult(requestID, containerID, response))
	}()

	c.logger.Info("container file operation", "container_id", containerID, "op", operation.Op)

	return nil
}

// runFileOp runs an operation without content and returns its final
// response, or the failure it reports as an error.
func (c *containerStreams) runFileOp(ctx context.Context, containerID string, operation fileops.Request, progress func(fileops.Progress)) (fileops.Response, error) {
	call, err := c.files.Start(ctx, containerID, operation)
	if err != nil {
		return fileops.Response{}, err
	}
	defer call.Close()

	for {
		response, err := call.Response(ctx)
		if err != nil {
			return fileops.Response{}, err
		}
		if !response.Final() {
			if progress != nil {
				progress(*response.Progress)
			}
			continue
		}
		if err := response.Err(); err != nil {
			return fileops.Response{}, err
		}
		return response, nil
	}
}

func (c *containerStreams) handleFSReadOpen(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSReadOpen
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.read.open does not match the protocol")
	}
	if c.files == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}
	if code, message := c.newStreamProblem(request.StreamID); code != "" {
		return reject(ctx, request.RequestID, code, message)
	}

	streamCtx, cancel := context.WithCancel(c.ctx)
	stream := newOutStream(request.StreamID, cancel)
	c.streams[request.StreamID] = stream
	c.wait.Add(1)
	go c.runRead(streamCtx, stream, request)

	return nil
}

func (c *containerStreams) runRead(ctx context.Context, stream *outStream, request protocol.FSReadOpen) {
	defer c.wait.Done()
	defer func() { c.finished <- stream.id }()
	defer stream.cancel()

	call, err := c.files.Start(ctx, request.ContainerID, fileops.Request{Op: fileops.OpRead, Path: request.Path, Offset: request.Offset})
	if err != nil {
		c.writeError(ctx, request.RequestID, err)
		return
	}
	defer call.Close()

	opened, err := call.Response(ctx)
	if err == nil {
		err = opened.Err()
	}
	if err != nil {
		c.writeError(ctx, request.RequestID, err)
		return
	}
	if opened.Entry == nil {
		c.writeError(ctx, request.RequestID, errors.New("the file helper sent no entry"))
		return
	}
	c.logger.Info("container file download", "container_id", request.ContainerID, "stream_id", stream.id, "type", opened.Entry.Type)
	if !c.writeFrame(ctx, protocol.FSReadOpened{
		Type:      protocol.FSReadOpenedType,
		RequestID: request.RequestID,
		StreamID:  stream.id,
		Entry:     fsEntry(*opened.Entry),
		Offset:    opened.Offset,
		Archive:   opened.Entry.Type == fileops.TypeDirectory,
	}) {
		return
	}

	err = c.forwardDownload(ctx, stream, call)
	if ctx.Err() != nil {
		return
	}
	closing := protocol.StreamClose{Type: protocol.StreamCloseType, StreamID: stream.id, Reason: protocol.StreamEnded}
	if err != nil {
		closing.Reason = protocol.StreamFailed
		closing.Code, _ = fileErrorCode(err)
		c.logger.Warn("container file download failed", "container_id", request.ContainerID, "error", err)
	}
	c.writeFrame(ctx, closing)
}

// forwardDownload copies helper content to the device as it grants credit.
func (c *containerStreams) forwardDownload(ctx context.Context, stream *outStream, call containerfiles.Call) error {
	buffer := make([]byte, protocol.MaxStreamChunkBytes)
	for {
		count, err := call.Read(ctx, buffer)
		if count > 0 {
			if takeErr := stream.take(ctx, int64(count)); takeErr != nil {
				return takeErr
			}
			if writeErr := c.writeBinary(ctx, protocol.StreamChannelFile, stream.id, buffer[:count]); writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(err, io.EOF) {
			final, err := call.Response(ctx)
			if err != nil {
				return err
			}
			return final.Err()
		}
		if err != nil {
			return err
		}
	}
}

func (c *containerStreams) handleFSWriteOpen(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.FSWriteOpen
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "fs.write.open does not match the protocol")
	}
	if c.files == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}
	if code, message := c.newStreamProblem(request.StreamID); code != "" {
		return reject(ctx, request.RequestID, code, message)
	}

	streamCtx, cancel := context.WithCancel(c.ctx)
	upload := &inStream{id: request.StreamID, cancel: cancel, inbox: fileops.NewInbox(protocol.StreamWindowBytes)}
	c.uploads[request.StreamID] = upload
	c.wait.Add(1)
	go c.runWrite(streamCtx, upload, request)

	return nil
}

func (c *containerStreams) runWrite(ctx context.Context, upload *inStream, request protocol.FSWriteOpen) {
	defer c.wait.Done()
	defer func() { c.finished <- upload.id }()
	defer upload.cancel()

	call, err := c.files.Start(ctx, request.ContainerID, fileops.Request{
		Op:              fileops.OpWrite,
		Path:            request.Path,
		Size:            request.Size,
		SHA256:          request.SHA256,
		ExpectedVersion: request.ExpectedVersion,
		Mode:            request.Mode,
	})
	if err != nil {
		c.writeError(ctx, request.RequestID, err)
		return
	}
	defer call.Close()

	ready, err := call.Response(ctx)
	if err == nil {
		err = ready.Err()
	}
	if err != nil {
		c.writeError(ctx, request.RequestID, err)
		return
	}
	if !c.writeFrame(ctx, protocol.FSWriteReady{Type: protocol.FSWriteReadyType, RequestID: request.RequestID, StreamID: upload.id, Offset: ready.Offset}) {
		return
	}

	err = c.forwardUpload(ctx, upload, call, request.Size-ready.Offset)
	var final fileops.Response
	if err == nil {
		final, err = call.Response(ctx)
	}
	if err == nil {
		err = final.Err()
	}
	if err == nil && final.Entry == nil {
		err = errors.New("the file helper sent no entry")
	}
	if err != nil {
		// A cancelled upload is not answered, as a cancelled stream.
		if ctx.Err() == nil {
			c.writeError(ctx, request.RequestID, err)
		}
		return
	}

	c.logger.Info("container file upload", "container_id", request.ContainerID, "stream_id", upload.id, "bytes", request.Size)
	c.writeFrame(ctx, protocol.FSWriteResult{Type: protocol.FSWriteResultType, RequestID: request.RequestID, StreamID: upload.id, Entry: fsEntry(*final.Entry)})
}

// forwardUpload passes remaining bytes from the device to the helper and
// returns credit to the device as the helper accepts them.
func (c *containerStreams) forwardUpload(ctx context.Context, upload *inStream, call containerfiles.Call, remaining int64) error {
	buffer := make([]byte, protocol.MaxStreamChunkBytes)
	unacknowledged := 0
	for remaining > 0 {
		readCtx, cancel := context.WithTimeout(ctx, uploadIdleTimeout)
		count, err := upload.inbox.Read(readCtx, buffer[:min(int64(len(buffer)), remaining)])
		timedOut := errors.Is(readCtx.Err(), context.DeadlineExceeded)
		cancel()
		if timedOut && count == 0 {
			return &fileops.ResponseError{Code: "upload_timeout", Message: "no data arrived in time"}
		}
		if err != nil && count == 0 {
			return err
		}

		if err := call.Write(ctx, buffer[:count]); err != nil {
			return err
		}
		remaining -= int64(count)
		unacknowledged += count
		if unacknowledged >= fileCreditBytes && remaining > 0 {
			if !c.writeFrame(ctx, protocol.StreamCredit{Type: protocol.StreamCreditType, StreamID: upload.id, Bytes: int64(unacknowledged)}) {
				return ctx.Err()
			}
			unacknowledged = 0
		}
	}

	return nil
}

// handleBinary queues upload data the device sends on channel 3.
func (c *containerStreams) handleBinary(ctx context.Context, data []byte, reject rejectFunc) error {
	if len(data) <= protocol.StreamFrameHeaderBytes || len(data) > protocol.StreamFrameHeaderBytes+protocol.MaxStreamChunkBytes || data[0] != protocol.StreamChannelFile {
		return reject(ctx, "", "invalid_frame", "a device sends binary frames only on channel 3 with 1 to 32768 bytes of data")
	}

	upload := c.uploads[binary.BigEndian.Uint32(data[1:protocol.StreamFrameHeaderBytes])]
	if upload == nil {
		// The upload ended while the frame was on its way.
		return nil
	}
	if err := upload.inbox.Put(data[protocol.StreamFrameHeaderBytes:]); err != nil {
		upload.inbox.Close(&fileops.ResponseError{Code: "invalid_credit", Message: "the device sent more than the node granted"})
	}

	return nil
}

// newStreamProblem returns the error code and message that refuse a new
// stream ID, or empty strings when it can be used.
func (c *containerStreams) newStreamProblem(id uint32) (string, string) {
	switch {
	case id == 0 || id > protocol.MaxStreamID:
		return "invalid_stream_id", "stream_id must be between 1 and 2147483647"
	case c.streamInUse(id):
		return "stream_id_in_use", "stream_id is already open"
	case len(c.streams)+len(c.uploads) >= protocol.MaxStreamsPerSession:
		return "too_many_streams", fmt.Sprintf("at most %d streams can be open", protocol.MaxStreamsPerSession)
	default:
		return "", ""
	}
}

func (c *containerStreams) streamInUse(id uint32) bool {
	_, download := c.streams[id]
	_, upload := c.uploads[id]

	return download || upload
}

func fileErrorCode(err error) (string, string) {
	if response, ok := errors.AsType[*fileops.ResponseError](err); ok {
		return response.Code, response.Message
	}

	codes := []struct {
		err  error
		code string
	}{
		{containerfiles.ErrNoVolumes, "no_volumes"},
		{containerfiles.ErrBusy, "busy"},
		{containerfiles.ErrUnavailable, "files_unavailable"},
		{fileops.ErrHelperGone, "files_unavailable"},
	}
	for _, known := range codes {
		if errors.Is(err, known.err) {
			return known.code, err.Error()
		}
	}

	return containerErrorCode(err)
}

func fsResult(requestID, containerID string, response fileops.Response) protocol.FSResult {
	result := protocol.FSResult{
		Type:        protocol.FSResultType,
		RequestID:   requestID,
		ContainerID: containerID,
		Entries:     fsEntries(response.Entries),
		Skipped:     response.Skipped,
	}
	if response.Entry != nil {
		entry := fsEntry(*response.Entry)
		result.Entry = &entry
	}
	if response.Progress != nil {
		result.Items, result.Bytes = response.Progress.Items, response.Progress.Bytes
	}

	return result
}

func fsEntries(entries []fileops.Entry) []protocol.FSEntry {
	result := make([]protocol.FSEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, fsEntry(entry))
	}

	return result
}

func fsEntry(entry fileops.Entry) protocol.FSEntry {
	return protocol.FSEntry{
		Name:       entry.Name,
		Type:       entry.Type,
		Size:       entry.Size,
		Mode:       entry.Mode,
		UID:        entry.UID,
		GID:        entry.GID,
		ModifiedAt: entry.ModifiedAt,
		LinkTarget: entry.LinkTarget,
		Version:    entry.Version,
		Mount:      entry.Mount,
		Virtual:    entry.Virtual,
		ReadOnly:   entry.ReadOnly,
	}
}
