package fileops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// maxCalls bounds the calls one helper runs at once.
	maxCalls = 32
	// creditBatchBytes is how much consumed data the helper collects before
	// it returns credit.
	creditBatchBytes = 256 * 1024
	// progressInterval spaces progress responses.
	progressInterval = 250 * time.Millisecond
)

// Serve runs the helper side of the protocol until in ends. The first frame
// must be an init request naming the mounts the helper may use.
func Serve(in io.Reader, out io.Writer) error {
	first, err := ReadFrame(in)
	if err != nil {
		return fmt.Errorf("read init: %w", err)
	}

	server := &server{out: out, calls: make(map[uint32]*call)}
	var request Request
	if first.Kind != FrameRequest || json.Unmarshal(first.Payload, &request) != nil || request.Op != OpInit {
		return errors.New("the first frame must be an init request")
	}
	mounts, err := openMounts(request.Mounts)
	if err != nil {
		_ = server.respond(first.Call, failure(err))
		return err
	}
	defer mounts.close()
	server.mounts = mounts
	if err := server.respond(first.Call, Response{OK: true}); err != nil {
		return err
	}

	err = server.readLoop(in)
	server.stop()
	if errors.Is(err, io.EOF) {
		return nil
	}

	return err
}

type server struct {
	mounts *mounts

	writeMu sync.Mutex
	out     io.Writer

	mu    sync.Mutex
	calls map[uint32]*call
	wait  sync.WaitGroup
}

// call is one running request.
type call struct {
	id     uint32
	ctx    context.Context
	cancel context.CancelFunc
	server *server
	// send limits data frames to the agent; inbox holds data from it.
	send  *Window
	inbox *Inbox
}

func (s *server) readLoop(in io.Reader) error {
	for {
		frame, err := ReadFrame(in)
		if err != nil {
			return err
		}

		switch frame.Kind {
		case FrameRequest:
			s.start(frame)
		case FrameData, FrameEnd, FrameCancel, FrameCredit:
			s.route(frame)
		default:
			return fmt.Errorf("unknown frame kind %d", frame.Kind)
		}
	}
}

func (s *server) start(frame Frame) {
	var request Request
	if err := json.Unmarshal(frame.Payload, &request); err != nil {
		_ = s.respond(frame.Call, Response{Code: CodeInvalidRequest, Message: "the request is not valid JSON"})
		return
	}

	s.mu.Lock()
	if _, exists := s.calls[frame.Call]; exists || len(s.calls) >= maxCalls {
		s.mu.Unlock()
		_ = s.respond(frame.Call, Response{Code: CodeBusy, Message: "the call id is in use or too many calls are running"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	current := &call{
		id:     frame.Call,
		ctx:    ctx,
		cancel: cancel,
		server: s,
		send:   NewWindow(WindowBytes),
		inbox:  NewInbox(WindowBytes),
	}
	s.calls[frame.Call] = current
	s.wait.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wait.Done()
		defer s.finish(current)

		response := s.dispatch(current, request)
		_ = s.respond(current.id, response)
	}()
}

func (s *server) route(frame Frame) {
	s.mu.Lock()
	current := s.calls[frame.Call]
	s.mu.Unlock()
	if current == nil {
		// The call ended while the frame was on its way.
		return
	}

	switch frame.Kind {
	case FrameData:
		if err := current.inbox.Put(frame.Payload); err != nil {
			current.inbox.Close(err)
			current.cancel()
		}
	case FrameEnd:
		current.inbox.Close(nil)
	case FrameCancel:
		current.cancel()
	case FrameCredit:
		credit, err := ParseCredit(frame.Payload)
		if err == nil {
			err = current.send.Grant(credit)
		}
		if err != nil {
			current.cancel()
		}
	}
}

func (s *server) finish(current *call) {
	current.cancel()
	current.inbox.Close(context.Canceled)

	s.mu.Lock()
	delete(s.calls, current.id)
	s.mu.Unlock()
}

// stop cancels every call and waits for them after the agent went away.
func (s *server) stop() {
	s.mu.Lock()
	for _, current := range s.calls {
		current.cancel()
	}
	s.mu.Unlock()
	s.wait.Wait()
}

func (s *server) dispatch(current *call, request Request) Response {
	var (
		response Response
		err      error
	)

	switch request.Op {
	case OpList:
		response, err = s.mounts.list(request.Path, request.After)
	case OpStat:
		response, err = s.mounts.statEntry(request.Path)
	case OpMkdir:
		response, err = s.mounts.mkdir(request.Path)
	case OpRename:
		response, err = s.mounts.rename(request.Path, request.To)
	case OpChmod:
		response, err = s.mounts.chmod(request.Path, request.Mode)
	case OpDelete:
		response, err = s.mounts.delete(current, request.Paths)
	case OpCopy:
		response, err = s.mounts.copyPaths(current, request.Paths, request.To)
	case OpArchive:
		response, err = s.mounts.archive(current, request.Paths, request.To, request.Format)
	case OpExtract:
		response, err = s.mounts.extract(current, request.Path, request.To)
	case OpRead:
		response, err = s.mounts.read(current, request.Path, request.Offset)
	case OpWrite:
		response, err = s.mounts.write(current, request)
	default:
		err = codedError(CodeInvalidRequest, "unknown operation "+request.Op)
	}
	if err != nil {
		if current.ctx.Err() != nil {
			return Response{Code: CodeCancelled, Message: "the operation was cancelled"}
		}
		return failure(err)
	}
	response.OK = true

	return response
}

func (s *server) respond(id uint32, response Response) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}

	return s.writeFrame(FrameResponse, id, payload)
}

func (s *server) writeFrame(kind byte, id uint32, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return WriteFrame(s.out, kind, id, payload)
}

// progress sends a progress response, at most once per progressInterval.
type progress struct {
	call  *call
	state Progress
	sent  time.Time
}

func (p *progress) add(items, bytes int64) {
	p.state.Items += items
	p.state.Bytes += bytes
	if time.Since(p.sent) < progressInterval {
		return
	}

	p.sent = time.Now()
	snapshot := p.state
	_ = p.call.server.respond(p.call.id, Response{Progress: &snapshot})
}

// dataWriter sends file content to the agent in data frames, waiting for
// credit.
type dataWriter struct {
	call *call
}

func (w dataWriter) Write(data []byte) (int, error) {
	written := 0
	for written < len(data) {
		end := min(written+DataChunkBytes, len(data))
		if err := w.call.send.Take(w.call.ctx, end-written); err != nil {
			return written, err
		}
		if err := w.call.server.writeFrame(FrameData, w.call.id, data[written:end]); err != nil {
			return written, err
		}
		written = end
	}

	return written, nil
}

// dataReader reads content the agent sends and returns credit as it is
// consumed.
type dataReader struct {
	call     *call
	consumed int
}

func (r *dataReader) Read(buffer []byte) (int, error) {
	count, err := r.call.inbox.Read(r.call.ctx, buffer)
	r.consumed += count
	if r.consumed >= creditBatchBytes {
		if creditErr := r.call.server.writeFrame(FrameCredit, r.call.id, CreditPayload(r.consumed)); creditErr != nil {
			return count, creditErr
		}
		r.consumed = 0
	}

	return count, err
}
