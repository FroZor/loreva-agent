package fileops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ErrHelperGone reports that the helper stopped while a call was running.
var ErrHelperGone = errors.New("the file helper stopped")

// responseBuffer is how many responses a call queues; progress responses
// are dropped once half of it is in use, so final ones always fit.
const responseBuffer = 16

// Client is the agent side of the helper protocol. It multiplexes calls
// over one helper's stdin and stdout.
type Client struct {
	writeMu sync.Mutex
	writer  io.Writer

	mu    sync.Mutex
	calls map[uint32]*Call
	next  uint32
	err   error
	done  chan struct{}
}

// NewClient starts reading helper frames from reader. Callers must Init it
// before any other call.
func NewClient(reader io.Reader, writer io.Writer) *Client {
	client := &Client{writer: writer, calls: make(map[uint32]*Call), done: make(chan struct{})}
	go client.readLoop(reader)

	return client
}

// Done is closed when the helper's output ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Init names the mounts the helper serves.
func (c *Client) Init(ctx context.Context, mounts []Mount) error {
	response, err := c.Do(ctx, Request{Op: OpInit, Mounts: mounts})
	if err != nil {
		return err
	}

	return response.Err()
}

// Do runs a call that has no content and returns its final response.
// Progress responses are skipped.
func (c *Client) Do(ctx context.Context, request Request) (Response, error) {
	call, err := c.Start(request)
	if err != nil {
		return Response{}, err
	}
	defer call.Close()

	for {
		response, err := call.Response(ctx)
		if err != nil {
			return Response{}, err
		}
		if response.Final() {
			return response, nil
		}
	}
}

// Start sends a request and returns its call. The caller must Close it.
func (c *Client) Start(request Request) (*Call, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	c.next++
	call := &Call{
		client:    c,
		id:        c.next,
		phases:    1,
		responses: make(chan Response, responseBuffer),
		inbox:     NewInbox(WindowBytes),
		send:      NewWindow(WindowBytes),
	}
	if request.Op == OpRead || request.Op == OpWrite {
		call.phases = 2
	}
	c.calls[call.id] = call
	c.mu.Unlock()

	if err := c.writeFrame(FrameRequest, call.id, payload); err != nil {
		c.forget(call.id)
		return nil, err
	}

	return call, nil
}

func (c *Client) readLoop(reader io.Reader) {
	var err error
	for {
		var frame Frame
		frame, err = ReadFrame(reader)
		if err != nil {
			break
		}
		if err = c.route(frame); err != nil {
			break
		}
	}

	c.mu.Lock()
	c.err = fmt.Errorf("%w: %w", ErrHelperGone, err)
	calls := c.calls
	c.calls = map[uint32]*Call{}
	c.mu.Unlock()
	for _, call := range calls {
		call.inbox.Close(ErrHelperGone)
	}
	close(c.done)
}

func (c *Client) route(frame Frame) error {
	c.mu.Lock()
	call := c.calls[frame.Call]
	c.mu.Unlock()
	if call == nil {
		// The call was closed while the frame was on its way.
		return nil
	}

	switch frame.Kind {
	case FrameResponse:
		var response Response
		if err := json.Unmarshal(frame.Payload, &response); err != nil {
			return fmt.Errorf("decode helper response: %w", err)
		}
		call.deliver(response)
	case FrameData:
		// Data for a call closed meanwhile is dropped; only a helper that
		// ignores its window is broken.
		if err := call.inbox.Put(frame.Payload); errors.Is(err, ErrWindowExceeded) {
			return fmt.Errorf("helper data for call %d: %w", frame.Call, err)
		}
	case FrameCredit:
		credit, err := ParseCredit(frame.Payload)
		if err != nil {
			return err
		}
		if err := call.send.Grant(credit); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected helper frame kind %d", frame.Kind)
	}

	return nil
}

func (c *Client) forget(id uint32) {
	c.mu.Lock()
	delete(c.calls, id)
	c.mu.Unlock()
}

func (c *Client) writeFrame(kind byte, id uint32, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return WriteFrame(c.writer, kind, id, payload)
}

// Call is one request in flight.
type Call struct {
	client *Client
	id     uint32
	// phases is how many successful responses end the call: two for read
	// and write, whose first response opens the content.
	phases    int
	responses chan Response
	inbox     *Inbox
	send      *Window
	consumed  int

	mu       sync.Mutex
	answered int
	finished bool
}

// Final reports whether a response ends its call's current phase rather
// than reporting progress.
func (r Response) Final() bool {
	return r.Progress == nil || r.OK || r.Code != ""
}

// Err returns the failure a response reports, or nil.
func (r Response) Err() error {
	if r.OK {
		return nil
	}

	return &ResponseError{Code: r.Code, Message: r.Message}
}

// ResponseError is a failure the helper reported.
type ResponseError struct {
	Code    string
	Message string
}

func (e *ResponseError) Error() string { return e.Code + ": " + e.Message }

func (c *Call) deliver(response Response) {
	if !response.Final() {
		if len(c.responses) < responseBuffer/2 {
			c.responses <- response
		}
		return
	}

	c.mu.Lock()
	c.answered++
	last := !response.OK || c.answered >= c.phases
	c.finished = c.finished || last
	c.mu.Unlock()

	if last {
		c.client.forget(c.id)
		if response.OK {
			c.inbox.Close(nil)
		} else {
			c.inbox.Close(response.Err())
		}
	}
	c.responses <- response
}

// Response waits for the next response of the call.
func (c *Call) Response(ctx context.Context) (Response, error) {
	select {
	case response := <-c.responses:
		return response, nil
	default:
	}

	select {
	case response := <-c.responses:
		return response, nil
	case <-c.client.done:
		select {
		case response := <-c.responses:
			return response, nil
		default:
			return Response{}, ErrHelperGone
		}
	case <-ctx.Done():
		return Response{}, ctx.Err()
	}
}

// Read reads content the helper sends. It returns io.EOF after the final
// successful response and returns credit to the helper as it goes.
func (c *Call) Read(ctx context.Context, buffer []byte) (int, error) {
	count, err := c.inbox.Read(ctx, buffer)
	c.consumed += count
	if c.consumed >= creditBatchBytes {
		if creditErr := c.client.writeFrame(FrameCredit, c.id, CreditPayload(c.consumed)); creditErr != nil {
			return count, creditErr
		}
		c.consumed = 0
	}

	return count, err
}

// Write sends content to the helper, waiting for credit.
func (c *Call) Write(ctx context.Context, data []byte) error {
	for len(data) > 0 {
		size := min(len(data), DataChunkBytes)
		if err := c.send.Take(ctx, size); err != nil {
			return err
		}
		if err := c.client.writeFrame(FrameData, c.id, data[:size]); err != nil {
			return err
		}
		data = data[size:]
	}

	return nil
}

// Close ends the call; a call that has not finished is cancelled.
func (c *Call) Close() {
	c.mu.Lock()
	finished := c.finished
	c.finished = true
	c.mu.Unlock()
	if finished {
		return
	}

	c.client.forget(c.id)
	c.inbox.Close(context.Canceled)
	_ = c.client.writeFrame(FrameCancel, c.id, nil)
}
