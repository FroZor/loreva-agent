package fileops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// creditBatchBytes is how much consumed data a receiver collects before it
// returns credit.
const creditBatchBytes = 256 * 1024

// ErrWindowExceeded reports a sender that ignored the credit it was given.
var ErrWindowExceeded = errors.New("data exceeds the granted window")

// Window is the send side of credit-based flow control.
type Window struct {
	mu        sync.Mutex
	available int
	limit     int
	notify    chan struct{}
}

// NewWindow returns a window that starts with limit bytes of credit.
func NewWindow(limit int) *Window {
	return &Window{available: limit, limit: limit, notify: make(chan struct{}, 1)}
}

// Grant adds credit; the window never grows past its initial size.
func (w *Window) Grant(bytes int) error {
	w.mu.Lock()
	if bytes <= 0 || w.available+bytes > w.limit {
		w.mu.Unlock()
		return fmt.Errorf("credit of %d bytes would exceed the %d-byte window", bytes, w.limit)
	}
	w.available += bytes
	w.mu.Unlock()

	select {
	case w.notify <- struct{}{}:
	default:
	}

	return nil
}

// Take waits until bytes of credit are available and uses them.
func (w *Window) Take(ctx context.Context, bytes int) error {
	for {
		w.mu.Lock()
		if w.available >= bytes {
			w.available -= bytes
			w.mu.Unlock()
			return nil
		}
		w.mu.Unlock()

		select {
		case <-w.notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Inbox is the receive side: a bounded byte queue that the frame reader
// fills without blocking and a consumer drains.
type Inbox struct {
	mu     sync.Mutex
	data   []byte
	limit  int
	err    error
	notify chan struct{}
}

// NewInbox returns an inbox that holds at most limit unread bytes.
func NewInbox(limit int) *Inbox {
	return &Inbox{limit: limit, notify: make(chan struct{}, 1)}
}

// Put queues data. It fails instead of blocking when the sender ignored
// its window.
func (b *Inbox) Put(data []byte) error {
	b.mu.Lock()
	if b.err != nil {
		b.mu.Unlock()
		return b.err
	}
	if len(b.data)+len(data) > b.limit {
		b.mu.Unlock()
		return ErrWindowExceeded
	}
	b.data = append(b.data, data...)
	b.mu.Unlock()
	b.wake()

	return nil
}

// Close ends the inbox: readers get the queued data and then err, or
// io.EOF when err is nil. Only the first call counts.
func (b *Inbox) Close(err error) {
	if err == nil {
		err = io.EOF
	}

	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()
	b.wake()
}

// Read waits for data. Cancelling ctx makes it return ctx.Err().
func (b *Inbox) Read(ctx context.Context, buffer []byte) (int, error) {
	for {
		b.mu.Lock()
		if len(b.data) > 0 {
			count := copy(buffer, b.data)
			b.data = b.data[count:]
			if len(b.data) == 0 {
				b.data = nil
			}
			b.mu.Unlock()
			return count, nil
		}
		err := b.err
		b.mu.Unlock()
		if err != nil {
			return 0, err
		}

		select {
		case <-b.notify:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (b *Inbox) wake() {
	select {
	case b.notify <- struct{}{}:
	default:
	}
}
