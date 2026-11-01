package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

type fakeFrameConn struct {
	mu      sync.Mutex
	written [][]byte
	frames  chan []byte
}

func (c *fakeFrameConn) Read(ctx context.Context) ([]byte, error) {
	select {
	case frame, ok := <-c.frames:
		if !ok {
			return nil, io.EOF
		}

		return frame, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeFrameConn) Write(_ context.Context, frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.written = append(c.written, append([]byte(nil), frame...))

	return nil
}

func TestBridgeCopiesInputLinesToNode(t *testing.T) {
	conn := &fakeFrameConn{frames: make(chan []byte)}
	var output bytes.Buffer

	err := bridge(t.Context(), conn, []byte(`{"type":"hello"}`), strings.NewReader("{\"a\":1}\n{\"b\":2}\n"), &output)
	if err != nil {
		t.Fatal(err)
	}

	if got := output.String(); got != "{\"type\":\"hello\"}\n" {
		t.Fatalf("output = %q, want only the hello line", got)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if len(conn.written) != 2 || string(conn.written[0]) != `{"a":1}` || string(conn.written[1]) != `{"b":2}` {
		t.Fatalf("frames to node = %q", conn.written)
	}
}

func TestBridgeWritesNodeFramesAsCompactLines(t *testing.T) {
	conn := &fakeFrameConn{frames: make(chan []byte, 1)}
	conn.frames <- []byte("{\n  \"type\": \"report\"\n}")
	close(conn.frames)

	input, inputWriter := io.Pipe()
	defer inputWriter.Close()

	var output bytes.Buffer
	err := bridge(t.Context(), conn, []byte(`{}`), input, &output)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("bridge() error = %v, want the node's end of session", err)
	}

	if got := output.String(); got != "{}\n{\"type\":\"report\"}\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestBridgeRejectsInvalidNodeFrame(t *testing.T) {
	conn := &fakeFrameConn{frames: make(chan []byte, 1)}
	conn.frames <- []byte("not json")

	input, inputWriter := io.Pipe()
	defer inputWriter.Close()

	err := bridge(t.Context(), conn, []byte(`{}`), input, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("bridge() error = %v, want invalid JSON", err)
	}
}
