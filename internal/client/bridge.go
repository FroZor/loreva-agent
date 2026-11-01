package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// MaxBridgeLine bounds one frame on the bridge input; the node accepts
// frames up to 64 KiB.
const MaxBridgeLine = 64 * 1024

// frameConn is the part of a Session the bridge uses.
type frameConn interface {
	Read(ctx context.Context) ([]byte, error)
	Write(ctx context.Context, frame []byte) error
}

// Bridge writes the node's hello to output as one JSON line, then copies
// frames in both directions until either side closes: every line of input
// is one frame to the node, and every frame from the node is one compact
// JSON line on output. It returns nil when ctx ends, the input's error (nil
// at EOF) when the input closes, and an error when the node ends the session.
func (s *Session) Bridge(ctx context.Context, input io.Reader, output io.Writer) error {
	hello, err := json.Marshal(s.Hello)
	if err != nil {
		return err
	}

	return bridge(ctx, s, hello, input, output)
}

func bridge(ctx context.Context, conn frameConn, hello []byte, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if _, err := output.Write(append(hello, '\n')); err != nil {
		return err
	}

	lines := bufio.NewScanner(input)
	lines.Buffer(make([]byte, 0, 4096), MaxBridgeLine)

	inputDone := make(chan error, 1)
	go func() {
		for lines.Scan() {
			if err := conn.Write(ctx, lines.Bytes()); err != nil {
				inputDone <- err
				return
			}
		}

		inputDone <- lines.Err()
	}()

	frames := make(chan []byte)
	readDone := make(chan error, 1)
	go func() {
		for {
			frame, err := conn.Read(ctx)
			if err != nil {
				readDone <- err
				return
			}

			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-inputDone:
			// The app closed the input: it is done with the session.
			return err
		case err := <-readDone:
			return fmt.Errorf("node session ended: %w", err)
		case frame := <-frames:
			var line bytes.Buffer
			if err := json.Compact(&line, frame); err != nil {
				return fmt.Errorf("node sent a frame that is not valid JSON: %w", err)
			}
			line.WriteByte('\n')

			if _, err := output.Write(line.Bytes()); err != nil {
				return err
			}
		}
	}
}
