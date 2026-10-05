package containerio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

const (
	// MaxLogTail bounds how many past lines a log stream starts with.
	MaxLogTail = 10_000
	// MaxChunkBytes bounds one piece of log output handed to a sink.
	MaxChunkBytes = 32 * 1024
)

// Stream names the container output a log chunk came from. A container with
// a TTY has a single stream, reported as Stdout.
type Stream int

const (
	Stdout Stream = iota + 1
	Stderr
)

// LogOptions selects which part of a container log is streamed.
type LogOptions struct {
	// Tail is the number of past lines to start with, 0 to MaxLogTail.
	Tail int
	// Since skips older entries when it is not zero.
	Since time.Time
	// Follow keeps the stream open for new output.
	Follow     bool
	Timestamps bool
}

// LogStream is an open container log.
type LogStream interface {
	// TTY reports that stdout and stderr are merged and may carry terminal
	// control sequences.
	TTY() bool
	// Copy hands the log to sink in chunks of at most MaxChunkBytes until
	// the log ends. sink may block to apply back-pressure and must not keep
	// data after it returns. A nil error means the log ended normally.
	Copy(sink func(Stream, []byte) error) error
	Close() error
}

// dockerLog is a log read from the Docker Engine API.
type dockerLog struct {
	tty    bool
	reader io.ReadCloser
}

// Logs opens the log of a container through Docker. Docker serves logs only
// for the local, json-file, and journald drivers or with dual logging.
func (s *Service) Logs(ctx context.Context, containerID string, options LogOptions) (LogStream, error) {
	if options.Tail < 0 || options.Tail > MaxLogTail {
		return nil, fmt.Errorf("tail must be between 0 and %d", MaxLogTail)
	}

	inspection, err := s.inspect(ctx, containerID)
	if err != nil {
		return nil, err
	}

	logOptions := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     options.Follow,
		Timestamps: options.Timestamps,
		Tail:       strconv.Itoa(options.Tail),
	}
	if !options.Since.IsZero() {
		logOptions.Since = strconv.FormatInt(options.Since.Unix(), 10)
	}

	reader, err := s.engine.ContainerLogs(ctx, containerID, logOptions)
	if err != nil {
		return nil, fmt.Errorf("open container logs: %w", err)
	}

	return &dockerLog{tty: inspection.Container.Config.Tty, reader: reader}, nil
}

func (l *dockerLog) TTY() bool { return l.tty }

func (l *dockerLog) Copy(sink func(Stream, []byte) error) error {
	if l.tty {
		return copyChunks(l.reader, func(data []byte) error { return sink(Stdout, data) })
	}

	stdout := &chunkWriter{stream: Stdout, sink: sink}
	stderr := &chunkWriter{stream: Stderr, sink: sink}
	_, err := stdcopy.StdCopy(stdout, stderr, l.reader)

	return err
}

func (l *dockerLog) Close() error {
	return l.reader.Close()
}

func copyChunks(reader io.Reader, sink func([]byte) error) error {
	buffer := make([]byte, MaxChunkBytes)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			if sinkErr := sink(buffer[:count]); sinkErr != nil {
				return sinkErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// chunkWriter splits demultiplexed output into sink-sized chunks.
type chunkWriter struct {
	stream Stream
	sink   func(Stream, []byte) error
}

func (w *chunkWriter) Write(data []byte) (int, error) {
	written := 0
	for written < len(data) {
		end := min(written+MaxChunkBytes, len(data))
		if err := w.sink(w.stream, data[written:end]); err != nil {
			return written, err
		}
		written = end
	}

	return written, nil
}
