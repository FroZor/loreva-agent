package control

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnSendReceiveRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	want := Message{Type: TypeInviteCreated, Invite: "key", ExpiresAt: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	go func() {
		_ = NewConn(client).Send(want)
	}()

	got, err := NewConn(server).Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Invite != want.Invite || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("Receive() = %#v, want %#v", got, want)
	}
}

func TestConnReceiveRejectsInvalidMessages(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "missing type", input: "{}\n", want: "type is required"},
		{name: "unknown field", input: `{"type":"devices","extra":1}` + "\n", want: "decode control message"},
		{name: "not JSON", input: "nope\n", want: "decode control message"},
		{name: "oversized", input: `{"type":"error","error":"` + strings.Repeat("a", maxMessageSize) + "\"}\n", want: "exceeds 64 KiB"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := receiveFrom(t, test.input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Receive() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestConnReceiveRejectsTruncatedMessage(t *testing.T) {
	if _, err := receiveFrom(t, `{"type":"devices"`); err == nil {
		t.Fatal("Receive() accepted a truncated message")
	}
}

func TestConnReceiveReportsCleanEOF(t *testing.T) {
	_, err := receiveFrom(t, "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Receive() error = %v, want EOF", err)
	}
}

func TestDialRejectsLongSocketPath(t *testing.T) {
	_, err := Dial("/" + strings.Repeat("d", maxSocketPath))
	if err == nil || !strings.Contains(err.Error(), "shorter --state-dir") {
		t.Fatalf("Dial() error = %v, want a socket path error", err)
	}
}

// receiveFrom feeds input to a Conn and closes the writing side after it.
func receiveFrom(t *testing.T, input string) (Message, error) {
	t.Helper()

	client, server := net.Pipe()
	defer server.Close()

	go func() {
		_, _ = io.WriteString(client, input)
		client.Close()
	}()

	return NewConn(server).Receive()
}
