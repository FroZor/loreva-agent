package direct_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

var testContainerID = string(bytes.Repeat([]byte("ab"), 32))

// fakeContainers serves a fixed log and echoes console commands.
type fakeContainers struct {
	mu       sync.Mutex
	commands []string
}

func (f *fakeContainers) Logs(_ context.Context, containerID string, _ containerio.LogOptions) (containerio.LogStream, error) {
	if containerID != testContainerID {
		return nil, containerio.ErrNotFound
	}

	return &fakeLog{}, nil
}

func (f *fakeContainers) ConsoleAdapter(context.Context, string) (containerio.Adapter, error) {
	return containerio.AdapterRCON, nil
}

func (f *fakeContainers) SendCommand(_ context.Context, _ string, command string) (containerio.CommandResult, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()

	return containerio.CommandResult{Adapter: containerio.AdapterRCON, Output: "ran " + command}, nil
}

// fakeInventory lists one container and describes it.
type fakeInventory struct{}

func (fakeInventory) List(context.Context) (protocol.ContainersListResult, error) {
	return protocol.ContainersListResult{
		Engine: protocol.ContainerEngine{Runtime: "docker", Version: "29.6.2", SecurityOptions: []string{}, Warnings: []string{}},
		Items:  []protocol.ContainerSummary{{ContainerID: testContainerID, Name: "minecraft", State: "exited", Health: "none", Ports: []protocol.ContainerPort{}}},
	}, nil
}

func (fakeInventory) Inspect(_ context.Context, containerID string, _ bool) (protocol.ContainerDetails, error) {
	if containerID != testContainerID {
		return protocol.ContainerDetails{}, containerio.ErrNotFound
	}

	return protocol.ContainerDetails{ContainerID: containerID, Name: "minecraft", Env: []string{"EULA=TRUE"}}, nil
}

// fakeLog emits more stdout than one stream window plus a stderr line.
type fakeLog struct{}

const fakeLogStdoutBytes = protocol.StreamWindowBytes + 3*protocol.MaxStreamChunkBytes

func (*fakeLog) TTY() bool { return false }

func (*fakeLog) Copy(sink func(containerio.Stream, []byte) error) error {
	chunk := bytes.Repeat([]byte("o"), protocol.MaxStreamChunkBytes)
	for sent := 0; sent < fakeLogStdoutBytes; sent += len(chunk) {
		if err := sink(containerio.Stdout, chunk); err != nil {
			return err
		}
	}

	return sink(containerio.Stderr, []byte("warning\n"))
}

func (*fakeLog) Close() error { return nil }

func TestDeviceContainerLogsUseCredit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	send(ctx, t, session, protocol.ContainerLogsOpen{
		Type: protocol.ContainerLogsOpenType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		StreamID: 7, ContainerID: testContainerID, Tail: 100, Follow: true,
	})

	var stdout, stderr int
	opened, closed := false, false
	for !closed {
		isBinary, data, err := session.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if isBinary {
			if !opened {
				t.Fatal("stream data arrived before container.logs.opened")
			}
			if len(data) <= protocol.StreamFrameHeaderBytes || binary.BigEndian.Uint32(data[1:5]) != 7 {
				t.Fatalf("bad stream frame header % x", data[:min(len(data), 5)])
			}
			payload := len(data) - protocol.StreamFrameHeaderBytes
			switch data[0] {
			case protocol.StreamChannelStdout:
				stdout += payload
			case protocol.StreamChannelStderr:
				stderr += payload
			}
			// Grant the consumed bytes back, as a reader that keeps up does.
			send(ctx, t, session, protocol.StreamCredit{Type: protocol.StreamCreditType, StreamID: 7, Bytes: int64(payload)})
			continue
		}

		messageType, err := protocol.MessageType(data)
		if err != nil {
			t.Fatalf("frame is not JSON: %s", data)
		}
		switch messageType {
		case protocol.ContainerLogsOpenedType:
			opened = true
		case protocol.StreamCloseType:
			var closing protocol.StreamClose
			if err := protocol.DecodeStrict(data, &closing); err != nil || closing.Reason != protocol.StreamEnded {
				t.Fatalf("stream.close = %s", data)
			}
			closed = true
		default:
			acknowledge(ctx, t, session, messageType, data, protocol.StreamCloseType)
		}
	}

	if stdout != fakeLogStdoutBytes || stderr != len("warning\n") {
		t.Fatalf("received stdout=%d stderr=%d", stdout, stderr)
	}
}

func TestDeviceContainerLogsStopWithoutCredit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	send(ctx, t, session, protocol.ContainerLogsOpen{
		Type: protocol.ContainerLogsOpenType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		StreamID: 1, ContainerID: testContainerID, Tail: 100,
	})

	received := 0
	for received < protocol.StreamWindowBytes {
		isBinary, data, err := session.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if isBinary {
			received += len(data) - protocol.StreamFrameHeaderBytes
			continue
		}
		if messageType, _ := protocol.MessageType(data); messageType != protocol.ContainerLogsOpenedType {
			acknowledge(ctx, t, session, messageType, data, "stream data")
		}
	}

	// With the window used up the node must wait; a cancel ends the stream
	// and the session keeps working.
	send(ctx, t, session, protocol.StreamClose{Type: protocol.StreamCloseType, StreamID: 1, Reason: protocol.StreamCancelled})
	send(ctx, t, session, protocol.ContainerConsoleInfo{
		Type: protocol.ContainerConsoleInfoType, RequestID: "6e0c1d91-5145-440f-bf97-d84db4f83644", ContainerID: testContainerID,
	})
	for {
		isBinary, data, err := session.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if isBinary {
			t.Fatalf("node sent %d bytes beyond the window", len(data)-protocol.StreamFrameHeaderBytes)
		}
		messageType, _ := protocol.MessageType(data)
		if messageType == protocol.ContainerConsoleInfoResultType {
			return
		}
		if messageType == protocol.StreamCloseType {
			t.Fatalf("node echoed a cancelled stream: %s", data)
		}
		acknowledge(ctx, t, session, messageType, data, protocol.ContainerConsoleInfoResultType)
	}
}

func TestDeviceContainerConsole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	send(ctx, t, session, protocol.ContainerConsoleSend{
		Type: protocol.ContainerConsoleSendType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		ContainerID: testContainerID, Command: "list",
	})
	var result protocol.ContainerConsoleSendResult
	expect(ctx, t, session, protocol.ContainerConsoleSendResultType, &result)
	if result.Adapter != "rcon" || result.Output != "ran list" {
		t.Fatalf("console result = %+v", result)
	}

	// A command that smuggles a second line is refused before it reaches
	// the container.
	send(ctx, t, session, protocol.ContainerConsoleSend{
		Type: protocol.ContainerConsoleSendType, RequestID: "6e0c1d91-5145-440f-bf97-d84db4f83644",
		ContainerID: testContainerID, Command: "say hi\nop attacker",
	})
	var refusal protocol.Error
	expect(ctx, t, session, protocol.ErrorType, &refusal)
	if refusal.Code != "invalid_command" {
		t.Fatalf("refusal = %+v", refusal)
	}

	node.containers.mu.Lock()
	defer node.containers.mu.Unlock()
	if len(node.containers.commands) != 1 {
		t.Fatalf("container received %q", node.containers.commands)
	}
}

func TestDeviceContainerInventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	send(ctx, t, session, protocol.ContainersList{Type: protocol.ContainersListType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"})
	var list protocol.ContainersListResult
	expect(ctx, t, session, protocol.ContainersListResultType, &list)
	if list.RequestID != "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65" || len(list.Items) != 1 || list.Items[0].State != "exited" {
		t.Fatalf("list = %+v", list)
	}

	send(ctx, t, session, protocol.ContainerInspect{
		Type: protocol.ContainerInspectType, RequestID: "6e0c1d91-5145-440f-bf97-d84db4f83644", ContainerID: testContainerID,
	})
	var inspected protocol.ContainerInspectResult
	expect(ctx, t, session, protocol.ContainerInspectResultType, &inspected)
	if inspected.Container.Name != "minecraft" || len(inspected.Container.Env) != 1 {
		t.Fatalf("inspect = %+v", inspected)
	}

	send(ctx, t, session, protocol.ContainerInspect{
		Type: protocol.ContainerInspectType, RequestID: "0d1b7f56-39b6-4b94-a3aa-c445a6a6ab59", ContainerID: string(bytes.Repeat([]byte("cd"), 32)),
	})
	var missing protocol.Error
	expect(ctx, t, session, protocol.ErrorType, &missing)
	if missing.Code != "container_not_found" || missing.RequestID != "0d1b7f56-39b6-4b94-a3aa-c445a6a6ab59" {
		t.Fatalf("missing = %+v", missing)
	}
}
