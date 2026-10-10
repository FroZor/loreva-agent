package session

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/containerfiles"
	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/fileops"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

type echoConsole struct{}

func (echoConsole) Logs(context.Context, string, containerio.LogOptions) (containerio.LogStream, error) {
	return nil, containerio.ErrNotFound
}

func (echoConsole) ConsoleAdapter(context.Context, string) (containerio.Adapter, error) {
	return containerio.AdapterStdin, nil
}

func (echoConsole) SendCommand(_ context.Context, _ string, command string) (containerio.CommandResult, error) {
	return containerio.CommandResult{Adapter: containerio.AdapterStdin, Output: command}, nil
}

// helperFiles runs the real file helper in-process over pipes with one
// temporary folder as the only mount.
type helperFiles struct {
	client *fileops.Client
	mount  string
}

func newHelperFiles(t *testing.T) *helperFiles {
	t.Helper()

	mount := t.TempDir()
	helperIn, agentOut := io.Pipe()
	agentIn, helperOut := io.Pipe()
	go func() {
		_ = fileops.Serve(helperIn, helperOut)
		helperOut.Close()
	}()
	t.Cleanup(func() { agentOut.Close() })

	files := &helperFiles{client: fileops.NewClient(agentIn, agentOut), mount: mount}
	if err := files.client.Init(t.Context(), []fileops.Mount{{Path: mount}}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	return files
}

func (f *helperFiles) Start(_ context.Context, _ string, request fileops.Request) (containerfiles.Call, error) {
	return f.client.Start(request)
}

// The portal session serves the same container frames as a device session;
// only how the peer authenticated differs.
func TestPortalSessionServesContainerConsole(t *testing.T) {
	agentSide, portalSide := newWebSocketPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	runner := &Runner{
		masterEndpoint: "wss://master.example/agent/v1/connect",
		identity:       &state.Identity{PortalID: "d1b181c1-52ec-4d55-b2c9-b1428305b294"},
	}
	files := newHelperFiles(t)
	live := &liveState{containers: newContainerStreams(ctx, echoConsole{}, files, agentSide, slog.New(slog.DiscardHandler))}
	defer live.containers.close()

	containerID := strings.Repeat("ab", 32)
	tests := []struct {
		frame    string
		wantType string
	}{
		{`{"type":"container.console.send","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","container_id":"` + containerID + `","command":"list"}`, protocol.ContainerConsoleSendResultType},
		{`{"type":"container.logs.open","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","stream_id":1,"container_id":"` + containerID + `","tail":0,"follow":false,"timestamps":false}`, protocol.ErrorType},
		{`{"type":"fs.list","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","container_id":"` + containerID + `","path":"` + files.mount + `"}`, protocol.FSListResultType},
	}

	for _, test := range tests {
		if err := runner.handleWorkingMessage(ctx, agentSide, "", runner.masterEndpoint, []byte(test.frame), live, Events{}); err != nil {
			t.Fatalf("handleWorkingMessage(%s) error = %v", test.frame, err)
		}

		data, err := wsframe.ReadRawJSON(ctx, portalSide)
		if err != nil {
			t.Fatal(err)
		}
		if messageType, _ := protocol.MessageType(data); messageType != test.wantType {
			t.Fatalf("portal received %s, want %s", data, test.wantType)
		}
	}
}
