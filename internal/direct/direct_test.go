package direct_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentapi"
	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
)

const testTimeout = 30 * time.Second

type testNode struct {
	node     *state.Node
	stateDir string
}

func startNode(t *testing.T) *testNode {
	t.Helper()

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node, err := direct.Init(store, direct.InitOptions{})
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- direct.Run(ctx, store, node, direct.Options{
			Version: "test",
			Collectors: direct.Collectors{
				Specifications: func(context.Context) (specifications.Snapshot, error) {
					return specifications.Snapshot{ObservationScope: "host"}, nil
				},
				Network: func(context.Context) (networkinfo.Snapshot, error) {
					return networkinfo.Snapshot{ObservationScope: "host"}, nil
				},
			},
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run() error = %v", err)
		}
	})

	return &testNode{node: node, stateDir: store.Dir()}
}

// dialControl waits for the control socket of a starting node.
func (n *testNode) dialControl(t *testing.T) *control.Conn {
	t.Helper()

	deadline := time.Now().Add(testTimeout)
	for {
		conn, err := control.Dial(n.stateDir)
		if err == nil {
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("control socket did not come up: %v", err)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func createInvite(t *testing.T, conn *control.Conn, noConfirm bool) *pairing.Invite {
	t.Helper()

	err := conn.Send(control.Message{
		Type:       control.TypeInviteCreate,
		TTLSeconds: 120,
		Endpoints:  []string{"127.0.0.1"},
		NoConfirm:  noConfirm,
	})
	if err != nil {
		t.Fatal(err)
	}

	created := receive(t, conn, control.TypeInviteCreated)
	invite, err := pairing.ParseInvite(created.Invite)
	if err != nil {
		t.Fatalf("ParseInvite() error = %v", err)
	}

	return invite
}

func receive(t *testing.T, conn *control.Conn, wantType string) control.Message {
	t.Helper()

	message, err := conn.Receive()
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if message.Type != wantType {
		t.Fatalf("control message = %+v, want type %q", message, wantType)
	}

	return message
}

type pairResult struct {
	credentials *client.Credentials
	err         error
}

func pairAsync(ctx context.Context, invite *pairing.Invite, sas chan<- string) <-chan pairResult {
	result := make(chan pairResult, 1)
	go func() {
		credentials, err := client.Pair(ctx, invite, client.PairOptions{
			DeviceName: "test laptop",
			ShowSAS:    func(code string) { sas <- code },
		})
		result <- pairResult{credentials: credentials, err: err}
	}()

	return result
}

func getJSON(ctx context.Context, t *testing.T, session *client.Session, path string, target any) {
	t.Helper()

	data, err := session.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("GET %s error = %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func wantAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()

	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.Code != code {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
}

func TestPairAndCallAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	conn := node.dialControl(t)
	invite := createInvite(t, conn, false)

	deviceSAS := make(chan string, 1)
	paired := pairAsync(ctx, invite, deviceSAS)

	requested := receive(t, conn, control.TypePairingRequested)
	if requested.DeviceName != "test laptop" {
		t.Fatalf("device name = %q", requested.DeviceName)
	}
	if code := <-deviceSAS; code != requested.SAS || len(code) != 9 {
		t.Fatalf("device SAS %q, node SAS %q", code, requested.SAS)
	}

	if err := conn.Send(control.Message{Type: control.TypePairingDecision, PairingID: requested.PairingID, Approve: true}); err != nil {
		t.Fatal(err)
	}
	completed := receive(t, conn, control.TypePairingCompleted)

	result := <-paired
	if result.err != nil {
		t.Fatalf("Pair() error = %v", result.err)
	}
	if result.credentials.DeviceID != completed.DeviceID {
		t.Fatalf("device ID = %q, node reported %q", result.credentials.DeviceID, completed.DeviceID)
	}

	session, err := client.Connect(ctx, result.credentials)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	var info agentapi.Node
	getJSON(ctx, t, session, agentapi.NodePath, &info)
	if info.NodeID != node.node.NodeID || info.ListenPort != node.node.ListenPort || info.AgentVersion != "test" {
		t.Fatalf("node info = %+v", info)
	}

	var specs agentapi.Specifications
	getJSON(ctx, t, session, agentapi.SpecificationsPath, &specs)
	if specs.ObservationScope != "host" {
		t.Fatalf("specifications = %+v", specs)
	}

	var devices agentapi.DeviceList
	getJSON(ctx, t, session, agentapi.DevicesPath, &devices)
	if len(devices.Devices) != 1 || !devices.Devices[0].Current || devices.Devices[0].Name != "test laptop" {
		t.Fatalf("devices = %+v", devices)
	}

	// The invite is single use, even while its temporary peer still exists.
	_, err = client.Pair(ctx, invite, client.PairOptions{DeviceName: "second", ShowSAS: func(string) {}})
	wantAPIError(t, err, http.StatusConflict, "invite_used")

	// Revoking the current device cuts its API access.
	if _, err := session.Do(ctx, http.MethodDelete, agentapi.DevicesPath+"/"+result.credentials.DeviceID, nil); err != nil {
		t.Fatalf("DELETE device error = %v", err)
	}
	_, err = session.Do(ctx, http.MethodGet, agentapi.NodePath, nil)
	wantAPIError(t, err, http.StatusForbidden, "forbidden")
}

func TestInvitePeerCannotCallDeviceAPI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	conn := node.dialControl(t)
	invite := createInvite(t, conn, false)

	session, err := client.ConnectInvite(ctx, invite)
	if err != nil {
		t.Fatalf("ConnectInvite() error = %v", err)
	}
	defer session.Close()

	for _, path := range []string{agentapi.NodePath, agentapi.DevicesPath, agentapi.NetworkPath} {
		_, err := session.Do(ctx, http.MethodGet, path, nil)
		wantAPIError(t, err, http.StatusForbidden, "forbidden")
	}

	_, err = session.Do(ctx, http.MethodPost, agentapi.PairingPath, map[string]any{"device_name": "x", "extra": true})
	wantAPIError(t, err, http.StatusBadRequest, "invalid_json")
}

func TestRejectedPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	conn := node.dialControl(t)
	invite := createInvite(t, conn, false)

	paired := pairAsync(ctx, invite, make(chan string, 1))
	requested := receive(t, conn, control.TypePairingRequested)

	if err := conn.Send(control.Message{Type: control.TypePairingDecision, PairingID: requested.PairingID}); err != nil {
		t.Fatal(err)
	}
	receive(t, conn, control.TypePairingRejected)

	if result := <-paired; !errors.Is(result.err, client.ErrPairingRejected) {
		t.Fatalf("Pair() error = %v, want rejection", result.err)
	}

	if err := conn.Send(control.Message{Type: control.TypeDevicesList}); err != nil {
		t.Fatal(err)
	}
	if devices := receive(t, conn, control.TypeDevices); len(devices.Devices) != 0 {
		t.Fatalf("devices after rejection = %+v", devices.Devices)
	}
}

func TestNoConfirmPairingAndDeviceRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	conn := node.dialControl(t)
	invite := createInvite(t, conn, true)

	result := <-pairAsync(ctx, invite, make(chan string, 1))
	if result.err != nil {
		t.Fatalf("Pair() error = %v", result.err)
	}
	receive(t, conn, control.TypePairingRequested)
	receive(t, conn, control.TypePairingCompleted)

	admin := node.dialControl(t)
	if err := admin.Send(control.Message{Type: control.TypeDeviceRemove, DeviceID: result.credentials.DeviceID}); err != nil {
		t.Fatal(err)
	}
	receive(t, admin, control.TypeDeviceRemoved)

	if err := admin.Send(control.Message{Type: control.TypeDevicesList}); err != nil {
		t.Fatal(err)
	}
	if devices := receive(t, admin, control.TypeDevices); len(devices.Devices) != 0 {
		t.Fatalf("devices after removal = %+v", devices.Devices)
	}
}
