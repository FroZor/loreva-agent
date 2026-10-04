package direct_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/workload"
)

const testTimeout = 30 * time.Second

type testNode struct {
	node      *state.Node
	stateDir  string
	workloads *fakeWorkloads
}

// fakeWorkloads records what device sessions hand to the workload runtime.
type fakeWorkloads struct {
	submitted chan protocol.WorkloadCommand
	stored    chan []byte

	mu      sync.Mutex
	results map[string]chan any
}

func newFakeWorkloads() *fakeWorkloads {
	return &fakeWorkloads{
		submitted: make(chan protocol.WorkloadCommand, 4),
		stored:    make(chan []byte, 4),
		results:   make(map[string]chan any),
	}
}

func (f *fakeWorkloads) Submit(command protocol.WorkloadCommand, source workload.ArtifactSource) error {
	if source != nil {
		return errors.New("device commands must not have an artifact source")
	}

	f.submitted <- command

	return nil
}

func (f *fakeWorkloads) Results(controller string) <-chan any {
	return f.queue(controller)
}

func (f *fakeWorkloads) queue(controller string) chan any {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.results[controller] == nil {
		f.results[controller] = make(chan any, 4)
	}

	return f.results[controller]
}

func (f *fakeWorkloads) StoreArtifact(reference protocol.ArtifactReference, data io.Reader) error {
	content, err := io.ReadAll(data)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(content)
	if int64(len(content)) != reference.SizeBytes || "sha256:"+hex.EncodeToString(sum[:]) != reference.SHA256 {
		return errors.New("artifact does not match")
	}

	f.stored <- content

	return nil
}

func testCollectors() direct.Collectors {
	return direct.Collectors{
		Specifications: func(context.Context) (specifications.Snapshot, error) {
			return specifications.Snapshot{ObservationScope: "host"}, nil
		},
		Network: func(context.Context) (networkinfo.Snapshot, error) {
			return networkinfo.Snapshot{ObservationScope: "host"}, nil
		},
		Metrics: func(context.Context) <-chan metrics.Sample {
			samples := make(chan metrics.Sample, 1)
			samples <- metrics.Sample{Snapshot: metrics.Snapshot{
				ObservedAt:       time.Now().UTC(),
				Interval:         time.Second,
				ObservationScope: "host",
			}}

			return samples
		},
	}
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

	workloads := newFakeWorkloads()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- direct.Run(ctx, store, node, direct.Options{
			Version:    "test",
			Collectors: testCollectors(),
			Workloads:  workloads,
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run() error = %v", err)
		}
	})

	return &testNode{node: node, stateDir: store.Dir(), workloads: workloads}
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

func pairDevice(ctx context.Context, t *testing.T, node *testNode) *client.Credentials {
	t.Helper()

	conn := node.dialControl(t)
	result := <-pairAsync(ctx, createInvite(t, conn, true), make(chan string, 1))
	if result.err != nil {
		t.Fatalf("Pair() error = %v", result.err)
	}

	return result.credentials
}

// expect reads frames until one of wantType arrives, acknowledging any
// metrics report on the way as the app would.
func expect(ctx context.Context, t *testing.T, session *client.Session, wantType string, target any) {
	t.Helper()

	for {
		data, err := session.Read(ctx)
		if err != nil {
			t.Fatalf("read %s: %v", wantType, err)
		}

		messageType, err := protocol.MessageType(data)
		if err != nil {
			t.Fatalf("frame is not JSON: %s", data)
		}
		if messageType == wantType {
			if err := protocol.DecodeStrict(data, target); err != nil {
				t.Fatalf("decode %s: %v", wantType, err)
			}

			return
		}
		acknowledge(ctx, t, session, messageType, data, wantType)
	}
}

// acknowledge accepts a node report or metrics report, as the app does.
func acknowledge(ctx context.Context, t *testing.T, session *client.Session, messageType string, data []byte, wantType string) {
	t.Helper()

	var report struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode %s: %v", messageType, err)
	}

	switch messageType {
	case protocol.NodeSpecificationsReportType:
		send(ctx, t, session, protocol.NodeSpecificationsAccepted{Type: protocol.NodeSpecificationsAcceptedType, RequestID: report.RequestID})
	case protocol.NodeNetworkReportType:
		send(ctx, t, session, protocol.NodeNetworkAccepted{Type: protocol.NodeNetworkAcceptedType, RequestID: report.RequestID})
	case protocol.MetricsReportType:
		send(ctx, t, session, protocol.MetricsAccepted{Type: protocol.MetricsAcceptedType, RequestID: report.RequestID})
	default:
		t.Fatalf("got %s while waiting for %s: %s", messageType, wantType, data)
	}
}

func send(ctx context.Context, t *testing.T, session *client.Session, frame any) {
	t.Helper()

	if err := session.WriteJSON(ctx, frame); err != nil {
		t.Fatalf("send %T: %v", frame, err)
	}
}

func TestPairAndUseSession(t *testing.T) {
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

	hello := session.Hello
	if hello.NodeID != node.node.NodeID || hello.AgentVersion != "test" || hello.DeviceID != result.credentials.DeviceID {
		t.Fatalf("hello = %+v", hello)
	}

	// The device receives the same node reports as the portal and
	// acknowledges them the same way; metrics follow the reports.
	var specs protocol.NodeSpecificationsReport
	expect(ctx, t, session, protocol.NodeSpecificationsReportType, &specs)
	if specs.ObservationScope != "host" {
		t.Fatalf("specifications = %+v", specs)
	}
	send(ctx, t, session, protocol.NodeSpecificationsAccepted{Type: protocol.NodeSpecificationsAcceptedType, RequestID: specs.RequestID})

	var network protocol.NodeNetworkReport
	expect(ctx, t, session, protocol.NodeNetworkReportType, &network)
	send(ctx, t, session, protocol.NodeNetworkAccepted{Type: protocol.NodeNetworkAcceptedType, RequestID: network.RequestID})

	var report protocol.MetricsReport
	expect(ctx, t, session, protocol.MetricsReportType, &report)
	if report.Metric.Type != protocol.MetricTypeNode {
		t.Fatalf("first metrics report = %+v", report.Metric)
	}
	send(ctx, t, session, protocol.MetricsAccepted{Type: protocol.MetricsAcceptedType, RequestID: report.RequestID})

	send(ctx, t, session, protocol.DevicesList{Type: protocol.DevicesListType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"})
	var devices protocol.DevicesListResult
	expect(ctx, t, session, protocol.DevicesListResultType, &devices)
	if len(devices.Devices) != 1 || !devices.Devices[0].Current || devices.Devices[0].Name != "test laptop" {
		t.Fatalf("devices = %+v", devices)
	}

	// The invite is single use, even while its temporary peer still exists.
	_, err = client.Pair(ctx, invite, client.PairOptions{DeviceName: "second", ShowSAS: func(string) {}})
	if remote, ok := errors.AsType[*client.RemoteError](err); !ok || remote.Code != "invite_used" {
		t.Fatalf("second Pair() error = %v, want invite_used", err)
	}

	// Revoking the current device ends its session.
	send(ctx, t, session, protocol.DeviceRemove{
		Type:      protocol.DeviceRemoveType,
		RequestID: "0d1b7f56-39b6-4b94-a3aa-c445a6a6ab59",
		DeviceID:  result.credentials.DeviceID,
	})
	var removed protocol.DeviceRemoveResult
	expect(ctx, t, session, protocol.DeviceRemoveResultType, &removed)
	for {
		if _, err := session.Read(ctx); err != nil {
			break
		}
	}
	if _, err := client.Connect(ctx, result.credentials); err == nil {
		t.Fatal("Connect() succeeded for a revoked device")
	}
}

func TestDeviceWorkloadsAndArtifacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	session, err := client.Connect(ctx, pairDevice(ctx, t, node))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	content := bytes.Repeat([]byte("loreva"), protocol.MaxArtifactChunkBytes/3)
	sum := sha256.Sum256(content)
	uploadID := "6e0c1d91-5145-440f-bf97-d84db4f83644"
	send(ctx, t, session, protocol.ArtifactUploadRequest{
		Type:       protocol.ArtifactUploadRequestType,
		RequestID:  uploadID,
		ArtifactID: "df9ffacf-fd65-4643-967b-422b2d4c826c",
		SHA256:     "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes:  int64(len(content)),
	})
	for offset := 0; offset < len(content); offset += protocol.MaxArtifactChunkBytes {
		end := min(offset+protocol.MaxArtifactChunkBytes, len(content))
		send(ctx, t, session, protocol.ArtifactUploadChunk{
			Type:      protocol.ArtifactUploadChunkType,
			RequestID: uploadID,
			Offset:    int64(offset),
			Data:      base64.StdEncoding.EncodeToString(content[offset:end]),
		})
	}

	var uploaded protocol.ArtifactUploadResult
	expect(ctx, t, session, protocol.ArtifactUploadResultType, &uploaded)
	if uploaded.State != protocol.ArtifactStored {
		t.Fatalf("upload result = %+v", uploaded)
	}
	if stored := <-node.workloads.stored; !bytes.Equal(stored, content) {
		t.Fatal("stored artifact differs from the upload")
	}

	payload := json.RawMessage(`{"format":"oci","oci":{"image":"busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	send(ctx, t, session, protocol.DeviceWorkloadCommand{
		Type:          protocol.WorkloadPlanRequestType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		WorkloadID:    "d1b181c1-52ec-4d55-b2c9-b1428305b294",
		Payload:       payload,
	})

	command := <-node.workloads.submitted
	if command.PortalID != node.node.NodeID || command.NodeID != node.node.NodeID {
		t.Fatalf("device command controller = %q, node = %q", command.PortalID, command.NodeID)
	}

	// Responses for the node's controller scope reach the device session.
	node.workloads.queue(node.node.NodeID) <- protocol.WorkloadPlanResult{
		Type:          protocol.WorkloadPlanResultType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload: protocol.WorkloadPlanResultPayload{
			State: "ready", Steps: []protocol.WorkloadPlanStep{}, Findings: []protocol.WorkloadFinding{},
		},
	}

	var plan protocol.WorkloadPlanResult
	expect(ctx, t, session, protocol.WorkloadPlanResultType, &plan)
	if plan.RequestID != command.RequestID || plan.Payload.State != "ready" {
		t.Fatalf("plan result = %+v", plan)
	}

	send(ctx, t, session, protocol.DeviceWorkloadCommand{
		Type:          protocol.WorkloadPlanRequestType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     "not-a-uuid",
		WorkloadID:    "d1b181c1-52ec-4d55-b2c9-b1428305b294",
		Payload:       payload,
	})
	var refusal protocol.Error
	expect(ctx, t, session, protocol.ErrorType, &refusal)
	if refusal.Code != "invalid_command" {
		t.Fatalf("refusal = %+v", refusal)
	}
}

func TestInvitePeerCanOnlyPair(t *testing.T) {
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

	if session.Hello.Peer != protocol.SessionPeerInvite || session.Hello.DeviceID != "" {
		t.Fatalf("invite hello = %+v", session.Hello)
	}

	for _, frame := range []any{
		protocol.DevicesList{Type: protocol.DevicesListType, RequestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"},
		map[string]any{"type": protocol.PairingRequestType, "device_name": "x", "extra": true},
	} {
		send(ctx, t, session, frame)

		var refusal protocol.Error
		expect(ctx, t, session, protocol.ErrorType, &refusal)
		if refusal.Code != "invalid_message" {
			t.Fatalf("refusal = %+v", refusal)
		}
	}
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

	session, err := client.Connect(ctx, result.credentials)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	admin := node.dialControl(t)
	if err := admin.Send(control.Message{Type: control.TypeDeviceRemove, DeviceID: result.credentials.DeviceID}); err != nil {
		t.Fatal(err)
	}
	receive(t, admin, control.TypeDeviceRemoved)

	// The operator's revocation also ends the device's open session.
	for {
		if _, err := session.Read(ctx); err != nil {
			break
		}
	}
	if ctx.Err() != nil {
		t.Fatal("device session outlived its revocation")
	}

	if err := admin.Send(control.Message{Type: control.TypeDevicesList}); err != nil {
		t.Fatal(err)
	}
	if devices := receive(t, admin, control.TypeDevices); len(devices.Devices) != 0 {
		t.Fatalf("devices after removal = %+v", devices.Devices)
	}
}

func TestClosingInviteExpiresPendingPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	node := startNode(t)
	conn := node.dialControl(t)
	invite := createInvite(t, conn, false)

	paired := pairAsync(ctx, invite, make(chan string, 1))
	receive(t, conn, control.TypePairingRequested)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if result := <-paired; !errors.Is(result.err, client.ErrPairingExpired) {
		t.Fatalf("Pair() error = %v, want expiry", result.err)
	}
}

func TestShutdownEndsPendingPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node, err := direct.Init(store, direct.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- direct.Run(runCtx, store, node, direct.Options{Collectors: testCollectors()})
	}()

	conn := (&testNode{node: node, stateDir: store.Dir()}).dialControl(t)
	invite := createInvite(t, conn, false)
	paired := pairAsync(ctx, invite, make(chan string, 1))
	receive(t, conn, control.TypePairingRequested)

	started := time.Now()
	stop()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v, want clean shutdown", err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("shutdown took %s", elapsed)
	}

	// The device only sees its own timeout once the node is gone.
	cancel()
	<-paired
}
