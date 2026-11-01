package nodeapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

func TestNodeReporterSendsSpecificationsBeforeNetwork(t *testing.T) {
	client, server := newWebSocketPair(t)
	reporter := newNodeReporter(t.Context(), Collectors{
		Specifications: func(context.Context) (specifications.Snapshot, error) {
			return specifications.Snapshot{
				ObservationScope: protocol.ObservationScopeHost,
				Specifications: protocol.NodeSpecifications{
					System: protocol.SystemSpecifications{Hostname: "node-a"},
				},
			}, nil
		},
		Network: func(context.Context) (networkinfo.Snapshot, error) {
			return networkinfo.Snapshot{
				ObservationScope: protocol.ObservationScopeHost,
				Network: protocol.NodeNetwork{
					Interfaces: []protocol.NetworkInterfaceConfiguration{},
				},
			}, nil
		},
	}, &ReportState{})

	first := waitForNodeReport(t, reporter.results)
	if first.kind != nodeReportSpecifications {
		t.Fatalf("first report kind = %d, want specifications", first.kind)
	}
	if err := reporter.writeResult(t.Context(), client, first); err != nil {
		t.Fatal(err)
	}

	var specificationsReport protocol.NodeSpecificationsReport
	if err := wsframe.ReadJSON(t.Context(), server, &specificationsReport); err != nil {
		t.Fatal(err)
	}
	if specificationsReport.Type != protocol.NodeSpecificationsReportType ||
		specificationsReport.Specifications.System.Hostname != "node-a" {
		t.Fatalf("unexpected specifications report: %#v", specificationsReport)
	}

	if err := wsframe.WriteJSON(t.Context(), server, protocol.NodeSpecificationsAccepted{
		Type:      protocol.NodeSpecificationsAcceptedType,
		RequestID: specificationsReport.RequestID,
	}); err != nil {
		t.Fatal(err)
	}

	accepted, err := wsframe.ReadRawJSON(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.handleResponse(t.Context(), accepted); err != nil {
		t.Fatal(err)
	}

	second := waitForNodeReport(t, reporter.results)
	if second.kind != nodeReportNetwork {
		t.Fatalf("second report kind = %d, want network", second.kind)
	}
	if err := reporter.writeResult(t.Context(), client, second); err != nil {
		t.Fatal(err)
	}

	var networkReport protocol.NodeNetworkReport
	if err := wsframe.ReadJSON(t.Context(), server, &networkReport); err != nil {
		t.Fatal(err)
	}
	if networkReport.Type != protocol.NodeNetworkReportType {
		t.Fatalf("network report type = %q", networkReport.Type)
	}
}

func TestNodeReporterRejectsMismatchedAcknowledgement(t *testing.T) {
	reporter := &nodeReporter{state: &ReportState{active: &activeNodeReport{
		kind:      nodeReportSpecifications,
		requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
	}}}

	err := reporter.handleResponse(t.Context(), []byte(`{
        "type":"node.specifications.accepted",
        "request_id":"7f039655-b659-4a7f-baa0-29e6142fd480"
    }`))
	if err == nil {
		t.Fatal("mismatched request ID was accepted")
	}
}

func TestNodeReporterRetriesSamePayloadAfterReconnect(t *testing.T) {
	collectionCount := 0
	collectors := Collectors{
		Specifications: func(context.Context) (specifications.Snapshot, error) {
			collectionCount++

			return specifications.Snapshot{
				ObservationScope: protocol.ObservationScopeHost,
				Specifications: protocol.NodeSpecifications{
					System: protocol.SystemSpecifications{Hostname: "node-a"},
				},
			}, nil
		},
	}
	state := &ReportState{}

	firstClient, firstServer := newWebSocketPair(t)
	firstReporter := newNodeReporter(t.Context(), collectors, state)
	firstResult := waitForNodeReport(t, firstReporter.results)
	if err := firstReporter.writeResult(t.Context(), firstClient, firstResult); err != nil {
		t.Fatal(err)
	}
	firstPayload, err := wsframe.ReadRawJSON(t.Context(), firstServer)
	if err != nil {
		t.Fatal(err)
	}

	secondClient, secondServer := newWebSocketPair(t)
	secondReporter := newNodeReporter(t.Context(), collectors, state)
	secondResult := waitForNodeReport(t, secondReporter.results)
	if err := secondReporter.writeResult(t.Context(), secondClient, secondResult); err != nil {
		t.Fatal(err)
	}
	secondPayload, err := wsframe.ReadRawJSON(t.Context(), secondServer)
	if err != nil {
		t.Fatal(err)
	}

	if string(firstPayload) != string(secondPayload) {
		t.Fatal("retried report payload changed after reconnect")
	}
	if collectionCount != 1 {
		t.Fatalf("specifications collected %d times, want once", collectionCount)
	}
}

func TestNodeReporterRejectsOversizedReport(t *testing.T) {
	reporter := &nodeReporter{state: &ReportState{}}
	result := CollectedReport{
		kind: nodeReportSpecifications,
		specifications: specifications.Snapshot{
			ObservationScope: protocol.ObservationScopeHost,
			Specifications: protocol.NodeSpecifications{
				System: protocol.SystemSpecifications{Hostname: strings.Repeat("a", maxNodeReportSize)},
			},
		},
	}

	err := reporter.writeResult(t.Context(), nil, result)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized report error = %v", err)
	}
}

func TestTerminalNodeReportRejectionSkipsReportWithoutEndingSession(t *testing.T) {
	peer := newTestReportPeer(t, nodeReportSpecifications)
	peer.exchange.reports.collectors.Network = func(context.Context) (networkinfo.Snapshot, error) {
		return networkinfo.Snapshot{ObservationScope: protocol.ObservationScopeHost}, nil
	}
	events := make(chan NodeReportRejection, 1)
	err := handleTestFrame(t, peer, []byte(`{
            "type":"node.specifications.rejected",
            "request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
            "code":"unsupported_schema_version"
        }`), Events{ReportRejected: func(rejection NodeReportRejection) { events <- rejection }})
	if err != nil {
		t.Fatalf("terminal report rejection ended session: %v", err)
	}
	if peer.exchange.reports.state.complete || peer.exchange.reports.state.active != nil {
		t.Fatal("terminal report rejection did not disable the rejected report")
	}

	next := waitForNodeReport(t, peer.exchange.reports.results)
	if next.kind != nodeReportNetwork {
		t.Fatalf("next report kind = %d, want network", next.kind)
	}

	event := <-events
	if event.Type != protocol.NodeSpecificationsReportType ||
		event.Code != "unsupported_schema_version" || event.Retryable {
		t.Fatalf("unexpected rejection event: %#v", event)
	}
}

func TestTransientNodeReportRejectionSchedulesSameReport(t *testing.T) {
	peer := newTestReportPeer(t, nodeReportSpecifications)
	events := make(chan NodeReportRejection, 1)
	err := handleTestFrame(t, peer, []byte(`{
            "type":"node.specifications.rejected",
            "request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
            "code":"temporarily_unavailable"
        }`), Events{ReportRejected: func(rejection NodeReportRejection) { events <- rejection }})
	if err != nil {
		t.Fatalf("transient report rejection ended session: %v", err)
	}
	if peer.exchange.reports.state.active == nil || peer.exchange.reports.state.retryAttempt != 1 {
		t.Fatal("transient report rejection did not preserve the active report")
	}

	event := <-events
	if event.Code != "temporarily_unavailable" || !event.Retryable {
		t.Fatalf("unexpected rejection event: %#v", event)
	}
}

func TestMalformedNodeReportRejectionReconnectsWithoutBecomingTerminal(t *testing.T) {
	peer := newTestReportPeer(t, nodeReportSpecifications)
	err := handleTestFrame(t, peer, []byte(`{
            "type":"node.specifications.rejected",
            "code":"internal_error"
        }`), Events{})
	if err == nil {
		t.Fatal("malformed report rejection was accepted")
	}
	if _, ok := errors.AsType[*IdentityRejection](err); ok {
		t.Fatalf("malformed report rejection became an identity rejection: %v", err)
	}
	if peer.exchange.reports.state.active == nil {
		t.Fatal("malformed report rejection cleared the active report")
	}
}

func TestMissingNodeIsTerminalIdentityFailure(t *testing.T) {
	peer := newTestReportPeer(t, nodeReportSpecifications)
	err := handleTestFrame(t, peer, []byte(`{
            "type":"node.specifications.rejected",
            "request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
            "code":"node_not_registered"
        }`), Events{})
	if _, ok := errors.AsType[*IdentityRejection](err); !ok {
		t.Fatalf("missing node rejection was not an identity rejection: %v", err)
	}
}

func TestDuplicateNodeReportAcknowledgementDoesNotAdvanceActiveReport(t *testing.T) {
	peer := newTestReportPeer(t, nodeReportNetwork)
	peer.exchange.reports.state.lastAcceptedKind = nodeReportSpecifications
	peer.exchange.reports.state.lastAcceptedRequestID = "6e0c1d91-5145-440f-bf97-d84db4f83644"
	err := handleTestFrame(t, peer, []byte(`{
            "type":"node.specifications.accepted",
            "request_id":"6e0c1d91-5145-440f-bf97-d84db4f83644"
        }`), Events{})
	if err != nil {
		t.Fatalf("duplicate acknowledgement ended session: %v", err)
	}
	if peer.exchange.reports.state.active == nil || peer.exchange.reports.state.active.kind != nodeReportNetwork {
		t.Fatal("duplicate acknowledgement advanced the active network report")
	}
}

func newTestReportPeer(t *testing.T, kind nodeReportKind) *Peer {
	t.Helper()

	replyTimer := NewStoppedTimer()
	retryTimer := NewStoppedTimer()
	t.Cleanup(func() {
		replyTimer.Stop()
		retryTimer.Stop()
	})

	state := &ReportState{active: &activeNodeReport{
		kind:      kind,
		requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		payload:   []byte(`{"type":"node.specifications.report"}`),
	}}

	return &Peer{exchange: &exchange{
		reports:          &nodeReporter{collectors: Collectors{}, results: make(chan CollectedReport, 1), state: state},
		reportReplyTimer: replyTimer,
		reportRetryTimer: retryTimer,
	}}
}

// handleTestFrame passes one frame to the peer as a session loop would.
func handleTestFrame(t *testing.T, peer *Peer, frame []byte, events Events) error {
	t.Helper()

	messageType, err := protocol.MessageType(frame)
	if err != nil {
		t.Fatal(err)
	}

	peer.events = events
	handled, err := peer.HandleMessage(t.Context(), messageType, frame)
	if !handled {
		t.Fatalf("frame %s was not handled", frame)
	}

	return err
}

func waitForNodeReport(t *testing.T, results <-chan CollectedReport) CollectedReport {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for collected node report")
		return CollectedReport{}
	}
}

func newWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	connections := make(chan *websocket.Conn, 1)
	errorsChannel := make(chan error, 1)
	done := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			errorsChannel <- err
			return
		}

		connections <- conn
		<-done
	}))

	client, _, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}

	var serverConnection *websocket.Conn
	select {
	case serverConnection = <-connections:
	case err := <-errorsChannel:
		server.Close()
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		server.Close()
		t.Fatal("timed out establishing WebSocket test pair")
	}

	t.Cleanup(func() {
		close(done)
		closeTestWebSocket(t, client)
		closeTestWebSocket(t, serverConnection)
		server.Close()
	})

	return client, serverConnection
}

func closeTestWebSocket(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	err := conn.CloseNow()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test WebSocket: %v", err)
	}
}
