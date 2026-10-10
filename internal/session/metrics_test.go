package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/metricstore"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

func testStore(t *testing.T, samples int, at time.Time) *metricstore.Store {
	t.Helper()

	store, err := metricstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for index := range samples {
		err := store.Append(metrics.Snapshot{
			ObservedAt:       at.Add(time.Duration(index) * time.Second),
			Interval:         time.Second,
			ObservationScope: protocol.ObservationScopeHost,
			Node:             protocol.NodeMetrics{CPU: protocol.CPUMetrics{Total: protocol.CPUUtilizationMetrics{UsagePercent: 5}}},
			Containers:       []protocol.ContainerMetrics{{ContainerID: "container:a", Name: "web"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	return store
}

// readFrame reads one frame the reporter wrote and returns its type and
// request ID.
func readFrame(t *testing.T, conn *websocket.Conn) (string, string, []byte) {
	t.Helper()

	conn.SetReadLimit(1 << 20)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	messageType, err := protocol.MessageType(data)
	if err != nil {
		t.Fatal(err)
	}

	return messageType, extractRequestID(data), data
}

func extractRequestID(data []byte) string {
	const marker = `"request_id":"`
	text := string(data)
	start := strings.Index(text, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)

	return text[start : start+36]
}

func accept(t *testing.T, reporter *metricReporter, requestID string) {
	t.Helper()

	if err := reporter.handleResponse([]byte(`{"type":"metrics.accepted","request_id":"` + requestID + `"}`)); err != nil {
		t.Fatalf("accept %s: %v", requestID, err)
	}
}

func TestMetricReporterSendsBatchesAndMovesTheCursor(t *testing.T) {
	store := testStore(t, 70, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	agent, peer := newWebSocketPair(t)

	// The first batch is 60 samples: a node frame, then a container frame.
	if sent, err := reporter.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatalf("writeNext() = %v, %v", sent, err)
	}
	messageType, requestID, data := readFrame(t, peer)
	var report protocol.MetricsReport
	if err := protocol.DecodeStrict(data, &report); err != nil {
		t.Fatal(err)
	}
	if messageType != protocol.MetricsReportType || report.Metric.Type != protocol.MetricTypeNode || len(report.Metric.Samples) != 60 {
		t.Fatalf("first frame = %s %s with %d samples", messageType, report.Metric.Type, len(report.Metric.Samples))
	}
	if report.StreamID != store.StreamID() || report.Metric.Samples[0].Sequence != 1 {
		t.Fatalf("first frame stream %q, first sequence %d", report.StreamID, report.Metric.Samples[0].Sequence)
	}

	accept(t, reporter, requestID)
	if store.Cursor("device:a") != 0 {
		t.Fatal("the cursor moved before the container frame was acknowledged")
	}

	if sent, err := reporter.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatalf("second writeNext() = %v, %v", sent, err)
	}
	_, requestID, data = readFrame(t, peer)
	if err := protocol.DecodeStrict(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Metric.Type != protocol.MetricTypeContainer || report.Metric.Samples[0].Containers.Items[0].Name != "web" {
		t.Fatalf("second frame = %+v", report.Metric)
	}
	accept(t, reporter, requestID)
	if store.Cursor("device:a") != 60 {
		t.Fatalf("cursor = %d after the batch, want 60", store.Cursor("device:a"))
	}

	// A new reporter for the same reader continues from the stored cursor.
	resumed := newMetricReporter(store, "device:a")
	if sent, err := resumed.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatal("resumed reporter sent nothing")
	}
	_, _, data = readFrame(t, peer)
	if err := protocol.DecodeStrict(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Metric.Samples[0].Sequence != 61 || len(report.Metric.Samples) != 10 {
		t.Fatalf("resumed frame starts at %d with %d samples", report.Metric.Samples[0].Sequence, len(report.Metric.Samples))
	}
}

func TestMetricReporterSendsRollupsForCompactedHistory(t *testing.T) {
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour)
	store := testStore(t, 120, start)
	if err := store.Maintain(time.Now(), true); err != nil {
		t.Fatal(err)
	}

	reporter := newMetricReporter(store, "portal:p")
	agent, peer := newWebSocketPair(t)

	if sent, err := reporter.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatalf("writeNext() = %v, %v", sent, err)
	}
	messageType, requestID, data := readFrame(t, peer)
	if messageType != protocol.MetricsRollupType {
		t.Fatalf("history frame type = %s, want %s", messageType, protocol.MetricsRollupType)
	}

	var rollup protocol.MetricsRollupReport
	if err := protocol.DecodeStrict(data, &rollup); err != nil {
		t.Fatal(err)
	}
	if len(rollup.Metric.Points) != 1 || rollup.Metric.Points[0].Samples != 120 {
		t.Fatalf("rollup points = %+v", rollup.Metric.Points)
	}

	accept(t, reporter, requestID)
	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	_, requestID, _ = readFrame(t, peer)
	accept(t, reporter, requestID)
	if store.Cursor("portal:p") != 120 {
		t.Fatalf("cursor = %d, want 120", store.Cursor("portal:p"))
	}
}

func TestMetricReporterAcknowledgementRules(t *testing.T) {
	store := testStore(t, 1, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.active = &activeMetricReport{requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}
	acknowledgement := []byte(`{"type":"metrics.accepted","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}`)

	if err := reporter.handleResponse(acknowledgement); err != nil {
		t.Fatal(err)
	}
	if reporter.active != nil {
		t.Fatal("accepted frame remains active")
	}
	if err := reporter.handleResponse(acknowledgement); !errors.Is(err, errDuplicateMetricsAcknowledgement) {
		t.Fatalf("duplicate acknowledgement error = %v", err)
	}

	reporter.active = &activeMetricReport{requestID: "6e0c1d91-5145-440f-bf97-d84db4f83644"}
	err := reporter.handleResponse([]byte(`{"type":"metrics.rejected","request_id":"6e0c1d91-5145-440f-bf97-d84db4f83644","code":"internal_error"}`))
	var rejection *metricRejection
	if !errors.As(err, &rejection) || reporter.active == nil {
		t.Fatalf("rejection error = %v, active = %v", err, reporter.active)
	}
}

func TestQueryResultReturnsStoredHistory(t *testing.T) {
	now := time.Now().UTC()
	store := testStore(t, 30, now.Add(-time.Minute))

	result, err := queryResult(store, "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65", now.Add(-2*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 30 || result.Items[0].Sample == nil || result.NextFrom != nil {
		t.Fatalf("query returned %d items, next %v", len(result.Items), result.NextFrom)
	}
}
