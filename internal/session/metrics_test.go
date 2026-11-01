package session

import (
	"context"
	"errors"
	"fmt"
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
	reporter.inflight = []*metricFrame{{requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}}
	acknowledgement := []byte(`{"type":"metrics.accepted","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}`)

	if err := reporter.handleResponse(acknowledgement); err != nil {
		t.Fatal(err)
	}
	if reporter.awaiting() || len(reporter.inflight) != 0 {
		t.Fatal("accepted frame remains in flight")
	}
	if err := reporter.handleResponse(acknowledgement); !errors.Is(err, errDuplicateMetricsAcknowledgement) {
		t.Fatalf("duplicate acknowledgement error = %v", err)
	}
	if err := reporter.handleResponse([]byte(`{"type":"metrics.accepted","request_id":"9d1f4c4e-1b7f-4a57-9a43-3c0e3f0a9b11"}`)); err == nil ||
		errors.Is(err, errDuplicateMetricsAcknowledgement) {
		t.Fatalf("unknown acknowledgement error = %v", err)
	}

	reporter.inflight = []*metricFrame{{requestID: "6e0c1d91-5145-440f-bf97-d84db4f83644"}}
	err := reporter.handleResponse([]byte(`{"type":"metrics.rejected","request_id":"6e0c1d91-5145-440f-bf97-d84db4f83644","code":"internal_error"}`))
	var rejection *metricRejection
	if !errors.As(err, &rejection) || rejection.requestID != "6e0c1d91-5145-440f-bf97-d84db4f83644" || !reporter.awaiting() {
		t.Fatalf("rejection error = %v, awaiting = %v", err, reporter.awaiting())
	}
}

func TestMetricReporterWindowMovesTheCursorOverAcknowledgedPrefix(t *testing.T) {
	store := testStore(t, 130, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.subscribe(false, 4)
	agent, peer := newWebSocketPair(t)

	if sent, err := reporter.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatalf("writeNext() = %v, %v", sent, err)
	}
	var requestIDs []string
	for range 4 {
		_, requestID, _ := readFrame(t, peer)
		requestIDs = append(requestIDs, requestID)
	}
	if len(reporter.inflight) != 4 {
		t.Fatalf("%d frames in flight, want the window of 4", len(reporter.inflight))
	}

	// The second batch is acknowledged first: the cursor waits for the first.
	accept(t, reporter, requestIDs[3])
	accept(t, reporter, requestIDs[2])
	accept(t, reporter, requestIDs[1])
	if store.Cursor("device:a") != 0 {
		t.Fatalf("cursor = %d before the first frame was acknowledged", store.Cursor("device:a"))
	}
	accept(t, reporter, requestIDs[0])
	if store.Cursor("device:a") != 120 || len(reporter.inflight) != 0 {
		t.Fatalf("cursor = %d with %d frames in flight, want 120 and none", store.Cursor("device:a"), len(reporter.inflight))
	}

	if sent, err := reporter.writeNext(t.Context(), agent); err != nil || !sent {
		t.Fatalf("third writeNext() = %v, %v", sent, err)
	}
	_, _, data := readFrame(t, peer)
	var report protocol.MetricsReport
	if err := protocol.DecodeStrict(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Metric.Samples[0].Sequence != 121 {
		t.Fatalf("third batch starts at %d, want 121", report.Metric.Samples[0].Sequence)
	}
}

func TestMetricReporterSendsTheNewestSampleLiveWhileHistoryIsBehind(t *testing.T) {
	store := testStore(t, 70, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.subscribe(true, 1)
	agent, peer := newWebSocketPair(t)

	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	_, historyID, _ := readFrame(t, peer)
	if err := reporter.writeLive(t.Context(), agent); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{protocol.MetricTypeNode, protocol.MetricTypeContainer} {
		messageType, requestID, data := readFrame(t, peer)
		var live protocol.MetricsLive
		if err := protocol.DecodeStrict(data, &live); err != nil {
			t.Fatal(err)
		}
		if messageType != protocol.MetricsLiveType || requestID != "" || live.Metric.Type != want ||
			len(live.Metric.Samples) != 1 || live.Metric.Samples[0].Sequence != 70 {
			t.Fatalf("live frame = %s %s with %d samples", messageType, live.Metric.Type, len(live.Metric.Samples))
		}
	}
	if store.Cursor("device:a") != 0 {
		t.Fatal("a live frame moved the cursor")
	}

	// The same newest sample is not sent live twice.
	if err := reporter.writeLive(t.Context(), agent); err != nil {
		t.Fatal(err)
	}

	accept(t, reporter, historyID)
	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	_, requestID, _ := readFrame(t, peer)
	if requestID == "" {
		t.Fatal("a second live frame was sent for the same sample")
	}
	accept(t, reporter, requestID)
	for range 2 {
		if _, err := reporter.writeNext(t.Context(), agent); err != nil {
			t.Fatal(err)
		}
		_, requestID, _ = readFrame(t, peer)
		accept(t, reporter, requestID)
	}
	if store.Cursor("device:a") != 70 {
		t.Fatalf("cursor = %d, want 70", store.Cursor("device:a"))
	}

	// History has caught up: a new sample goes out as history, not live.
	if err := store.Append(metrics.Snapshot{ObservedAt: time.Now().UTC(), Interval: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	if err := reporter.writeLive(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	messageType, _, _ := readFrame(t, peer)
	if messageType != protocol.MetricsReportType {
		t.Fatalf("caught-up sample went out as %s", messageType)
	}
}

func TestMetricReporterResendsUnacknowledgedFramesOnce(t *testing.T) {
	store := testStore(t, 130, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.subscribe(false, 4)
	agent, peer := newWebSocketPair(t)

	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	var requestIDs []string
	for range 4 {
		_, requestID, _ := readFrame(t, peer)
		requestIDs = append(requestIDs, requestID)
	}
	accept(t, reporter, requestIDs[0])

	if _, scheduled := reporter.scheduleRetry(); !scheduled {
		t.Fatal("the first rejection did not schedule a retry")
	}
	if _, scheduled := reporter.scheduleRetry(); scheduled {
		t.Fatal("a burst of rejections scheduled a second retry")
	}
	if sent, _ := reporter.writeNext(t.Context(), agent); sent {
		t.Fatal("new frames were sent while a retry was pending")
	}

	if err := reporter.resend(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	for _, want := range requestIDs[1:] {
		if _, requestID, _ := readFrame(t, peer); requestID != want {
			t.Fatalf("resent request %s, want %s", requestID, want)
		}
	}
}

func TestMetricReporterIgnoresSecondAnswersToResentFrames(t *testing.T) {
	store := testStore(t, 1, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	const (
		acceptedID  = "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"
		discardedID = "6e0c1d91-5145-440f-bf97-d84db4f83644"
	)
	reporter.inflight = []*metricFrame{{requestID: acceptedID}, {requestID: discardedID}}

	accept(t, reporter, acceptedID)
	reporter.discard(discardedID)

	for _, answer := range []string{
		`{"type":"metrics.rejected","request_id":"` + acceptedID + `","code":"busy"}`,
		`{"type":"metrics.accepted","request_id":"` + discardedID + `"}`,
		`{"type":"metrics.rejected","request_id":"` + discardedID + `","code":"invalid_report"}`,
	} {
		if err := reporter.handleResponse([]byte(answer)); !errors.Is(err, errDuplicateMetricsAcknowledgement) {
			t.Fatalf("%s: error = %v, want a duplicate", answer, err)
		}
	}
}

func TestMetricReporterCancelsRetryWhenEveryFrameIsAnswered(t *testing.T) {
	store := testStore(t, 1, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.inflight = []*metricFrame{{requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}}

	if _, scheduled := reporter.scheduleRetry(); !scheduled {
		t.Fatal("retry was not scheduled")
	}
	if reporter.cancelRetry() {
		t.Fatal("retry was cancelled while a frame awaits its answer")
	}
	accept(t, reporter, "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65")
	if !reporter.cancelRetry() || reporter.retrying {
		t.Fatal("retry stayed scheduled after the late acknowledgement")
	}
}

func TestMetricReporterSendsNoLiveFrameForTheNextHistorySample(t *testing.T) {
	store := testStore(t, 3, time.Now().UTC())
	reporter := newMetricReporter(store, "device:a")
	reporter.subscribe(true, 1)
	agent, peer := newWebSocketPair(t)

	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	readFrame(t, peer)

	// One sample arrives while the batch is still unacknowledged: it is the
	// next history sample, not a reason for a live frame.
	if err := store.Append(metrics.Snapshot{ObservedAt: time.Now().UTC(), Interval: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := reporter.writeLive(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	if reporter.liveSent != 0 {
		t.Fatalf("live frame sent for sequence %d", reporter.liveSent)
	}
}

func TestSubscribeMetricsValidatesAndAppliesSettings(t *testing.T) {
	store := testStore(t, 70, time.Now().UTC())
	x := &exchange{
		collectors:        Collectors{Metrics: store},
		reports:           &nodeReporter{state: &nodeReportState{complete: true}},
		metrics:           newMetricReporter(store, "device:a"),
		metricsReplyTimer: newStoppedTimer(),
		metricsRetryTimer: newStoppedTimer(),
	}
	agent, peer := newWebSocketPair(t)
	var rejected string
	reject := func(_ context.Context, _, code, _ string) error {
		rejected = code
		return nil
	}

	for _, frame := range []string{
		`{"type":"metrics.subscribe","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","live":true,"window":9}`,
		`{"type":"metrics.subscribe","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","live":true,"window":0}`,
		`{"type":"metrics.subscribe","request_id":"not-a-uuid","live":true,"window":2}`,
		`{"type":"metrics.subscribe","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","live":true,"window":2,"extra":1}`,
	} {
		rejected = ""
		if handled, err := x.handleRequest(t.Context(), agent, protocol.MetricsSubscribeType, []byte(frame), reject); !handled || err != nil {
			t.Fatalf("handleRequest(%s) = %v, %v", frame, handled, err)
		}
		if rejected != "invalid_message" {
			t.Fatalf("%s was answered with %q, want invalid_message", frame, rejected)
		}
	}

	request := `{"type":"metrics.subscribe","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","live":true,"window":2}`
	if _, err := x.handleRequest(t.Context(), agent, protocol.MetricsSubscribeType, []byte(request), reject); err != nil {
		t.Fatal(err)
	}
	defer stopTimer(x.metricsReplyTimer)

	_, _, data := readFrame(t, peer)
	var accepted protocol.MetricsSubscribeAccepted
	if err := protocol.DecodeStrict(data, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Type != protocol.MetricsSubscribeAcceptedType || !accepted.Live || accepted.Window != 2 {
		t.Fatalf("subscription answer = %+v", accepted)
	}

	// The window of two history frames goes out, then the newest sample live.
	want := []string{protocol.MetricsReportType, protocol.MetricsReportType, protocol.MetricsLiveType, protocol.MetricsLiveType}
	for _, wantType := range want {
		if messageType, _, _ := readFrame(t, peer); messageType != wantType {
			t.Fatalf("frame type = %s, want %s", messageType, wantType)
		}
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

func TestMetricFramesSendAnEmptyProcessListAfterTheStoreDroppedIt(t *testing.T) {
	store := testStore(t, 1, time.Now().UTC())
	items := store.After(0, 1)

	series := sampleSeries(protocol.MetricTypeNode, items)
	item := toProtocolItem(items[0])
	if series.Samples[0].Node.Processes.Items == nil || item.Sample.Node.Processes.Items == nil {
		t.Fatal("a stored sample without a process list is sent with processes.items null")
	}
}

func TestMetricReporterSplitsAWindowTooLargeForOneFrame(t *testing.T) {
	store, err := metricstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	containers := make([]protocol.ContainerMetrics, 300)
	for index := range containers {
		containers[index] = protocol.ContainerMetrics{ContainerID: fmt.Sprintf("container:%d", index), Name: "web", State: "running"}
	}
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour)
	for index := range 60 {
		err := store.Append(metrics.Snapshot{
			ObservedAt: start.Add(time.Duration(index) * time.Second), Interval: time.Second,
			ObservationScope: protocol.ObservationScopeHost, Containers: containers,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Maintain(time.Now(), true); err != nil {
		t.Fatal(err)
	}

	reporter := newMetricReporter(store, "device:a")
	reporter.subscribe(false, protocol.MaxMetricsWindow)
	agent, peer := newWebSocketPair(t)
	if _, err := reporter.writeNext(t.Context(), agent); err != nil {
		t.Fatal(err)
	}

	series := 0
	containerFrames := 0
	for len(reporter.inflight) > 0 {
		_, requestID, data := readFrame(t, peer)
		if len(data) > maxMetricsReportSize {
			t.Fatalf("frame of %d bytes exceeds the limit", len(data))
		}
		var frame protocol.MetricsRollupReport
		if err := protocol.DecodeStrict(data, &frame); err != nil {
			t.Fatal(err)
		}
		point := frame.Metric.Points[0]
		if len(frame.Metric.Points) != 1 || point.FirstSequence != 1 || point.LastSequence != 60 || len(point.Series) > maxRollupSeries {
			t.Fatalf("part has %d points, sequences %d-%d, %d series", len(frame.Metric.Points), point.FirstSequence, point.LastSequence, len(point.Series))
		}
		if frame.Metric.Type == protocol.MetricTypeContainer {
			containerFrames++
			series += len(point.Series)
		}

		accept(t, reporter, requestID)
		if _, err := reporter.writeNext(t.Context(), agent); err != nil {
			t.Fatal(err)
		}
	}

	if containerFrames < 2 || series != len(store.After(0, 1)[0].Container.Series) {
		t.Fatalf("%d container parts carry %d series", containerFrames, series)
	}
	if store.Cursor("device:a") != 60 {
		t.Fatalf("cursor = %d after every part, want 60", store.Cursor("device:a"))
	}
}
