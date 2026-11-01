package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/metricstore"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const watchRequestID = "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"

var watchBase = time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)

func watchSample(at time.Time, cpu float64, containers ...protocol.ContainerMetrics) metrics.Snapshot {
	return metrics.Snapshot{
		ObservedAt: at,
		Interval:   time.Second,
		Node: protocol.NodeMetrics{
			CPU:       protocol.CPUMetrics{Total: protocol.CPUUtilizationMetrics{UsagePercent: cpu}},
			Memory:    protocol.MemoryMetrics{TotalBytes: 1000, UsedBytes: 400},
			Processes: protocol.ProcessMetrics{Items: []protocol.ProcessMetric{{PID: 1, CPUPercent: 1}, {PID: 2, CPUPercent: 9}, {PID: 3, CPUPercent: 5}}},
		},
		Containers:      containers,
		ContainersFresh: true,
	}
}

type watchHarness struct {
	t       *testing.T
	store   *metricstore.Store
	x       *exchange
	client  *websocket.Conn
	server  *websocket.Conn
	rejects []string
}

func newWatchHarness(t *testing.T) *watchHarness {
	t.Helper()

	store, err := metricstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client, server := newWebSocketPair(t)
	harness := &watchHarness{
		t: t, store: store, client: client, server: server,
		x: &exchange{collectors: Collectors{Metrics: store}, metrics: newMetricWatch(store, "test")},
	}
	t.Cleanup(harness.x.metrics.stop)

	return harness
}

func (h *watchHarness) append(snapshot metrics.Snapshot) {
	h.t.Helper()

	if err := h.store.Append(snapshot); err != nil {
		h.t.Fatal(err)
	}
}

func (h *watchHarness) reject(_ context.Context, _, code, _ string) error {
	h.rejects = append(h.rejects, code)

	return nil
}

func (h *watchHarness) watch(views ...protocol.MetricsView) {
	h.t.Helper()

	if views == nil {
		views = []protocol.MetricsView{}
	}
	data, err := json.Marshal(protocol.MetricsWatch{Type: protocol.MetricsWatchType, RequestID: watchRequestID, Views: views})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.x.watchMetrics(h.t.Context(), h.server, data, h.reject); err != nil {
		h.t.Fatal(err)
	}
}

// read decodes the next frame the session wrote, which must be of the
// given type.
func (h *watchHarness) read(messageType string, target any) {
	h.t.Helper()

	ctx, cancel := context.WithTimeout(h.t.Context(), 2*time.Second)
	defer cancel()

	_, data, err := h.client.Read(ctx)
	if err != nil {
		h.t.Fatalf("read %s: %v", messageType, err)
	}
	if got, _ := protocol.MessageType(data); got != messageType {
		h.t.Fatalf("got %s, want %s: %s", got, messageType, data)
	}
	if err := protocol.DecodeStrict(data, target); err != nil {
		h.t.Fatalf("decode %s: %v", messageType, err)
	}
}

func TestWatchSendsTheCurrentValuesAtOnceAndThenOnlyChanges(t *testing.T) {
	h := newWatchHarness(t)
	h.append(watchSample(watchBase, 12.34))

	h.watch(protocol.MetricsView{Scope: protocol.MetricsScopeOverview})

	var accepted protocol.MetricsWatchAccepted
	h.read(protocol.MetricsWatchAcceptedType, &accepted)
	if accepted.IntervalMS != protocol.MetricsIntervalDefaultMS || accepted.StreamID != h.store.StreamID() {
		t.Fatalf("accepted = %+v", accepted)
	}
	var schema protocol.MetricsSchema
	h.read(protocol.MetricsSchemaType, &schema)
	if !schema.Full || schema.Version != 1 || schema.Columns[0].Key != "cpu.usage_percent" || schema.Columns[0].Index != 0 {
		t.Fatalf("schema = %+v", schema)
	}
	var tick protocol.MetricsTick
	h.read(protocol.MetricsTickType, &tick)
	if len(tick.Values) != len(schema.Columns) || *tick.Values[0] != 12.3 {
		t.Fatalf("keyframe = %+v", tick)
	}
	if demand := h.store.Demand(); !demand.Containers || demand.Processes != 0 {
		t.Fatalf("demand = %+v", demand)
	}

	// Only the value that changed is sent.
	h.append(watchSample(watchBase.Add(time.Second), 50))
	if err := h.x.metrics.send(t.Context(), h.server); err != nil {
		t.Fatal(err)
	}
	tick = protocol.MetricsTick{}
	h.read(protocol.MetricsTickType, &tick)
	if tick.Values != nil || len(tick.Changes) != 1 || *tick.Changes["0"] != 50 {
		t.Fatalf("delta = %+v", tick)
	}

	// A new container adds columns without a full schema; when it goes
	// its columns are removed and their indices are not reused.
	web := protocol.ContainerMetrics{ContainerID: "a", Name: "web", CPU: protocol.ContainerCPUMetrics{UsagePercent: 7}}
	h.append(watchSample(watchBase.Add(2*time.Second), 50, web))
	if err := h.x.metrics.send(t.Context(), h.server); err != nil {
		t.Fatal(err)
	}
	var added protocol.MetricsSchema
	h.read(protocol.MetricsSchemaType, &added)
	if added.Full || added.Version != 2 || len(added.Columns) == 0 || added.Columns[0].Index < len(schema.Columns) {
		t.Fatalf("added = %+v", added)
	}
	h.read(protocol.MetricsTickType, &tick)
	if tick.Version != 2 {
		t.Fatalf("tick version = %d", tick.Version)
	}

	h.append(watchSample(watchBase.Add(3*time.Second), 50))
	if err := h.x.metrics.send(t.Context(), h.server); err != nil {
		t.Fatal(err)
	}
	var removed protocol.MetricsSchema
	h.read(protocol.MetricsSchemaType, &removed)
	if len(removed.Removed) != len(added.Columns) || len(removed.Columns) != 0 {
		t.Fatalf("removed = %+v", removed)
	}

	// An empty watch stops it and clears the demand.
	h.watch()
	accepted = protocol.MetricsWatchAccepted{}
	h.read(protocol.MetricsWatchAcceptedType, &accepted)
	if len(accepted.Views) != 0 || h.x.metrics.active {
		t.Fatalf("stopped watch = %+v", accepted)
	}
	if demand := h.store.Demand(); demand != (metrics.Demand{}) {
		t.Fatalf("demand after stop = %+v", demand)
	}
}

func TestWatchSendsTheTopProcessesAndAsksForThem(t *testing.T) {
	h := newWatchHarness(t)
	h.append(watchSample(watchBase, 5))

	h.watch(protocol.MetricsView{Scope: protocol.MetricsScopeProcesses, Limit: 2})

	var accepted protocol.MetricsWatchAccepted
	h.read(protocol.MetricsWatchAcceptedType, &accepted)
	var detail protocol.MetricsDetail
	h.read(protocol.MetricsDetailType, &detail)
	items := detail.Processes.Items
	if len(items) != 2 || items[0].PID != 2 || items[1].PID != 3 || !detail.Processes.Truncated {
		t.Fatalf("processes = %+v", detail.Processes)
	}
	if demand := h.store.Demand(); demand.Processes != 2 {
		t.Fatalf("demand = %+v", demand)
	}
}

func TestWatchRejectsInvalidSettings(t *testing.T) {
	h := newWatchHarness(t)

	for _, raw := range []string{
		`{"type":"metrics.watch","request_id":"` + watchRequestID + `","views":[{"scope":"overview"}],"interval_ms":200}`,
		`{"type":"metrics.watch","request_id":"` + watchRequestID + `","views":[{"scope":"container"}]}`,
		`{"type":"metrics.watch","request_id":"` + watchRequestID + `","views":[{"scope":"all"}]}`,
		`{"type":"metrics.watch","request_id":"` + watchRequestID + `"}`,
		`{"type":"metrics.watch","request_id":"not-a-uuid","views":[]}`,
	} {
		h.rejects = nil
		if err := h.x.watchMetrics(t.Context(), h.server, []byte(raw), h.reject); err != nil {
			t.Fatal(err)
		}
		if len(h.rejects) != 1 || h.rejects[0] != "invalid_message" {
			t.Errorf("%s: rejects = %v", raw, h.rejects)
		}
	}
}

func TestHistoryAndEventsAreAnsweredInOneFrame(t *testing.T) {
	h := newWatchHarness(t)
	for offset := range 30 {
		h.append(watchSample(watchBase.Add(time.Duration(offset)*time.Second), 20))
	}

	request := `{"type":"metrics.history","request_id":"` + watchRequestID + `","range":"5m","series":["cpu.usage_percent"]}`
	if err := h.x.answerMetricsHistory(t.Context(), h.server, []byte(request), h.reject); err != nil {
		t.Fatal(err)
	}
	var history protocol.MetricsHistoryResult
	h.read(protocol.MetricsHistoryResultType, &history)
	if history.RequestID != watchRequestID || history.StepS != 1 || len(history.Series) != 1 || len(history.Series[0].Avg) != 300 {
		t.Fatalf("history = %+v", history)
	}

	request = `{"type":"metrics.history","request_id":"` + watchRequestID + `","range":"30d","series":["cpu.usage_percent"]}`
	if err := h.x.answerMetricsHistory(t.Context(), h.server, []byte(request), h.reject); err != nil {
		t.Fatal(err)
	}
	if len(h.rejects) != 1 || h.rejects[0] != "invalid_range" {
		t.Fatalf("rejects = %v", h.rejects)
	}

	request = `{"type":"metrics.events","request_id":"` + watchRequestID + `","from":"2030-01-02T00:00:00Z","to":"2030-01-02T04:00:00Z"}`
	if err := h.x.answerMetricsEvents(t.Context(), h.server, []byte(request), h.reject); err != nil {
		t.Fatal(err)
	}
	var events protocol.MetricsEventsResult
	h.read(protocol.MetricsEventsResultType, &events)
	if events.RequestID != watchRequestID || events.Events == nil {
		t.Fatalf("events = %+v", events)
	}
}
