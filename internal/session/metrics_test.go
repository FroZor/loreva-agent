package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestEncodeMetricReportUsesRequestIDWithoutCounters(t *testing.T) {
	sample := canonicalMetricSample(1)
	queued := queuedMetricSample{metricType: protocol.MetricTypeNode, sample: sample}

	payload, err := encodeMetricReport(
		"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65",
		"d1b181c1-52ec-4d55-b2c9-b1428305b294",
		&queued,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("batch_id")) || bytes.Contains(payload, []byte("processed")) ||
		bytes.Contains(payload, []byte("failed")) {
		t.Fatalf("metrics payload contains obsolete fields: %s", payload)
	}

	var report protocol.MetricsReport
	if err := protocol.DecodeStrict(payload, &report); err != nil {
		t.Fatal(err)
	}
	if report.RequestID != "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65" {
		t.Fatalf("request_id = %q", report.RequestID)
	}
	if report.Metric.Type != protocol.MetricTypeNode {
		t.Fatalf("metric type = %q", report.Metric.Type)
	}
}

func TestMetricReporterAcceptsAndDeduplicatesAcknowledgement(t *testing.T) {
	state := metricState{active: &activeMetricReport{requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}}
	reporter := metricReporter{state: &state}
	acknowledgement := []byte(`{"type":"metrics.accepted","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}`)

	if err := reporter.handleResponse(acknowledgement); err != nil {
		t.Fatal(err)
	}
	if state.active != nil {
		t.Fatal("accepted metric request remains active")
	}
	if err := reporter.handleResponse(acknowledgement); !errors.Is(err, errDuplicateMetricsAcknowledgement) {
		t.Fatalf("duplicate acknowledgement error = %v", err)
	}
}

func TestMetricReporterKeepsRejectedRequestForRetry(t *testing.T) {
	state := metricState{active: &activeMetricReport{requestID: "2ab9d734-7434-4cdf-bca4-6ce7a46cdd65"}}
	reporter := metricReporter{state: &state}
	rejection := []byte(`{"type":"metrics.rejected","request_id":"2ab9d734-7434-4cdf-bca4-6ce7a46cdd65","code":"temporarily_unavailable"}`)

	err := reporter.handleResponse(rejection)
	metricError, ok := errors.AsType[*metricRejection](err)
	if !ok || metricError.code != "temporarily_unavailable" {
		t.Fatalf("rejection error = %v", err)
	}
	if state.active == nil {
		t.Fatal("rejected metric request was discarded before policy classification")
	}
}

func TestMetricReporterQueuesNodeBeforeContainers(t *testing.T) {
	state := metricState{}
	reporter := metricReporter{state: &state}

	err := reporter.enqueue(metricCollection{snapshot: metrics.Snapshot{
		ObservedAt:       time.Unix(1, 0).UTC(),
		Interval:         time.Second,
		ObservationScope: protocol.ObservationScopeHost,
		Node:             canonicalNodeMetrics(),
		Containers:       []protocol.ContainerMetrics{},
		CollectionIssues: []protocol.CollectionIssue{
			{Component: "gpus", Code: "not_available"},
			{Component: "containers.docker", Code: "client_unavailable"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if len(state.queued) != 2 {
		t.Fatalf("queued requests = %d, want 2", len(state.queued))
	}
	if state.queued[0].metricType != protocol.MetricTypeNode || state.queued[0].sample.Node == nil {
		t.Fatalf("first queued metric = %#v", state.queued[0])
	}
	if state.queued[1].metricType != protocol.MetricTypeContainer || state.queued[1].sample.Containers == nil {
		t.Fatalf("second queued metric = %#v", state.queued[1])
	}
	if len(state.queued[0].sample.CollectionIssues) != 1 ||
		state.queued[0].sample.CollectionIssues[0].Component != "gpus" {
		t.Fatalf("node issues = %#v", state.queued[0].sample.CollectionIssues)
	}
	if len(state.queued[1].sample.CollectionIssues) != 1 ||
		state.queued[1].sample.CollectionIssues[0].Component != "containers.docker" {
		t.Fatalf("container issues = %#v", state.queued[1].sample.CollectionIssues)
	}
}

func TestMetricReporterBoundsQueueAndMarksTruncation(t *testing.T) {
	state := metricState{}
	reporter := metricReporter{state: &state}

	for sequence := uint64(1); sequence <= maxQueuedMetricRequests/2+1; sequence++ {
		if err := reporter.enqueue(metricCollection{snapshot: metrics.Snapshot{
			ObservedAt:       time.Unix(int64(sequence), 0).UTC(),
			Interval:         time.Second,
			ObservationScope: protocol.ObservationScopeHost,
			Node:             canonicalNodeMetrics(),
			Containers:       []protocol.ContainerMetrics{},
		}}); err != nil {
			t.Fatal(err)
		}
	}

	if len(state.queued) != maxQueuedMetricRequests {
		t.Fatalf("queued requests = %d, want %d", len(state.queued), maxQueuedMetricRequests)
	}
	last := state.queued[len(state.queued)-1]
	encoded, err := json.Marshal(last.sample.CollectionIssues)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"metrics.buffer"`)) {
		t.Fatalf("last sample issues = %s", encoded)
	}
}

func canonicalMetricSample(sequence uint64) protocol.MetricSample {
	node := canonicalNodeMetrics()

	return protocol.MetricSample{
		Sequence:         sequence,
		ObservedAt:       time.Unix(int64(sequence), 0).UTC(),
		IntervalMS:       1000,
		ObservationScope: protocol.ObservationScopeHost,
		Node:             &node,
	}
}

func canonicalNodeMetrics() protocol.NodeMetrics {
	return protocol.NodeMetrics{
		CPU: protocol.CPUMetrics{
			Total:   protocol.CPUUtilizationMetrics{},
			Logical: []protocol.LogicalProcessorMetrics{},
		},
		Memory: protocol.MemoryMetrics{},
		Storage: protocol.StorageMetrics{
			Devices:     []protocol.StorageDeviceMetrics{},
			Filesystems: []protocol.FilesystemMetrics{},
		},
		Network: []protocol.NetworkMetrics{},
		GPUs:    []protocol.GPUMetrics{},
		Processes: protocol.ProcessMetrics{
			Items: []protocol.ProcessMetric{},
		},
	}
}
