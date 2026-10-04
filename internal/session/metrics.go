package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	metricsInterval         = time.Second
	metricsCollectTimeout   = 900 * time.Millisecond
	metricsWriteTimeout     = 10 * time.Second
	metricsReplyTimeout     = 30 * time.Second
	maxMetricsReportSize    = 512 * 1024
	maxQueuedMetricRequests = 120
)

type metricCollection struct {
	snapshot metrics.Snapshot
	err      error
}

type activeMetricReport struct {
	requestID  string
	metricType string
	payload    []byte
}

type queuedMetricSample struct {
	metricType string
	sample     protocol.MetricSample
}

type metricState struct {
	streamID              string
	nextSequence          uint64
	queued                []queuedMetricSample
	active                *activeMetricReport
	retryAttempt          int
	lastAcceptedRequestID string
}

type metricReporter struct {
	collect func(context.Context) (metrics.Snapshot, error)
	results chan metricCollection
	state   *metricState
}

type metricRejection struct {
	code    string
	message string
}

var errDuplicateMetricsAcknowledgement = errors.New("duplicate metrics acknowledgement")

func (rejection *metricRejection) Error() string {
	if rejection.message == "" {
		return "portal rejected metrics: " + rejection.code
	}

	return "portal rejected metrics: " + rejection.code + ": " + rejection.message
}

func newMetricReporter(
	ctx context.Context,
	collect func(context.Context) (metrics.Snapshot, error),
	state *metricState,
) (*metricReporter, error) {
	if state.streamID == "" {
		streamID, err := agentcrypto.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("create metrics stream ID: %w", err)
		}
		state.streamID = streamID
	}

	reporter := &metricReporter{
		collect: collect,
		results: make(chan metricCollection, 1),
		state:   state,
	}
	if collect != nil {
		go reporter.collectLoop(ctx)
	}

	return reporter, nil
}

func (reporter *metricReporter) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		collectionCtx, cancel := context.WithTimeout(ctx, metricsCollectTimeout)
		snapshot, err := reporter.collect(collectionCtx)
		cancel()

		select {
		case reporter.results <- metricCollection{snapshot: snapshot, err: err}:
		case <-ctx.Done():
			return
		}
	}
}

func (reporter *metricReporter) enqueue(collection metricCollection) error {
	if collection.err != nil {
		return collection.err
	}

	intervalMS := collection.snapshot.Interval.Milliseconds()
	if intervalMS < 1 {
		intervalMS = 1
	}
	if intervalMS > math.MaxUint32 {
		intervalMS = math.MaxUint32
	}

	nodeIssues, containerIssues := splitMetricIssues(collection.snapshot.CollectionIssues)
	node := collection.snapshot.Node
	containers := protocol.ContainerMetricSet{
		Items: append([]protocol.ContainerMetrics(nil), collection.snapshot.Containers...),
	}

	reporter.enqueueSample(queuedMetricSample{
		metricType: protocol.MetricTypeNode,
		sample: protocol.MetricSample{
			Sequence:         reporter.nextSequence(),
			ObservedAt:       collection.snapshot.ObservedAt,
			IntervalMS:       uint64(intervalMS),
			ObservationScope: collection.snapshot.ObservationScope,
			Node:             &node,
			CollectionIssues: nodeIssues,
		},
	})
	reporter.enqueueSample(queuedMetricSample{
		metricType: protocol.MetricTypeContainer,
		sample: protocol.MetricSample{
			Sequence:         reporter.nextSequence(),
			ObservedAt:       collection.snapshot.ObservedAt,
			IntervalMS:       uint64(intervalMS),
			ObservationScope: collection.snapshot.ObservationScope,
			Containers:       &containers,
			CollectionIssues: containerIssues,
		},
	})

	return nil
}

func (reporter *metricReporter) nextSequence() uint64 {
	reporter.state.nextSequence++

	return reporter.state.nextSequence
}

func (reporter *metricReporter) enqueueSample(queued queuedMetricSample) {
	if len(reporter.state.queued) == maxQueuedMetricRequests {
		appendMetricIssue(&queued.sample, "metrics.buffer", "truncated")
		copy(reporter.state.queued, reporter.state.queued[1:])
		reporter.state.queued[len(reporter.state.queued)-1] = queued
		return
	}

	reporter.state.queued = append(reporter.state.queued, queued)
}

func splitMetricIssues(issues []protocol.CollectionIssue) ([]protocol.CollectionIssue, []protocol.CollectionIssue) {
	nodeIssues := make([]protocol.CollectionIssue, 0, len(issues))
	containerIssues := make([]protocol.CollectionIssue, 0, len(issues))

	for _, issue := range issues {
		if strings.HasPrefix(issue.Component, "containers") {
			containerIssues = append(containerIssues, issue)
			continue
		}

		nodeIssues = append(nodeIssues, issue)
	}

	return nodeIssues, containerIssues
}

func (reporter *metricReporter) writeNext(ctx context.Context, conn *websocket.Conn) (bool, error) {
	if reporter.state.active != nil {
		return false, nil
	}
	if len(reporter.state.queued) == 0 {
		return false, nil
	}

	requestID, err := agentcrypto.NewUUID()
	if err != nil {
		return false, fmt.Errorf("create metrics request ID: %w", err)
	}

	queued := reporter.state.queued[0]
	payload, err := encodeMetricReport(requestID, reporter.state.streamID, &queued)
	if err != nil {
		return false, err
	}
	reporter.state.queued = reporter.state.queued[1:]
	reporter.state.active = &activeMetricReport{
		requestID:  requestID,
		metricType: queued.metricType,
		payload:    payload,
	}

	if err := reporter.writeActive(ctx, conn); err != nil {
		return false, err
	}

	return true, nil
}

func (reporter *metricReporter) writeReady(ctx context.Context, conn *websocket.Conn) (bool, error) {
	if reporter.state.active != nil {
		return true, reporter.writeActive(ctx, conn)
	}

	return reporter.writeNext(ctx, conn)
}

func encodeMetricReport(requestID, streamID string, queued *queuedMetricSample) ([]byte, error) {
	for {
		report := protocol.MetricsReport{
			Type:          protocol.MetricsReportType,
			SchemaVersion: protocol.MetricsSchemaVersion,
			RequestID:     requestID,
			StreamID:      streamID,
			Metric: protocol.MetricSeries{
				Type:    queued.metricType,
				Samples: []protocol.MetricSample{queued.sample},
			},
		}

		payload, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("encode metrics report: %w", err)
		}
		if len(payload) <= maxMetricsReportSize {
			return payload, nil
		}

		switch {
		case queued.sample.Node != nil && len(queued.sample.Node.Processes.Items) > 0:
			items := queued.sample.Node.Processes.Items
			queued.sample.Node.Processes.Items = items[:len(items)/2]
			queued.sample.Node.Processes.Truncated = true
			appendMetricIssue(&queued.sample, "processes", "truncated")
		case queued.sample.Containers != nil && len(queued.sample.Containers.Items) > 0:
			items := queued.sample.Containers.Items
			queued.sample.Containers.Items = items[:len(items)/2]
			appendMetricIssue(&queued.sample, "containers", "truncated")
		default:
			return nil, fmt.Errorf("metrics report exceeds %d bytes without optional entries", maxMetricsReportSize)
		}
	}
}

func appendMetricIssue(sample *protocol.MetricSample, component, code string) {
	for _, issue := range sample.CollectionIssues {
		if issue.Component == component && issue.Code == code {
			return
		}
	}

	sample.CollectionIssues = append(sample.CollectionIssues, protocol.CollectionIssue{
		Component: component,
		Code:      code,
	})
}

func (reporter *metricReporter) writeActive(ctx context.Context, conn *websocket.Conn) error {
	if reporter.state.active == nil {
		return errors.New("metrics retry has no active request")
	}

	writeCtx, cancel := context.WithTimeout(ctx, metricsWriteTimeout)
	err := conn.Write(writeCtx, websocket.MessageText, reporter.state.active.payload)
	cancel()

	if err != nil {
		return fmt.Errorf("write metrics report: %w", err)
	}

	return nil
}

func (reporter *metricReporter) handleResponse(data []byte) error {
	messageType, err := protocol.MessageType(data)
	if err != nil {
		return errors.New("metrics result is not valid JSON")
	}

	if messageType == protocol.MetricsAcceptedType {
		var accepted protocol.MetricsAccepted
		if err := protocol.DecodeStrict(data, &accepted); err != nil {
			return fmt.Errorf("decode metrics acknowledgement: %w", err)
		}
		if accepted.RequestID == reporter.state.lastAcceptedRequestID &&
			(reporter.state.active == nil || accepted.RequestID != reporter.state.active.requestID) {
			return errDuplicateMetricsAcknowledgement
		}
		if reporter.state.active == nil || accepted.RequestID != reporter.state.active.requestID {
			return errors.New("invalid metrics acknowledgement")
		}

		reporter.state.lastAcceptedRequestID = accepted.RequestID
		reporter.state.active = nil
		reporter.state.retryAttempt = 0

		return nil
	}

	if messageType != protocol.MetricsRejectedType {
		return fmt.Errorf("unexpected metrics result type %q", messageType)
	}

	var rejected protocol.NodeReportRejected
	if err := protocol.DecodeStrict(data, &rejected); err != nil {
		return fmt.Errorf("decode metrics rejection: %w", err)
	}
	if reporter.state.active == nil || rejected.RequestID != reporter.state.active.requestID || rejected.Code == "" {
		return errors.New("invalid metrics rejection")
	}

	return &metricRejection{code: rejected.Code, message: rejected.Message}
}

func (reporter *metricReporter) retryDelay() time.Duration {
	reporter.state.retryAttempt++

	return retryDelay(reporter.state.retryAttempt)
}

func (reporter *metricReporter) discardActive() {
	reporter.state.active = nil
	reporter.state.retryAttempt = 0
}

func (reporter *metricReporter) activeType() string {
	if reporter.state.active == nil {
		return protocol.MetricsReportType
	}

	return protocol.MetricsReportType + "/" + reporter.state.active.metricType
}
