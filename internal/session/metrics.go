package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/metricstore"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	metricsWriteTimeout  = 10 * time.Second
	metricsReplyTimeout  = 30 * time.Second
	maxMetricsReportSize = 512 * 1024
	// maxMetricBatch is the most samples or rollups one frame carries; the
	// contract allows 60 samples per metrics.report.
	maxMetricBatch = 60
)

// MetricsSource is the agent's metrics store. Every session is a reader with
// its own cursor, so a reader that was offline catches up where it stopped.
type MetricsSource interface {
	StreamID() string
	After(after uint64, limit int) []metricstore.Item
	Range(from, to time.Time, limit int) []metricstore.Item
	Changed() <-chan struct{}
	Cursor(reader string) uint64
	SetCursor(reader string, sequence uint64)
	RemoveCursor(reader string)
}

type activeMetricReport struct {
	requestID  string
	metricType string
	payload    []byte
	// commit is the cursor to store once this frame is acknowledged; zero
	// while more frames of the same batch follow.
	commit uint64
}

// metricReporter delivers stored metrics to one reader, one frame at a time.
// A batch of samples becomes a node frame and a container frame; the cursor
// moves when both are acknowledged.
type metricReporter struct {
	source  MetricsSource
	reader  string
	cursor  uint64
	wake    <-chan struct{}
	pending []activeMetricReport

	active                *activeMetricReport
	retryAttempt          int
	lastAcceptedRequestID string
}

type metricRejection struct {
	code    string
	message string
}

var errDuplicateMetricsAcknowledgement = errors.New("duplicate metrics acknowledgement")

func (rejection *metricRejection) Error() string {
	if rejection.message == "" {
		return "peer rejected metrics: " + rejection.code
	}

	return "peer rejected metrics: " + rejection.code + ": " + rejection.message
}

func newMetricReporter(source MetricsSource, reader string) *metricReporter {
	reporter := &metricReporter{source: source, reader: reader}
	if source != nil {
		reporter.cursor = source.Cursor(reader)
		reporter.wake = source.Changed()
	}

	return reporter
}

// woke re-arms the wake channel after it fired.
func (reporter *metricReporter) woke() {
	reporter.wake = reporter.source.Changed()
}

// writeNext sends the next frame unless one is waiting for its answer.
func (reporter *metricReporter) writeNext(ctx context.Context, conn *websocket.Conn) (bool, error) {
	if reporter.active != nil || reporter.source == nil {
		return false, nil
	}
	if len(reporter.pending) == 0 {
		frames, err := reporter.nextBatch()
		if err != nil {
			return false, err
		}
		reporter.pending = frames
	}
	if len(reporter.pending) == 0 {
		return false, nil
	}

	next := reporter.pending[0]
	reporter.pending = reporter.pending[1:]
	reporter.active = &next

	if err := reporter.writeActive(ctx, conn); err != nil {
		return false, err
	}

	return true, nil
}

func (reporter *metricReporter) writeReady(ctx context.Context, conn *websocket.Conn) (bool, error) {
	if reporter.active != nil {
		return true, reporter.writeActive(ctx, conn)
	}

	return reporter.writeNext(ctx, conn)
}

// nextBatch encodes the next run of items of one kind as frames, halving the
// batch until every frame fits the size limit.
func (reporter *metricReporter) nextBatch() ([]activeMetricReport, error) {
	items := reporter.source.After(reporter.cursor, maxMetricBatch)
	if len(items) == 0 {
		return nil, nil
	}

	rollup := items[0].Record == nil
	end := 1
	for end < len(items) && (items[end].Record == nil) == rollup {
		end++
	}
	items = items[:end]

	for {
		frames, err := reporter.encodeBatch(items, rollup)
		if err == nil || len(items) == 1 {
			return frames, err
		}
		if !errors.Is(err, errMetricsFrameTooLarge) {
			return nil, err
		}

		items = items[:len(items)/2]
	}
}

var errMetricsFrameTooLarge = errors.New("metrics frame is too large")

func (reporter *metricReporter) encodeBatch(items []metricstore.Item, rollup bool) ([]activeMetricReport, error) {
	streamID := reporter.source.StreamID()
	last := items[len(items)-1].LastSequence()

	var frames []activeMetricReport
	for index, metricType := range []string{protocol.MetricTypeNode, protocol.MetricTypeContainer} {
		requestID, err := agentcrypto.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("create metrics request ID: %w", err)
		}

		var frame any
		if rollup {
			frame = rollupFrame(requestID, streamID, metricType, items)
		} else {
			frame = sampleFrame(requestID, streamID, metricType, items)
		}

		payload, err := json.Marshal(frame)
		if err != nil {
			return nil, fmt.Errorf("encode metrics frame: %w", err)
		}
		if len(payload) > maxMetricsReportSize {
			if len(items) > 1 {
				return nil, errMetricsFrameTooLarge
			}
			if payload, err = shrinkSingleSample(frame); err != nil {
				return nil, err
			}
		}

		active := activeMetricReport{requestID: requestID, metricType: metricType, payload: payload}
		if index == 1 {
			active.commit = last
		}
		frames = append(frames, active)
	}

	return frames, nil
}

func sampleFrame(requestID, streamID, metricType string, items []metricstore.Item) *protocol.MetricsReport {
	samples := make([]protocol.MetricSample, 0, len(items))
	for _, item := range items {
		record := item.Record
		nodeIssues, containerIssues := splitMetricIssues(record.Issues)
		sample := protocol.MetricSample{
			Sequence:         record.Sequence,
			ObservedAt:       record.ObservedAt,
			IntervalMS:       record.IntervalMS,
			ObservationScope: record.ObservationScope,
		}
		if metricType == protocol.MetricTypeNode {
			node := record.Node
			sample.Node = &node
			sample.CollectionIssues = nodeIssues
		} else {
			sample.Containers = &protocol.ContainerMetricSet{Items: append([]protocol.ContainerMetrics{}, record.Containers...)}
			sample.CollectionIssues = containerIssues
		}
		samples = append(samples, sample)
	}

	return &protocol.MetricsReport{
		Type:          protocol.MetricsReportType,
		SchemaVersion: protocol.MetricsSchemaVersion,
		RequestID:     requestID,
		StreamID:      streamID,
		Metric:        protocol.MetricSeries{Type: metricType, Samples: samples},
	}
}

func rollupFrame(requestID, streamID, metricType string, items []metricstore.Item) *protocol.MetricsRollupReport {
	points := make([]protocol.MetricRollup, 0, len(items))
	for _, item := range items {
		if metricType == protocol.MetricTypeNode {
			points = append(points, *item.Node)
		} else {
			points = append(points, *item.Container)
		}
	}

	return &protocol.MetricsRollupReport{
		Type:          protocol.MetricsRollupType,
		SchemaVersion: protocol.MetricsSchemaVersion,
		RequestID:     requestID,
		StreamID:      streamID,
		Metric:        protocol.MetricRollupSeries{Type: metricType, Points: points},
	}
}

// shrinkSingleSample trims optional lists of one oversized sample.
func shrinkSingleSample(frame any) ([]byte, error) {
	report, ok := frame.(*protocol.MetricsReport)
	if !ok || len(report.Metric.Samples) != 1 {
		return nil, fmt.Errorf("metrics frame exceeds %d bytes", maxMetricsReportSize)
	}

	sample := &report.Metric.Samples[0]
	for {
		payload, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("encode metrics report: %w", err)
		}
		if len(payload) <= maxMetricsReportSize {
			return payload, nil
		}

		switch {
		case sample.Node != nil && len(sample.Node.Processes.Items) > 0:
			items := sample.Node.Processes.Items
			sample.Node.Processes.Items = items[:len(items)/2]
			sample.Node.Processes.Truncated = true
			appendMetricIssue(sample, "processes", "truncated")
		case sample.Containers != nil && len(sample.Containers.Items) > 0:
			items := sample.Containers.Items
			sample.Containers.Items = items[:len(items)/2]
			appendMetricIssue(sample, "containers", "truncated")
		default:
			return nil, fmt.Errorf("metrics report exceeds %d bytes without optional entries", maxMetricsReportSize)
		}
	}
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
	if reporter.active == nil {
		return errors.New("metrics retry has no active request")
	}

	writeCtx, cancel := context.WithTimeout(ctx, metricsWriteTimeout)
	err := conn.Write(writeCtx, websocket.MessageText, reporter.active.payload)
	cancel()

	if err != nil {
		return fmt.Errorf("write metrics frame: %w", err)
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
		if accepted.RequestID == reporter.lastAcceptedRequestID &&
			(reporter.active == nil || accepted.RequestID != reporter.active.requestID) {
			return errDuplicateMetricsAcknowledgement
		}
		if reporter.active == nil || accepted.RequestID != reporter.active.requestID {
			return errors.New("invalid metrics acknowledgement")
		}

		reporter.lastAcceptedRequestID = accepted.RequestID
		reporter.complete()

		return nil
	}

	if messageType != protocol.MetricsRejectedType {
		return fmt.Errorf("unexpected metrics result type %q", messageType)
	}

	var rejected protocol.NodeReportRejected
	if err := protocol.DecodeStrict(data, &rejected); err != nil {
		return fmt.Errorf("decode metrics rejection: %w", err)
	}
	if reporter.active == nil || rejected.RequestID != reporter.active.requestID || rejected.Code == "" {
		return errors.New("invalid metrics rejection")
	}

	return &metricRejection{code: rejected.Code, message: rejected.Message}
}

// complete finishes the active frame and, at the end of a batch, stores the
// reader's cursor.
func (reporter *metricReporter) complete() {
	if commit := reporter.active.commit; commit > reporter.cursor {
		reporter.cursor = commit
		reporter.source.SetCursor(reporter.reader, commit)
	}

	reporter.active = nil
	reporter.retryAttempt = 0
}

func (reporter *metricReporter) retryDelay() time.Duration {
	reporter.retryAttempt++

	return retryDelay(reporter.retryAttempt)
}

// discardActive skips a frame the peer rejected for good, so one bad frame
// cannot stall the reader.
func (reporter *metricReporter) discardActive() {
	reporter.complete()
}

func (reporter *metricReporter) activeType() string {
	if reporter.active == nil {
		return protocol.MetricsReportType
	}

	return protocol.MetricsReportType + "/" + reporter.active.metricType
}

// queryResult answers metrics.query from the store, cut to fit one frame.
func queryResult(source MetricsSource, requestID string, from, to time.Time) (protocol.MetricsQueryResult, error) {
	result := protocol.MetricsQueryResult{
		Type:      protocol.MetricsQueryResultType,
		RequestID: requestID,
		StreamID:  source.StreamID(),
		Items:     []protocol.MetricsItem{},
	}

	size := 512
	for _, item := range source.Range(from, to, 100000) {
		converted := toProtocolItem(item)
		data, err := json.Marshal(converted)
		if err != nil {
			return result, err
		}
		if size+len(data) > maxMetricsReportSize-1024 {
			// An item that alone exceeds the frame is skipped, so paging
			// still moves forward.
			if len(result.Items) == 0 {
				continue
			}

			next := itemStart(item)
			result.NextFrom = &next
			break
		}

		size += len(data) + 1
		result.Items = append(result.Items, converted)
	}

	return result, nil
}

func toProtocolItem(item metricstore.Item) protocol.MetricsItem {
	if item.Record == nil {
		return protocol.MetricsItem{Node: item.Node, Container: item.Container}
	}

	record := item.Record
	return protocol.MetricsItem{Sample: &protocol.MetricsSampleRecord{
		Sequence:         record.Sequence,
		ObservedAt:       record.ObservedAt,
		IntervalMS:       record.IntervalMS,
		ObservationScope: record.ObservationScope,
		Node:             record.Node,
		Containers:       append([]protocol.ContainerMetrics{}, record.Containers...),
		CollectionIssues: record.Issues,
	}}
}

func itemStart(item metricstore.Item) time.Time {
	if item.Record != nil {
		return item.Record.ObservedAt
	}

	return item.Node.Start
}
