package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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
	// maxRollupSeries is the most series one rollup point carries; the
	// contract allows 4096.
	maxRollupSeries = 4096
	// frameEnvelope is room for the fields of a frame around its points.
	frameEnvelope = 1024
	// recentAnswers is how many answered request IDs a reporter remembers,
	// so a second answer to a resent frame is ignored.
	recentAnswers = 4 * protocol.MaxMetricsWindow
)

// MetricsSource is the agent's metrics store. Every session is a reader with
// its own cursor, so a reader that was offline catches up where it stopped.
type MetricsSource interface {
	StreamID() string
	After(after uint64, limit int) []metricstore.Item
	Range(from, to time.Time, limit int) []metricstore.Item
	Latest() *metricstore.Record
	Changed() <-chan struct{}
	Cursor(reader string) uint64
	SetCursor(reader string, sequence uint64)
	RemoveCursor(reader string)
}

type metricFrame struct {
	requestID  string
	metricType string
	payload    []byte
	// commit is the cursor to store once this frame is acknowledged; zero
	// while more frames of the same batch follow.
	commit       uint64
	acknowledged bool
}

// metricReporter delivers stored metrics to one reader. A batch of samples
// becomes a node frame and a container frame; the cursor moves when both are
// acknowledged. Up to window frames await acknowledgement at once; the
// reader sets the window and live delivery with metrics.subscribe.
type metricReporter struct {
	source MetricsSource
	reader string
	cursor uint64
	wake   <-chan struct{}
	window int
	live   bool

	// encoded is the newest sequence placed in a frame, sent or pending.
	encoded uint64
	// liveSent is the sequence of the last metrics.live sample.
	liveSent uint64
	pending  []metricFrame
	// inflight holds written frames in order until every frame before
	// them is acknowledged.
	inflight []*metricFrame
	// retrying holds new frames back until the unacknowledged ones are
	// sent again.
	retrying     bool
	retryAttempt int
	// answered holds the request IDs of recently accepted or skipped frames.
	answered []string
}

type metricRejection struct {
	requestID string
	code      string
	message   string
}

var errDuplicateMetricsAcknowledgement = errors.New("duplicate metrics acknowledgement")

func (rejection *metricRejection) Error() string {
	if rejection.message == "" {
		return "peer rejected metrics: " + rejection.code
	}

	return "peer rejected metrics: " + rejection.code + ": " + rejection.message
}

func newMetricReporter(source MetricsSource, reader string) *metricReporter {
	reporter := &metricReporter{source: source, reader: reader, window: 1}
	if source != nil {
		reporter.cursor = source.Cursor(reader)
		reporter.encoded = reporter.cursor
		reporter.wake = source.Changed()
	}

	return reporter
}

// woke re-arms the wake channel after it fired.
func (reporter *metricReporter) woke() {
	reporter.wake = reporter.source.Changed()
}

// subscribe applies a reader's delivery settings.
func (reporter *metricReporter) subscribe(live bool, window int) {
	reporter.live = live
	reporter.window = window
}

// awaiting reports whether a written frame waits for its acknowledgement.
func (reporter *metricReporter) awaiting() bool {
	return slices.ContainsFunc(reporter.inflight, func(frame *metricFrame) bool { return !frame.acknowledged })
}

// writeNext fills the window with the next frames. It reports whether it
// wrote any.
func (reporter *metricReporter) writeNext(ctx context.Context, conn *websocket.Conn) (bool, error) {
	if reporter.source == nil || reporter.retrying {
		return false, nil
	}

	sent := false
	for len(reporter.inflight) < reporter.window {
		if len(reporter.pending) == 0 {
			frames, err := reporter.nextBatch()
			if err != nil {
				return sent, err
			}
			reporter.pending = frames
		}
		if len(reporter.pending) == 0 {
			break
		}

		next := reporter.pending[0]
		reporter.pending = reporter.pending[1:]
		reporter.inflight = append(reporter.inflight, &next)

		if err := writeMetricFrame(ctx, conn, next.payload); err != nil {
			return sent, err
		}
		sent = true
	}

	return sent, nil
}

// resend writes every unacknowledged frame again, with the same request ID,
// and lets new frames follow.
func (reporter *metricReporter) resend(ctx context.Context, conn *websocket.Conn) error {
	reporter.retrying = false

	for _, frame := range reporter.inflight {
		if frame.acknowledged {
			continue
		}
		if err := writeMetricFrame(ctx, conn, frame.payload); err != nil {
			return err
		}
	}

	return nil
}

// writeLive sends the newest sample as metrics.live while stored history
// has not reached it yet. Once history is caught up the regular frames
// carry new samples, so live frames stop.
func (reporter *metricReporter) writeLive(ctx context.Context, conn *websocket.Conn) error {
	if !reporter.live || reporter.source == nil {
		return nil
	}

	// The sample right after the last encoded one goes out as history next,
	// so live frames start only when history is further behind.
	record := reporter.source.Latest()
	if record == nil || record.Sequence <= reporter.encoded+1 || record.Sequence <= reporter.liveSent {
		return nil
	}

	for _, metricType := range []string{protocol.MetricTypeNode, protocol.MetricTypeContainer} {
		frame := &protocol.MetricsLive{
			Type:          protocol.MetricsLiveType,
			SchemaVersion: protocol.MetricsSchemaVersion,
			StreamID:      reporter.source.StreamID(),
			Metric:        sampleSeries(metricType, []metricstore.Item{{Record: record}}),
		}

		payload, err := encodeSampleFrame(frame, &frame.Metric)
		if err != nil {
			return err
		}
		if err := writeMetricFrame(ctx, conn, payload); err != nil {
			return err
		}
	}
	reporter.liveSent = record.Sequence

	return nil
}

// nextBatch encodes the next run of items of one kind as frames, halving the
// batch until every frame fits the size limit.
func (reporter *metricReporter) nextBatch() ([]metricFrame, error) {
	items := reporter.source.After(reporter.encoded, maxMetricBatch)
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
		if err == nil {
			reporter.encoded = items[len(items)-1].LastSequence()
			return frames, nil
		}
		if len(items) == 1 || !errors.Is(err, errMetricsFrameTooLarge) {
			return nil, err
		}

		items = items[:len(items)/2]
	}
}

var errMetricsFrameTooLarge = errors.New("metrics frame is too large")

func (reporter *metricReporter) encodeBatch(items []metricstore.Item, rollup bool) ([]metricFrame, error) {
	streamID := reporter.source.StreamID()

	var frames []metricFrame
	for _, metricType := range []string{protocol.MetricTypeNode, protocol.MetricTypeContainer} {
		typed, err := encodeType(streamID, metricType, items, rollup)
		if err != nil {
			return nil, err
		}
		frames = append(frames, typed...)
	}
	frames[len(frames)-1].commit = items[len(items)-1].LastSequence()

	return frames, nil
}

// encodeType encodes the frames of one metric type. A single compacted
// window too large for one frame, for example on a node with many
// containers, is sent as several points that each carry part of its series.
func encodeType(streamID, metricType string, items []metricstore.Item, rollup bool) ([]metricFrame, error) {
	if !rollup {
		requestID, err := agentcrypto.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("create metrics request ID: %w", err)
		}

		frame := &protocol.MetricsReport{
			Type:          protocol.MetricsReportType,
			SchemaVersion: protocol.MetricsSchemaVersion,
			RequestID:     requestID,
			StreamID:      streamID,
			Metric:        sampleSeries(metricType, items),
		}
		payload, err := encodeSampleFrame(frame, &frame.Metric)
		if err != nil {
			return nil, err
		}

		return []metricFrame{{requestID: requestID, metricType: metricType, payload: payload}}, nil
	}

	points := rollupPoints(metricType, items)
	batches := [][]protocol.MetricRollup{points}
	if len(points) == 1 {
		batches = nil
		for _, part := range splitRollup(points[0], maxMetricsReportSize-frameEnvelope) {
			batches = append(batches, []protocol.MetricRollup{part})
		}
	}

	var frames []metricFrame
	for _, batch := range batches {
		requestID, err := agentcrypto.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("create metrics request ID: %w", err)
		}
		payload, err := json.Marshal(rollupFrame(requestID, streamID, metricType, batch))
		if err != nil {
			return nil, fmt.Errorf("encode metrics frame: %w", err)
		}
		if len(payload) > maxMetricsReportSize || slices.ContainsFunc(batch, func(point protocol.MetricRollup) bool {
			return len(point.Series) > maxRollupSeries
		}) {
			return nil, errMetricsFrameTooLarge
		}

		frames = append(frames, metricFrame{requestID: requestID, metricType: metricType, payload: payload})
	}

	return frames, nil
}

// sampleSeries puts the node or the container part of full samples into one
// series.
func sampleSeries(metricType string, items []metricstore.Item) protocol.MetricSeries {
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
			node := wireNode(record.Node)
			sample.Node = &node
			sample.CollectionIssues = nodeIssues
		} else {
			sample.Containers = &protocol.ContainerMetricSet{Items: append([]protocol.ContainerMetrics{}, record.Containers...)}
			sample.CollectionIssues = containerIssues
		}
		samples = append(samples, sample)
	}

	return protocol.MetricSeries{Type: metricType, Samples: samples}
}

// rollupPoints returns the node or the container rollups of compacted items.
func rollupPoints(metricType string, items []metricstore.Item) []protocol.MetricRollup {
	points := make([]protocol.MetricRollup, 0, len(items))
	for _, item := range items {
		if metricType == protocol.MetricTypeNode {
			points = append(points, *item.Node)
		} else {
			points = append(points, *item.Container)
		}
	}

	return points
}

func rollupFrame(requestID, streamID, metricType string, points []protocol.MetricRollup) *protocol.MetricsRollupReport {
	return &protocol.MetricsRollupReport{
		Type:          protocol.MetricsRollupType,
		SchemaVersion: protocol.MetricsSchemaVersion,
		RequestID:     requestID,
		StreamID:      streamID,
		Metric:        protocol.MetricRollupSeries{Type: metricType, Points: points},
	}
}

// splitRollup divides the series of one window into points of at most
// budget encoded bytes and maxRollupSeries series. Every part keeps the
// window's sequences and times, so a reader merges them by first_sequence.
// A window that fits is returned as is.
func splitRollup(point protocol.MetricRollup, budget int) []protocol.MetricRollup {
	empty := point
	empty.Series = map[string]protocol.MetricAggregate{}
	header, err := json.Marshal(empty)
	if err != nil {
		return []protocol.MetricRollup{point}
	}

	var parts []protocol.MetricRollup
	current := empty
	size := len(header)
	for _, key := range slices.Sorted(maps.Keys(point.Series)) {
		entry, err := json.Marshal(map[string]protocol.MetricAggregate{key: point.Series[key]})
		if err != nil {
			continue
		}

		if len(current.Series) > 0 && (size+len(entry) > budget || len(current.Series) == maxRollupSeries) {
			parts = append(parts, current)
			current = empty
			current.Series = map[string]protocol.MetricAggregate{}
			size = len(header)
		}
		current.Series[key] = point.Series[key]
		size += len(entry)
	}

	return append(parts, current)
}

// encodeSampleFrame marshals a frame of samples. A frame of one oversized
// sample has its optional lists trimmed until it fits; a larger frame is
// reported as too large, so the caller splits the batch.
func encodeSampleFrame(frame any, series *protocol.MetricSeries) ([]byte, error) {
	for {
		payload, err := json.Marshal(frame)
		if err != nil {
			return nil, fmt.Errorf("encode metrics frame: %w", err)
		}
		if len(payload) <= maxMetricsReportSize {
			return payload, nil
		}
		if len(series.Samples) != 1 {
			return nil, errMetricsFrameTooLarge
		}

		sample := &series.Samples[0]
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
			return nil, fmt.Errorf("metrics frame exceeds %d bytes without optional entries", maxMetricsReportSize)
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

func writeMetricFrame(ctx context.Context, conn *websocket.Conn, payload []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, metricsWriteTimeout)
	err := conn.Write(writeCtx, websocket.MessageText, payload)
	cancel()

	if err != nil {
		return fmt.Errorf("write metrics frame: %w", err)
	}

	return nil
}

// handleResponse applies metrics.accepted or metrics.rejected to the frame
// it names. A rejection is returned as *metricRejection.
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

		frame := reporter.frame(accepted.RequestID)
		if frame == nil || frame.acknowledged {
			if slices.Contains(reporter.answered, accepted.RequestID) {
				return errDuplicateMetricsAcknowledgement
			}

			return errors.New("invalid metrics acknowledgement")
		}

		reporter.retryAttempt = 0
		reporter.complete(frame)

		return nil
	}

	if messageType != protocol.MetricsRejectedType {
		return fmt.Errorf("unexpected metrics result type %q", messageType)
	}

	var rejected protocol.NodeReportRejected
	if err := protocol.DecodeStrict(data, &rejected); err != nil {
		return fmt.Errorf("decode metrics rejection: %w", err)
	}
	if rejected.Code == "" {
		return errors.New("invalid metrics rejection")
	}
	if frame := reporter.frame(rejected.RequestID); frame == nil || frame.acknowledged {
		// A resent frame can be answered twice; the first answer counts.
		if slices.Contains(reporter.answered, rejected.RequestID) {
			return errDuplicateMetricsAcknowledgement
		}

		return errors.New("invalid metrics rejection")
	}

	return &metricRejection{requestID: rejected.RequestID, code: rejected.Code, message: rejected.Message}
}

func (reporter *metricReporter) frame(requestID string) *metricFrame {
	for _, frame := range reporter.inflight {
		if frame.requestID == requestID {
			return frame
		}
	}

	return nil
}

// complete marks a frame answered and drops the answered frames at the head
// of the window, storing the reader's cursor at the end of each batch.
func (reporter *metricReporter) complete(frame *metricFrame) {
	frame.acknowledged = true
	if len(reporter.answered) == recentAnswers {
		reporter.answered = reporter.answered[1:]
	}
	reporter.answered = append(reporter.answered, frame.requestID)

	for len(reporter.inflight) > 0 && reporter.inflight[0].acknowledged {
		if commit := reporter.inflight[0].commit; commit > reporter.cursor {
			reporter.cursor = commit
			reporter.source.SetCursor(reporter.reader, commit)
		}
		reporter.inflight = reporter.inflight[1:]
	}
}

// scheduleRetry holds new frames back and returns the delay before the
// unacknowledged frames are sent again. It reports false when a retry is
// already scheduled, so a burst of rejections backs off only once.
func (reporter *metricReporter) scheduleRetry() (time.Duration, bool) {
	if reporter.retrying {
		return 0, false
	}

	reporter.retrying = true
	reporter.retryAttempt++

	return retryDelay(reporter.retryAttempt), true
}

// discard skips a frame the peer rejected for good, so one bad frame cannot
// stall the reader.
func (reporter *metricReporter) discard(requestID string) {
	if frame := reporter.frame(requestID); frame != nil {
		reporter.retryAttempt = 0
		reporter.complete(frame)
	}
}

// cancelRetry drops a scheduled retry once every written frame has been
// answered, so delivery does not wait out a backoff with nothing to resend.
func (reporter *metricReporter) cancelRetry() bool {
	if !reporter.retrying || reporter.awaiting() {
		return false
	}

	reporter.retrying = false

	return true
}

// frameType names the frame for rejection events.
func (reporter *metricReporter) frameType(requestID string) string {
	if frame := reporter.frame(requestID); frame != nil {
		return protocol.MetricsReportType + "/" + frame.metricType
	}
	for _, frame := range reporter.inflight {
		if !frame.acknowledged {
			return protocol.MetricsReportType + "/" + frame.metricType
		}
	}

	return protocol.MetricsReportType
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
		if size+len(data) > maxMetricsReportSize-frameEnvelope {
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
		Node:             wireNode(record.Node),
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

// wireNode returns node metrics as the contract requires them. The store
// drops process lists after five minutes and on disk, which leaves them nil;
// the contract sends an empty list instead.
func wireNode(node protocol.NodeMetrics) protocol.NodeMetrics {
	if node.Processes.Items == nil {
		node.Processes.Items = []protocol.ProcessMetric{}
	}

	return node
}
