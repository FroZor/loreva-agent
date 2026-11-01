package session

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/metricstore"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	metricsWriteTimeout = 10 * time.Second
	// keyframeInterval is how often a tick carries every value, so a
	// reader that missed a change converges.
	keyframeInterval = 30 * time.Second
	// maxEventPushes bounds the events sent with one tick.
	maxEventPushes = 64
	maxSeriesKey   = 512
	maxEventsRange = 8 * 24 * time.Hour
)

// MetricsSource is the agent's metrics store.
type MetricsSource interface {
	StreamID() string
	Latest() *metricstore.Sample
	History(name string, keys []string, since *time.Time, now time.Time) (protocol.MetricsHistoryResult, error)
	Events(from, to time.Time, limit int) ([]protocol.MetricEvent, bool)
	EventsRevision() uint64
	EventsChanged(revision uint64) ([]protocol.MetricEvent, uint64)
	SetDemand(reader string, demand metrics.Demand)
}

var watchReaders atomic.Uint64

// metricWatch sends one session what its reader shows: overview ticks,
// detail readings and events, every interval while the lease lasts.
type metricWatch struct {
	source MetricsSource
	// reader names this session's demand in the store.
	reader   string
	views    []protocol.MetricsView
	interval time.Duration
	lease    time.Duration
	tick     *time.Timer
	leaseEnd *time.Timer
	active   bool

	// Overview columns of this watch. Indices only grow.
	index      map[string]int
	columns    map[int]protocol.MetricColumn
	sent       map[int]float64
	next       int
	version    uint64
	keyframeAt time.Time
	sequence   uint64
	revision   uint64
}

func newMetricWatch(source MetricsSource, reader string) *metricWatch {
	return &metricWatch{
		source:   source,
		reader:   reader + "#" + strconv.FormatUint(watchReaders.Add(1), 10),
		tick:     newStoppedTimer(),
		leaseEnd: newStoppedTimer(),
	}
}

// stop ends the watch and the timers.
func (w *metricWatch) stop() {
	w.end()
	w.tick.Stop()
	w.leaseEnd.Stop()
}

// end stops sending and tells the collector this reader is gone.
func (w *metricWatch) end() {
	w.active = false
	w.views = nil
	stopTimer(w.tick)
	stopTimer(w.leaseEnd)
	if w.source != nil {
		w.source.SetDemand(w.reader, metrics.Demand{})
	}
}

// validateWatch checks a request and fills defaults.
func validateWatch(request *protocol.MetricsWatch) bool {
	if !agentcrypto.ValidUUID(request.RequestID) || request.Views == nil || len(request.Views) > protocol.MaxMetricsViews {
		return false
	}
	if request.IntervalMS == 0 {
		request.IntervalMS = protocol.MetricsIntervalDefaultMS
	}
	if request.LeaseS == 0 {
		request.LeaseS = protocol.MetricsLeaseDefaultS
	}
	if request.IntervalMS < protocol.MetricsIntervalMinMS || request.IntervalMS > protocol.MetricsIntervalMaxMS ||
		request.LeaseS < protocol.MetricsLeaseMinS || request.LeaseS > protocol.MetricsLeaseMaxS {
		return false
	}

	for index := range request.Views {
		view := &request.Views[index]
		switch view.Scope {
		case protocol.MetricsScopeOverview, protocol.MetricsScopeNode:
			if view.ContainerID != "" || view.Limit != 0 {
				return false
			}
		case protocol.MetricsScopeContainer:
			if view.ContainerID == "" || len(view.ContainerID) > 128 || view.Limit != 0 {
				return false
			}
		case protocol.MetricsScopeProcesses:
			if view.ContainerID != "" || view.Limit < 0 || view.Limit > protocol.MaxMetricsProcesses {
				return false
			}
			if view.Limit == 0 {
				view.Limit = protocol.DefaultMetricsProcesses
			}
		default:
			return false
		}
	}

	return true
}

// apply starts or renews the watch. A renewal with the same views keeps
// the columns, so the reader gets no new full schema.
func (w *metricWatch) apply(request protocol.MetricsWatch) {
	if len(request.Views) == 0 {
		w.end()
		return
	}

	if !w.active || !slices.Equal(w.views, request.Views) {
		w.index = make(map[string]int)
		w.columns = make(map[int]protocol.MetricColumn)
		w.sent = make(map[int]float64)
		w.next = 0
		w.version = 0
		w.sequence = 0
	}
	if !w.active {
		w.revision = w.source.EventsRevision()
	}

	w.active = true
	w.views = slices.Clone(request.Views)
	w.interval = time.Duration(request.IntervalMS) * time.Millisecond
	w.lease = time.Duration(request.LeaseS) * time.Second

	var demand metrics.Demand
	for _, view := range w.views {
		switch view.Scope {
		case protocol.MetricsScopeOverview, protocol.MetricsScopeContainer:
			demand.Containers = true
		case protocol.MetricsScopeNode:
			demand.Detail = true
		case protocol.MetricsScopeProcesses:
			demand.Processes = max(demand.Processes, view.Limit)
		}
	}
	w.source.SetDemand(w.reader, demand)

	stopTimer(w.leaseEnd)
	w.leaseEnd.Reset(w.lease)
}

// send writes what the views show for the newest sample, and the events
// that changed, then arms the next tick.
func (w *metricWatch) send(ctx context.Context, conn *websocket.Conn) error {
	if !w.active {
		return nil
	}
	defer func() {
		stopTimer(w.tick)
		w.tick.Reset(w.interval)
	}()

	if sample := w.source.Latest(); sample != nil && sample.Sequence != w.sequence {
		w.sequence = sample.Sequence
		for _, view := range w.views {
			if err := w.sendView(ctx, conn, view, sample); err != nil {
				return err
			}
		}
	}

	events, revision := w.source.EventsChanged(w.revision)
	w.revision = revision
	for _, event := range events[max(len(events)-maxEventPushes, 0):] {
		if err := writeMetricsFrame(ctx, conn, protocol.MetricsEventPush{Type: protocol.MetricsEventType, Event: event}); err != nil {
			return err
		}
	}

	return nil
}

func (w *metricWatch) sendView(ctx context.Context, conn *websocket.Conn, view protocol.MetricsView, sample *metricstore.Sample) error {
	snapshot := sample.Snapshot
	detail := protocol.MetricsDetail{
		Type:       protocol.MetricsDetailType,
		Scope:      view.Scope,
		Sequence:   sample.Sequence,
		ObservedAt: snapshot.ObservedAt,
	}

	switch view.Scope {
	case protocol.MetricsScopeOverview:
		return w.sendOverview(ctx, conn, sample)
	case protocol.MetricsScopeNode:
		node := snapshot.Node
		node.Processes.Items = []protocol.ProcessMetric{}
		detail.Node = &node
		detail.Issues = snapshot.CollectionIssues
	case protocol.MetricsScopeContainer:
		index := slices.IndexFunc(snapshot.Containers, func(c protocol.ContainerMetrics) bool { return c.ContainerID == view.ContainerID })
		if index < 0 {
			return nil
		}
		container := snapshot.Containers[index]
		detail.Container = &container
	case protocol.MetricsScopeProcesses:
		processes := snapshot.Node.Processes
		items := slices.Clone(processes.Items)
		sort.SliceStable(items, func(left, right int) bool { return items[left].CPUPercent > items[right].CPUPercent })
		if len(items) > view.Limit {
			items = items[:view.Limit]
			processes.Truncated = true
		}
		processes.Items = items
		detail.Processes = &processes
	}

	return writeMetricsFrame(ctx, conn, detail)
}

// sendOverview writes the schema changes and then a keyframe or the
// values that changed.
func (w *metricWatch) sendOverview(ctx context.Context, conn *websocket.Conn, sample *metricstore.Sample) error {
	series := metricstore.KeySeries(sample.Snapshot)
	full := w.version == 0
	schema := protocol.MetricsSchema{
		Type:     protocol.MetricsSchemaType,
		StreamID: w.source.StreamID(),
		Full:     full,
		Columns:  []protocol.MetricColumn{},
	}

	present := make(map[string]struct{}, len(series))
	for _, item := range series {
		key := item.Column.Key
		present[key] = struct{}{}
		index, known := w.index[key]
		if !known {
			index = w.next
			w.next++
			w.index[key] = index
		}
		column := item.Column
		column.Index = index
		if !known || !sameColumn(w.columns[index], column) {
			w.columns[index] = column
			schema.Columns = append(schema.Columns, column)
		}
	}
	for key, index := range w.index {
		if _, still := present[key]; !still {
			schema.Removed = append(schema.Removed, index)
			delete(w.index, key)
			delete(w.columns, index)
			delete(w.sent, index)
		}
	}
	sort.Ints(schema.Removed)

	if full || len(schema.Columns) > 0 || len(schema.Removed) > 0 {
		w.version++
		schema.Version = w.version
		if err := writeMetricsFrame(ctx, conn, schema); err != nil {
			return err
		}
	}

	tick := protocol.MetricsTick{
		Type:       protocol.MetricsTickType,
		Version:    w.version,
		Sequence:   sample.Sequence,
		ObservedAt: sample.Snapshot.ObservedAt,
	}
	now := time.Now()
	keyframe := full || now.Sub(w.keyframeAt) >= keyframeInterval
	if keyframe {
		w.keyframeAt = now
		tick.Values = make([]*float64, w.next)
	} else {
		tick.Changes = make(map[string]*float64)
	}
	for _, item := range series {
		index := w.index[item.Column.Key]
		value := metricstore.Round(item.Value)
		if keyframe {
			tick.Values[index] = value
		} else if previous, sent := w.sent[index]; value != nil && (!sent || previous != *value) {
			tick.Changes[strconv.Itoa(index)] = value
		}
		if value != nil {
			w.sent[index] = *value
		}
	}
	if !keyframe && len(tick.Changes) == 0 {
		return nil
	}

	return writeMetricsFrame(ctx, conn, tick)
}

func sameColumn(left, right protocol.MetricColumn) bool {
	return left.Key == right.Key && left.Unit == right.Unit && left.Name == right.Name &&
		left.ContainerID == right.ContainerID && equalPointer(left.TotalBytes, right.TotalBytes) &&
		equalPointer(left.LimitCores, right.LimitCores)
}

func equalPointer[T comparable](left, right *T) bool {
	if left == nil || right == nil {
		return left == right
	}

	return *left == *right
}

func writeMetricsFrame(ctx context.Context, conn *websocket.Conn, frame any) error {
	writeCtx, cancel := context.WithTimeout(ctx, metricsWriteTimeout)
	defer cancel()

	if err := wsframe.WriteJSON(writeCtx, conn, frame); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}

	return nil
}

// watchMetrics starts, renews, changes or stops the session's watch, and
// sends the current values right away.
func (x *exchange) watchMetrics(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.MetricsWatch
	if err := protocol.DecodeStrict(data, &request); err != nil || !validateWatch(&request) {
		return reject(ctx, request.RequestID, "invalid_message", fmt.Sprintf(
			"metrics.watch needs a UUID request_id, up to %d views, interval_ms of %d to %d and lease_s of %d to %d",
			protocol.MaxMetricsViews, protocol.MetricsIntervalMinMS, protocol.MetricsIntervalMaxMS,
			protocol.MetricsLeaseMinS, protocol.MetricsLeaseMaxS))
	}
	if x.collectors.Metrics == nil {
		return reject(ctx, request.RequestID, "metrics_unavailable", "this node keeps no metrics")
	}

	x.metrics.apply(request)
	if err := writeMetricsFrame(ctx, conn, protocol.MetricsWatchAccepted{
		Type:       protocol.MetricsWatchAcceptedType,
		RequestID:  request.RequestID,
		StreamID:   x.collectors.Metrics.StreamID(),
		IntervalMS: request.IntervalMS,
		LeaseS:     request.LeaseS,
		Views:      x.metrics.viewsOrEmpty(),
	}); err != nil {
		return err
	}

	return x.metrics.send(ctx, conn)
}

func (w *metricWatch) viewsOrEmpty() []protocol.MetricsView {
	if w.views == nil {
		return []protocol.MetricsView{}
	}

	return w.views
}

func (x *exchange) answerMetricsHistory(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.MetricsHistory
	valid := protocol.DecodeStrict(data, &request) == nil && agentcrypto.ValidUUID(request.RequestID) &&
		len(request.Series) > 0 && len(request.Series) <= protocol.MaxHistorySeries
	for _, key := range request.Series {
		valid = valid && key != "" && len(key) <= maxSeriesKey
	}
	if !valid {
		return reject(ctx, request.RequestID, "invalid_message",
			fmt.Sprintf("metrics.history needs a UUID request_id, a range, and 1 to %d series", protocol.MaxHistorySeries))
	}
	if x.collectors.Metrics == nil {
		return reject(ctx, request.RequestID, "metrics_unavailable", "this node keeps no metrics")
	}

	result, err := x.collectors.Metrics.History(request.Range, request.Series, request.Since, time.Now())
	if err != nil {
		return reject(ctx, request.RequestID, "invalid_range", "range must be one of 5m, 1h, 6h, 24h, 7d")
	}
	result.RequestID = request.RequestID

	return x.writeAnswer(ctx, conn, request.RequestID, result, reject)
}

func (x *exchange) answerMetricsEvents(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.MetricsEvents
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) ||
		request.Limit < 0 || request.Limit > protocol.MaxEventsLimit {
		return reject(ctx, request.RequestID, "invalid_message",
			fmt.Sprintf("metrics.events needs a UUID request_id, from, to, and a limit of at most %d", protocol.MaxEventsLimit))
	}
	if request.To.Before(request.From) || request.To.Sub(request.From) > maxEventsRange {
		return reject(ctx, request.RequestID, "invalid_range", "to must not be before from, and the range must be at most 8 days")
	}
	if x.collectors.Metrics == nil {
		return reject(ctx, request.RequestID, "metrics_unavailable", "this node keeps no metrics")
	}

	limit := request.Limit
	if limit == 0 {
		limit = protocol.DefaultEventsLimit
	}
	events, more := x.collectors.Metrics.Events(request.From, request.To, limit)

	return x.writeAnswer(ctx, conn, request.RequestID, protocol.MetricsEventsResult{
		Type:      protocol.MetricsEventsResultType,
		RequestID: request.RequestID,
		Events:    events,
		More:      more,
	}, reject)
}
