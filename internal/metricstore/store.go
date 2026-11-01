// Package metricstore keeps the node's metric history in rings of fixed
// size, like RRD: every key series has one average and one maximum per
// bucket in each ring, so the store never grows with time or load. The
// rings match what a reader shows: 5 minutes at 1 second, an hour at 10
// seconds, a day at a minute, and a week at 30 minutes. A short spike stays
// visible at every range as the maximum of its bucket, and notable changes
// are kept in a journal of events.
//
// Only key series are stored (see KeySeries); per-CPU, process, sensor and
// error details are shown live and not kept.
package metricstore

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	// containerSettle is how long a container lives before it gets history
	// columns, so short-lived containers do not fill the store.
	containerSettle = 10 * time.Second
	// maxContainerColumns bounds the container series; the container
	// that was seen longest ago gives its columns up first.
	maxContainerColumns = 512 * containerSeries
	containerSeries     = 6
	// columnRetention is how long a series that stopped reporting keeps
	// its column: as long as the longest ring holds its data.
	columnRetention = 7*24*time.Hour + 30*time.Minute
	initialCapacity = 64
)

var errUnknownRange = errors.New("unknown metrics range")

// column is one key series in the rings. A free column has no key.
type column struct {
	Key string `json:"key"`
	// Since is when the column started to belong to this series, in Unix
	// seconds; older data in its slots belongs to a previous series.
	Since     int64 `json:"since"`
	LastSeen  int64 `json:"last_seen"`
	Container bool  `json:"container,omitempty"`
}

// Sample is the newest collected sample.
type Sample struct {
	Sequence uint64
	Snapshot *metrics.Snapshot
}

// Store is safe for concurrent use.
type Store struct {
	dir string
	// maintain serialises Maintain, which writes files outside mu.
	maintain sync.Mutex
	warnings []error

	mu       sync.Mutex
	streamID string
	columns  []column
	index    map[string]int
	tiers    []*tier
	// waiting holds containers seen for less than containerSettle, with
	// the time they were first seen.
	waiting      map[string]int64
	columnsDirty bool
	latest       *Sample
	sequence     uint64
	detector     *detector
	journal      journal
	demand       map[string]metrics.Demand
	changed      chan struct{}
}

func newStore(dir, streamID string) *Store {
	store := &Store{
		dir:      dir,
		streamID: streamID,
		index:    make(map[string]int),
		waiting:  make(map[string]int64),
		detector: newDetector(),
		demand:   make(map[string]metrics.Demand),
		changed:  make(chan struct{}),
	}
	for _, spec := range tierSpecs {
		store.tiers = append(store.tiers, newTier(spec, initialCapacity))
	}

	return store
}

// StreamID identifies this store across restarts.
func (s *Store) StreamID() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.streamID
}

// Append stores a sample's key series, runs the event rules on it, and
// wakes readers.
func (s *Store) Append(snapshot metrics.Snapshot) error {
	at := snapshot.ObservedAt.Unix()
	series, signals := keySeries(&snapshot)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sequence++
	s.latest = &Sample{Sequence: s.sequence, Snapshot: &snapshot}

	present := make(map[string]struct{}, len(series))
	values := make([]columnValue, 0, len(series))
	for _, item := range series {
		if item.container && !snapshot.ContainersFresh {
			continue
		}
		present[item.Column.Key] = struct{}{}
		if math.IsNaN(item.Value) || math.IsInf(item.Value, 0) {
			continue
		}
		index, ok := s.columnFor(item.Column.Key, item.container, at, snapshot.ObservedAt)
		if !ok {
			continue
		}
		s.columns[index].LastSeen = at
		values = append(values, columnValue{column: index, value: item.Value})
	}
	if snapshot.ContainersFresh {
		for key := range s.waiting {
			if _, seen := present[key]; !seen {
				delete(s.waiting, key)
			}
		}
	}
	for _, t := range s.tiers {
		t.add(at, values)
	}

	s.detector.observe(snapshot.ObservedAt, series, signals, &s.journal)
	for _, event := range snapshot.ContainerEvents {
		if converted, ok := containerEvent(event); ok {
			s.journal.instant(converted)
		}
	}

	close(s.changed)
	s.changed = make(chan struct{})

	return nil
}

// columnFor returns the column of a series, giving it one when it has none.
// A container series waits containerSettle first.
func (s *Store) columnFor(key string, container bool, at int64, now time.Time) (int, bool) {
	if index, ok := s.index[key]; ok {
		return index, true
	}

	if container {
		first, waiting := s.waiting[key]
		if !waiting {
			s.waiting[key] = at
			return 0, false
		}
		if at-first < int64(containerSettle/time.Second) {
			return 0, false
		}
		delete(s.waiting, key)

		if s.containerColumns() >= maxContainerColumns {
			s.evictContainer(now)
		}
	}

	index := -1
	for candidate, existing := range s.columns {
		if existing.Key == "" {
			index = candidate
			break
		}
	}
	if index < 0 {
		index = len(s.columns)
		s.columns = append(s.columns, column{})
		if len(s.columns) > s.tiers[0].capacity {
			capacity := max(s.tiers[0].capacity*2, initialCapacity)
			for _, t := range s.tiers {
				t.resize(capacity)
			}
		}
	}

	for _, t := range s.tiers {
		t.clearColumn(index)
	}
	s.columns[index] = column{Key: key, Since: at, LastSeen: at, Container: container}
	s.index[key] = index
	s.columnsDirty = true

	return index, true
}

func (s *Store) containerColumns() int {
	count := 0
	for _, existing := range s.columns {
		if existing.Container {
			count++
		}
	}

	return count
}

// evictContainer frees the columns of the container seen longest ago and
// records that its history was dropped.
func (s *Store) evictContainer(now time.Time) {
	oldest := -1
	for index, existing := range s.columns {
		if existing.Container && (oldest < 0 || existing.LastSeen < s.columns[oldest].LastSeen) {
			oldest = index
		}
	}
	if oldest < 0 {
		return
	}

	_, subject := SplitKey(s.columns[oldest].Key)
	for index, existing := range s.columns {
		if _, other := SplitKey(existing.Key); existing.Container && other == subject {
			s.freeColumn(index)
		}
	}
	s.journal.instant(protocol.MetricEvent{Kind: EventHistoryEvicted, Subject: subject, Start: now})
}

func (s *Store) freeColumn(index int) {
	delete(s.index, s.columns[index].Key)
	s.columns[index] = column{}
	s.columnsDirty = true
}

// expireColumns frees the columns of series that stopped reporting longer
// ago than the longest ring holds.
func (s *Store) expireColumns(now time.Time) {
	cut := now.Add(-columnRetention).Unix()
	for index, existing := range s.columns {
		if existing.Key != "" && existing.LastSeen < cut {
			s.freeColumn(index)
		}
	}
}

// Changed returns a channel that closes on the next Append.
func (s *Store) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.changed
}

// Latest returns the newest sample, or nil before the first one.
func (s *Store) Latest() *Sample {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.latest
}

// rangeSpec maps a reader's range to a ring and to how many of its buckets
// form one point.
type rangeSpec struct {
	tier   int
	factor int64
	points int64
}

var ranges = map[string]rangeSpec{
	protocol.MetricsRange5m:  {tier: tierLive, factor: 1, points: 300},
	protocol.MetricsRange1h:  {tier: tier10s, factor: 1, points: 360},
	protocol.MetricsRange6h:  {tier: tier1m, factor: 1, points: 360},
	protocol.MetricsRange24h: {tier: tier1m, factor: 5, points: 288},
	protocol.MetricsRange7d:  {tier: tier30m, factor: 1, points: 336},
}

// History returns the points of the given series over a range, ending
// with the bucket that is still filling. Keys the store does not know are
// listed in Unknown.
func (s *Store) History(name string, keys []string, since *time.Time, now time.Time) (protocol.MetricsHistoryResult, error) {
	spec, ok := ranges[name]
	if !ok {
		return protocol.MetricsHistoryResult{}, errUnknownRange
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	t := s.tiers[spec.tier]
	step := t.stepS * spec.factor
	end := t.latestBucket()
	if end == 0 {
		end = now.Unix()
	}
	end -= mod(end, step)
	start := end - (spec.points-1)*step
	if since != nil {
		from := since.Unix() - mod(since.Unix(), step)
		start = max(start, from)
	}
	points := int64(0)
	if start <= end {
		points = (end-start)/step + 1
	}

	result := protocol.MetricsHistoryResult{
		Type:     protocol.MetricsHistoryResultType,
		StreamID: s.streamID,
		Range:    name,
		StepS:    int(step),
		Start:    time.Unix(start, 0).UTC(),
		Points:   int(points),
		Series:   []protocol.MetricHistorySeries{},
	}
	for _, key := range keys {
		index, known := s.index[key]
		if !known {
			result.Unknown = append(result.Unknown, key)
			continue
		}

		series := protocol.MetricHistorySeries{
			Key: key,
			Avg: make([]*float64, points),
			Max: make([]*float64, points),
		}
		since := s.columns[index].Since
		for point := range points {
			bucket := start + point*step
			sum, peak, count := 0.0, math.Inf(-1), 0
			for sub := range spec.factor {
				avg, high, present := t.point(bucket+sub*t.stepS, index, since)
				if !present {
					continue
				}
				sum += avg
				peak = math.Max(peak, high)
				count++
			}
			if count > 0 {
				series.Avg[point] = round(sum / float64(count))
				series.Max[point] = round(peak)
			}
		}
		result.Series = append(result.Series, series)
	}

	return result, nil
}

// Events returns up to limit events that overlap [from, to], oldest first,
// and whether more remain.
func (s *Store) Events(from, to time.Time, limit int) ([]protocol.MetricEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.journal.overlapping(from, to, limit)
}

// EventsRevision is the revision of the newest event change, for a reader
// that starts watching.
func (s *Store) EventsRevision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.journal.revision
}

// EventsChanged returns the events that began, changed or ended after
// revision, and the revision to pass next time.
func (s *Store) EventsChanged(revision uint64) ([]protocol.MetricEvent, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.journal.changedAfter(revision)
}

// SetDemand records what a reader watches; a zero Demand removes it.
func (s *Store) SetDemand(reader string, demand metrics.Demand) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if demand == (metrics.Demand{}) {
		delete(s.demand, reader)
		return
	}
	s.demand[reader] = demand
}

// Demand combines what all readers watch.
func (s *Store) Demand() metrics.Demand {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result metrics.Demand
	for _, demand := range s.demand {
		result.Processes = max(result.Processes, demand.Processes)
		result.Containers = result.Containers || demand.Containers
		result.Detail = result.Detail || demand.Detail
	}

	return result
}

// Columns returns the keys of the stored series, sorted.
func (s *Store) Columns() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := make([]string, 0, len(s.index))
	for key := range s.index {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// Collect samples once per interval into the store until ctx is cancelled.
// The agent stores every sample whether or not any reader is connected;
// what readers watch decides which costly parts are read.
func (s *Store) Collect(
	ctx context.Context,
	collect func(context.Context, metrics.Demand) (metrics.Snapshot, error),
	interval, timeout time.Duration,
	onError func(error),
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		collectCtx, cancel := context.WithTimeout(ctx, timeout)
		snapshot, err := collect(collectCtx, s.Demand())
		cancel()

		if err == nil {
			err = s.Append(snapshot)
		}
		if err != nil && onError != nil {
			onError(err)
		}
	}
}

// round keeps three significant digits, or one decimal for values below
// 100, which is as precise as a chart can show and keeps frames small.
func round(value float64) *float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil
	}

	abs := math.Abs(value)
	var result float64
	if abs < 100 {
		result = math.Round(value*10) / 10
	} else {
		scale := math.Pow(10, math.Floor(math.Log10(abs))-2)
		result = math.Round(value/scale) * scale
	}

	return &result
}

// Round is the rounding of tick and history values.
func Round(value float64) *float64 { return round(value) }
