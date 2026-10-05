// Package metricstore keeps the node's metrics on disk for every reader: the
// agent appends each sample, compacts old data itself, and readers (paired
// devices and the portal) each read from their own cursor. A reader that was
// offline catches up from where it stopped; nothing is removed because a
// reader has seen it, only because it grew old.
//
// Retention, as in monitoring systems such as Zabbix:
//   - the last hour: every sample;
//   - up to a day: one rollup per minute, except minutes with a spike, which
//     keep one rollup per 10 seconds; neighbouring minutes that differ only
//     by noise are merged;
//   - up to a week: one rollup per hour, with each series' min, average,
//     max, and the time of the max.
package metricstore

import (
	"compress/flate"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const (
	rawRetention     = time.Hour
	minuteRetention  = 24 * time.Hour
	hourRetention    = 7 * 24 * time.Hour
	processRetention = 5 * time.Minute
	// maxStoreBytes bounds the files on disk; the oldest data goes first.
	maxStoreBytes = 200 << 20
	maxFileBytes  = 64 << 20
	metaName      = "meta.json"
	fileSuffix    = ".seg"
	storeVersion  = 1
)

// Record is one collected sample.
type Record struct {
	Sequence         uint64                      `json:"sequence"`
	ObservedAt       time.Time                   `json:"observed_at"`
	IntervalMS       uint64                      `json:"interval_ms"`
	ObservationScope string                      `json:"observation_scope"`
	Node             protocol.NodeMetrics        `json:"node"`
	Containers       []protocol.ContainerMetrics `json:"containers"`
	Issues           []protocol.CollectionIssue  `json:"issues,omitempty"`
}

// Item is what a reader receives: a full sample or a compacted window with a
// rollup per metric type.
type Item struct {
	Record    *Record `json:"record,omitempty"`
	Node      *Rollup `json:"node,omitempty"`
	Container *Rollup `json:"container,omitempty"`
}

// FirstSequence is the lowest sample sequence the item covers.
func (item Item) FirstSequence() uint64 {
	if item.Record != nil {
		return item.Record.Sequence
	}

	return min(item.Node.FirstSequence, item.Container.FirstSequence)
}

// LastSequence is the highest sample sequence the item covers.
func (item Item) LastSequence() uint64 {
	if item.Record != nil {
		return item.Record.Sequence
	}

	return max(item.Node.LastSequence, item.Container.LastSequence)
}

func (item Item) start() time.Time {
	if item.Record != nil {
		return item.Record.ObservedAt
	}

	return item.Node.Start
}

func (item Item) end() time.Time {
	if item.Record != nil {
		return item.Record.ObservedAt
	}

	return item.Node.End
}

type meta struct {
	Version      int               `json:"version"`
	StreamID     string            `json:"stream_id"`
	NextSequence uint64            `json:"next_sequence"`
	Cursors      map[string]uint64 `json:"cursors"`
}

// Store is safe for concurrent use.
type Store struct {
	dir string
	// maintain serialises Maintain, which writes files outside mu.
	maintain sync.Mutex
	warnings []error

	mu      sync.Mutex
	meta    meta
	raw     []*Record
	minute  []Item
	hour    []Item
	changed chan struct{}
	// dirty marks tier files that need rewriting.
	dirtyMinute map[int64]struct{}
	dirtyHour   map[int64]struct{}
	pendingRaw  map[int64][]*Record
}

// Open loads or creates the store in dir.
func Open(dir string) (*Store, error) {
	for _, tier := range []string{"raw", "minute", "hour"} {
		if err := os.MkdirAll(filepath.Join(dir, tier), 0o700); err != nil {
			return nil, fmt.Errorf("create metrics store: %w", err)
		}
	}

	store := &Store{
		dir:         dir,
		changed:     make(chan struct{}),
		dirtyMinute: make(map[int64]struct{}),
		dirtyHour:   make(map[int64]struct{}),
		pendingRaw:  make(map[int64][]*Record),
	}
	if err := store.load(); err != nil {
		return nil, err
	}

	return store, nil
}

// StreamID identifies this store across restarts; sequences only grow
// within it.
func (s *Store) StreamID() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.meta.StreamID
}

// Append stores a sample and wakes readers.
func (s *Store) Append(snapshot metrics.Snapshot) error {
	interval := snapshot.Interval.Milliseconds()
	if interval < 1 {
		interval = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.meta.NextSequence++
	record := &Record{
		Sequence:         s.meta.NextSequence,
		ObservedAt:       snapshot.ObservedAt.UTC(),
		IntervalMS:       uint64(interval),
		ObservationScope: snapshot.ObservationScope,
		Node:             snapshot.Node,
		Containers:       slices.Clone(snapshot.Containers),
		Issues:           slices.Clone(snapshot.CollectionIssues),
	}
	s.raw = append(s.raw, record)

	minuteKey := record.ObservedAt.Truncate(time.Minute).Unix()
	s.pendingRaw[minuteKey] = append(s.pendingRaw[minuteKey], record)

	close(s.changed)
	s.changed = make(chan struct{})

	return nil
}

// Changed returns a channel that closes on the next Append.
func (s *Store) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.changed
}

// After returns up to limit items that cover sequences above after, oldest
// first.
func (s *Store) After(after uint64, limit int) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []Item
	collect := func(item Item) bool {
		if item.LastSequence() <= after {
			return true
		}
		result = append(result, item)

		return len(result) < limit
	}

	for _, item := range s.hour {
		if !collect(item) {
			return result
		}
	}
	for _, item := range s.minute {
		if !collect(item) {
			return result
		}
	}
	for _, record := range s.raw {
		if !collect(Item{Record: record}) {
			return result
		}
	}

	return result
}

// Range returns up to limit items that overlap [from, to], oldest first.
func (s *Store) Range(from, to time.Time, limit int) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []Item
	add := func(item Item) bool {
		if item.end().Before(from) || item.start().After(to) {
			return true
		}
		result = append(result, item)

		return len(result) < limit
	}

	for _, tier := range [][]Item{s.hour, s.minute} {
		for _, item := range tier {
			if !add(item) {
				return result
			}
		}
	}
	for _, record := range s.raw {
		if !add(Item{Record: record}) {
			return result
		}
	}

	return result
}

// Cursor returns the last sequence a reader acknowledged; zero means the
// reader has seen nothing and gets the whole store.
func (s *Store) Cursor(reader string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.meta.Cursors[reader]
}

// SetCursor records a reader's progress. It never moves a cursor back.
func (s *Store) SetCursor(reader string, sequence uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sequence > s.meta.Cursors[reader] {
		s.meta.Cursors[reader] = sequence
	}
}

// RemoveCursor forgets a reader, for example a revoked device.
func (s *Store) RemoveCursor(reader string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.meta.Cursors, reader)
}

// Run compacts and persists the store every interval until stop closes, and
// once more before it returns.
func (s *Store) Run(stop <-chan struct{}, interval time.Duration, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			if err := s.Maintain(time.Now(), true); err != nil && onError != nil {
				onError(err)
			}
			return
		case <-ticker.C:
			if err := s.Maintain(time.Now(), false); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// Maintain compacts tiers by age and writes changed files. With flushAll it
// also writes the raw samples of the current minute. Compaction runs under
// the lock; disk writes run outside it, so Append and readers never wait for
// I/O.
func (s *Store) Maintain(now time.Time, flushAll bool) error {
	s.maintain.Lock()
	defer s.maintain.Unlock()

	s.mu.Lock()
	s.stripProcesses(now)
	s.compactRaw(now)
	s.compactMinutes(now)
	s.expireHours(now)
	plan := s.planWritesLocked(now, flushAll)
	s.mu.Unlock()

	err := s.execute(plan)

	s.mu.Lock()
	defer s.mu.Unlock()

	return errors.Join(err, s.enforceSizeLocked())
}

// stripProcesses drops process lists from samples older than
// processRetention. Records are replaced, never changed in place, because
// readers marshal them outside the lock.
func (s *Store) stripProcesses(now time.Time) {
	for index, record := range s.raw {
		if now.Sub(record.ObservedAt) > processRetention && record.Node.Processes.Items != nil {
			stripped := *record
			stripped.Node.Processes.Items = nil
			s.raw[index] = &stripped
		}
	}
}

// compactRaw turns complete minutes older than rawRetention into the minute
// tier.
func (s *Store) compactRaw(now time.Time) {
	cutoff := now.Add(-rawRetention).Truncate(time.Minute)

	index := 0
	for index < len(s.raw) && s.raw[index].ObservedAt.Before(cutoff) {
		minute := s.raw[index].ObservedAt.Truncate(time.Minute)
		end := index
		for end < len(s.raw) && s.raw[end].ObservedAt.Truncate(time.Minute).Equal(minute) {
			end++
		}

		s.compactMinute(s.raw[index:end])
		index = end
	}

	if index > 0 {
		s.raw = slices.Clone(s.raw[index:])
	}
}

// spikeWindow is the resolution kept for a minute with a spike: the shape of
// the spike survives without keeping every sample.
const spikeWindow = 10 * time.Second

func (s *Store) compactMinute(records []*Record) {
	minute := rollupRecords(records)
	hourKey := records[0].ObservedAt.Truncate(time.Hour).Unix()
	s.dirtyMinute[hourKey] = struct{}{}

	if hasSpike(*minute.Node) || hasSpike(*minute.Container) {
		start := 0
		for start < len(records) {
			window := records[start].ObservedAt.Truncate(spikeWindow)
			end := start
			for end < len(records) && records[end].ObservedAt.Truncate(spikeWindow).Equal(window) {
				end++
			}

			s.minute = append(s.minute, rollupRecords(records[start:end]))
			start = end
		}
		return
	}

	if last := len(s.minute) - 1; last >= 0 && s.minute[last].Record == nil &&
		s.minute[last].Node.End.Truncate(time.Hour).Equal(minute.Node.Start.Truncate(time.Hour)) &&
		similar(*s.minute[last].Node, *minute.Node) && similar(*s.minute[last].Container, *minute.Container) {
		s.minute[last] = mergeItems(s.minute[last], minute)
		return
	}

	s.minute = append(s.minute, minute)
}

func rollupRecords(records []*Record) Item {
	node, container := newRollupBuilder(), newRollupBuilder()
	for _, record := range records {
		node.add(record.Sequence, record.ObservedAt, record.ObservedAt, seriesOf(record, protocol.MetricTypeNode))
		container.add(record.Sequence, record.ObservedAt, record.ObservedAt, seriesOf(record, protocol.MetricTypeContainer))
	}

	nodeRollup, containerRollup := node.result(), container.result()

	return Item{Node: &nodeRollup, Container: &containerRollup}
}

func mergeItems(items ...Item) Item {
	node, container := newRollupBuilder(), newRollupBuilder()
	for _, item := range items {
		if item.Record != nil {
			node.add(item.Record.Sequence, item.Record.ObservedAt, item.Record.ObservedAt, seriesOf(item.Record, protocol.MetricTypeNode))
			container.add(item.Record.Sequence, item.Record.ObservedAt, item.Record.ObservedAt, seriesOf(item.Record, protocol.MetricTypeContainer))
			continue
		}

		node.addRollup(*item.Node)
		container.addRollup(*item.Container)
	}

	nodeRollup, containerRollup := node.result(), container.result()

	return Item{Node: &nodeRollup, Container: &containerRollup}
}

// compactMinutes turns complete hours older than minuteRetention into hourly
// rollups.
func (s *Store) compactMinutes(now time.Time) {
	cutoff := now.Add(-minuteRetention).Truncate(time.Hour)

	index := 0
	for index < len(s.minute) && s.minute[index].start().Before(cutoff) {
		hour := s.minute[index].start().Truncate(time.Hour)
		end := index
		for end < len(s.minute) && s.minute[end].start().Truncate(time.Hour).Equal(hour) {
			end++
		}

		s.hour = append(s.hour, mergeItems(s.minute[index:end]...))
		s.dirtyMinute[hour.Unix()] = struct{}{}
		s.dirtyHour[hour.Truncate(24*time.Hour).Unix()] = struct{}{}
		index = end
	}

	if index > 0 {
		s.minute = slices.Clone(s.minute[index:])
	}
}

func (s *Store) expireHours(now time.Time) {
	cutoff := now.Add(-hourRetention)

	index := 0
	for index < len(s.hour) && s.hour[index].end().Before(cutoff) {
		s.dirtyHour[s.hour[index].start().Truncate(24*time.Hour).Unix()] = struct{}{}
		index++
	}

	if index > 0 {
		s.hour = slices.Clone(s.hour[index:])
	}
}

// writeJob writes or (with values nil) removes one file. retry marks the
// data dirty again when the job fails, so the next Maintain retries it.
type writeJob struct {
	path   string
	values []any
	merge  bool
	retry  func()
}

// writePlan orders writes so that a crash never loses data: higher tiers and
// new raw minutes first, then meta, and removals of compacted data last.
type writePlan struct {
	writes   []writeJob
	meta     []byte
	removals []writeJob
	rawFloor int64
}

func (s *Store) planWritesLocked(now time.Time, flushAll bool) writePlan {
	plan := writePlan{rawFloor: s.oldestRawMinute(now)}
	current := now.UTC().Truncate(time.Minute).Unix()

	for day := range s.dirtyHour {
		plan.add(s.tierJob("hour", day, s.itemsIn(s.hour, day, 24*time.Hour), s.dirtyHour))
		delete(s.dirtyHour, day)
	}
	for hour := range s.dirtyMinute {
		plan.add(s.tierJob("minute", hour, s.itemsIn(s.minute, hour, time.Hour), s.dirtyMinute))
		delete(s.dirtyMinute, hour)
	}

	for minute, records := range s.pendingRaw {
		// Minutes already compacted live in the minute tier.
		if minute < plan.rawFloor {
			delete(s.pendingRaw, minute)
			continue
		}
		if minute >= current && !flushAll {
			continue
		}

		values := make([]any, 0, len(records))
		for _, record := range records {
			copied := *record
			copied.Node.Processes.Items = nil
			values = append(values, copied)
		}
		pending := records
		plan.writes = append(plan.writes, writeJob{
			path:   filepath.Join(s.dir, "raw", key(minute)),
			values: values,
			merge:  true,
			retry:  func() { s.pendingRaw[minute] = append(pending, s.pendingRaw[minute]...) },
		})
		delete(s.pendingRaw, minute)
	}

	plan.meta, _ = json.Marshal(s.meta)

	return plan
}

func (s *Store) tierJob(tier string, unix int64, items []Item, dirty map[int64]struct{}) writeJob {
	job := writeJob{
		path:  filepath.Join(s.dir, tier, key(unix)),
		retry: func() { dirty[unix] = struct{}{} },
	}
	for _, item := range items {
		job.values = append(job.values, item)
	}

	return job
}

func (plan *writePlan) add(job writeJob) {
	if job.values == nil {
		plan.removals = append(plan.removals, job)
		return
	}

	plan.writes = append(plan.writes, job)
}

func (s *Store) execute(plan writePlan) error {
	var errs []error
	failed := func(job writeJob, err error) {
		errs = append(errs, err)
		s.mu.Lock()
		job.retry()
		s.mu.Unlock()
	}

	for _, job := range plan.writes {
		var err error
		if job.merge {
			err = mergeRawFile(job.path, job.values)
		} else {
			err = writeFile(job.path, job.values)
		}
		if err != nil {
			failed(job, err)
		}
	}

	if err := atomicWrite(filepath.Join(s.dir, metaName), func(w io.Writer) error {
		_, err := w.Write(plan.meta)
		return err
	}); err != nil {
		// Without durable meta, removing compacted files could lose data.
		return errors.Join(append(errs, err)...)
	}

	for _, job := range plan.removals {
		if err := os.Remove(job.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed(job, err)
		}
	}
	errs = append(errs, removeOld(filepath.Join(s.dir, "raw"), plan.rawFloor))

	return errors.Join(errs...)
}

func (s *Store) oldestRawMinute(now time.Time) int64 {
	if len(s.raw) > 0 {
		return s.raw[0].ObservedAt.Truncate(time.Minute).Unix()
	}

	return now.Add(-rawRetention).Truncate(time.Minute).Unix()
}

func (s *Store) itemsIn(items []Item, start int64, span time.Duration) []Item {
	from := time.Unix(start, 0).UTC()
	to := from.Add(span)

	var result []Item
	for _, item := range items {
		if !item.start().Before(from) && item.start().Before(to) {
			result = append(result, item)
		}
	}

	return result
}

// enforceSizeLocked drops the oldest hourly, then minute data while the
// files exceed maxStoreBytes.
func (s *Store) enforceSizeLocked() error {
	for {
		size, err := s.sizeOnDisk()
		if err != nil || size <= maxStoreBytes {
			return err
		}

		switch {
		case len(s.hour) > 0:
			day := s.hour[0].start().Truncate(24 * time.Hour).Unix()
			s.hour = slices.DeleteFunc(s.hour, func(item Item) bool { return item.start().Truncate(24*time.Hour).Unix() == day })
			if err := os.Remove(filepath.Join(s.dir, "hour", key(day))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		case len(s.minute) > 0:
			hour := s.minute[0].start().Truncate(time.Hour).Unix()
			s.minute = slices.DeleteFunc(s.minute, func(item Item) bool { return item.start().Truncate(time.Hour).Unix() == hour })
			if err := os.Remove(filepath.Join(s.dir, "minute", key(hour))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		default:
			return nil
		}
	}
}

func (s *Store) sizeOnDisk() (int64, error) {
	var total int64
	err := filepath.WalkDir(s.dir, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()

		return nil
	})

	return total, err
}

func key(unix int64) string {
	return fmt.Sprintf("%d%s", unix, fileSuffix)
}

// sequenceReserve is added to the next sequence on every reopen. meta.json is
// written only during maintenance, so after a crash it can lag behind
// sequences already delivered; skipping ahead keeps them unique.
const sequenceReserve = 10000

// load reads meta and every tier file. A file that cannot be read is moved
// aside and reported in LoadWarnings instead of keeping the agent from
// starting.
func (s *Store) load() error {
	data, err := os.ReadFile(filepath.Join(s.dir, metaName))
	reopened := err == nil
	switch {
	case errors.Is(err, os.ErrNotExist):
		streamID, err := agentcrypto.NewUUID()
		if err != nil {
			return err
		}
		s.meta = meta{Version: storeVersion, StreamID: streamID, Cursors: map[string]uint64{}}
	case err != nil:
		return fmt.Errorf("read metrics store meta: %w", err)
	default:
		if err := strictjson.Decode(data, &s.meta); err != nil || s.meta.Version != storeVersion || !agentcrypto.ValidUUID(s.meta.StreamID) {
			return errors.New("metrics store meta is invalid; remove the metrics directory to start over")
		}
		if s.meta.Cursors == nil {
			s.meta.Cursors = map[string]uint64{}
		}
	}

	var records []*Record
	s.loadTier("raw", func(data []byte) error {
		var record Record
		if err := strictjson.Decode(data, &record); err != nil {
			return err
		}
		records = append(records, &record)

		return nil
	})
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	s.raw = records

	for tier, target := range map[string]*[]Item{"minute": &s.minute, "hour": &s.hour} {
		s.loadTier(tier, func(data []byte) error {
			var item Item
			if err := strictjson.Decode(data, &item); err != nil {
				return err
			}
			if item.Record == nil && (item.Node == nil || item.Container == nil) {
				return errors.New("metrics item has no content")
			}
			*target = append(*target, item)

			return nil
		})
		sort.Slice(*target, func(i, j int) bool { return (*target)[i].FirstSequence() < (*target)[j].FirstSequence() })
	}

	// After a crash during compaction, a lower tier can still hold data that
	// a higher tier already covers; the higher tier wins.
	var lastHour uint64
	for _, item := range s.hour {
		lastHour = max(lastHour, item.LastSequence())
	}
	s.minute = slices.DeleteFunc(s.minute, func(item Item) bool { return item.LastSequence() <= lastHour })
	if last := s.lastCompacted(); last > 0 {
		s.raw = slices.DeleteFunc(s.raw, func(record *Record) bool { return record.Sequence <= last })
	}

	next := max(s.meta.NextSequence, s.lastCompacted())
	for _, record := range s.raw {
		next = max(next, record.Sequence)
	}
	if reopened {
		next += sequenceReserve
	}
	s.meta.NextSequence = next

	return nil
}

// LoadWarnings lists files that could not be read when the store opened.
func (s *Store) LoadWarnings() []error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.warnings)
}

func (s *Store) loadTier(tier string, decode func([]byte) error) {
	dir := filepath.Join(s.dir, tier)
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.warnings = append(s.warnings, fmt.Errorf("read metrics %s tier: %w", tier, err))
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		var decoded [][]byte
		err := readFile(path, func(data []byte) error {
			decoded = append(decoded, slices.Clone(data))
			return nil
		})
		if err == nil {
			for _, data := range decoded {
				if err = decode(data); err != nil {
					break
				}
			}
		}
		if err != nil {
			s.warnings = append(s.warnings, fmt.Errorf("metrics file %s/%s is unreadable and was set aside: %w", tier, entry.Name(), err))
			_ = os.Rename(path, path+".bad")
		}
	}
}

func (s *Store) lastCompacted() uint64 {
	var last uint64
	for _, tier := range [][]Item{s.hour, s.minute} {
		for _, item := range tier {
			last = max(last, item.LastSequence())
		}
	}

	return last
}

// Files are a DEFLATE stream of JSON records, one per line: compact, quick
// to read back, and decoded strictly.
func readFile(path string, decode func([]byte) error) (resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()

	reader := flate.NewReader(io.LimitReader(file, maxFileBytes))
	defer func() { resultErr = errors.Join(resultErr, reader.Close()) }()

	decoder := json.NewDecoder(io.LimitReader(reader, maxFileBytes))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}

		if err := decode(raw); err != nil {
			return err
		}
	}
}

// mergeRawFile adds records to an existing raw minute file.
func mergeRawFile(path string, records []any) error {
	var values []any
	if err := readFile(path, func(data []byte) error {
		var record Record
		if err := strictjson.Decode(data, &record); err != nil {
			return err
		}
		values = append(values, record)

		return nil
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return writeFile(path, append(values, records...))
}

// removeOld removes tier files whose start lies before beforeUnix.
func removeOld(dir string, beforeUnix int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var errs []error
	for _, entry := range entries {
		var unix int64
		if _, err := fmt.Sscanf(entry.Name(), "%d"+fileSuffix, &unix); err != nil || entry.Name() != key(unix) {
			continue
		}
		if unix < beforeUnix {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func writeFile(path string, values []any) error {
	return atomicWrite(path, func(w io.Writer) error {
		compressor, err := flate.NewWriter(w, flate.DefaultCompression)
		if err != nil {
			return err
		}

		encoder := json.NewEncoder(compressor)
		for _, value := range values {
			if err := encoder.Encode(value); err != nil {
				return err
			}
		}

		return compressor.Close()
	})
}

// atomicWrite writes a private temporary file and renames it into place.
func atomicWrite(path string, fill func(io.Writer) error) (resultErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, temporary.Close(), os.Remove(temporary.Name()))
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := fill(temporary); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}

	committed = true

	return nil
}

// Collect samples once per interval into the store until ctx is cancelled.
// The agent stores every sample whether or not any reader is connected.
func (s *Store) Collect(
	ctx context.Context,
	collect func(context.Context) (metrics.Snapshot, error),
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
		snapshot, err := collect(collectCtx)
		cancel()

		if err == nil {
			err = s.Append(snapshot)
		}
		if err != nil && onError != nil {
			onError(err)
		}
	}
}
