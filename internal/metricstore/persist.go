package metricstore

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

// On disk the store is columns.json, one file per ring, and events.jsonl.
// A ring file is a header and then one row per slot: the bucket start and
// the average and maximum of every column. Closing a bucket rewrites only
// its row, in place, so the minute ring writes a few KiB a minute.
const (
	columnsName   = "columns.json"
	eventsName    = "events.jsonl"
	storeVersion  = 2
	ringMagic     = "LMR2"
	ringHeader    = 16
	maxEventsFile = 16 << 20
)

// legacyEntries are the files of the earlier store, which kept every
// sample; they are removed when the new store opens.
var legacyEntries = []string{"raw", "minute", "hour", "meta.json"}

type columnsFile struct {
	Version  int      `json:"version"`
	StreamID string   `json:"stream_id"`
	Capacity int      `json:"capacity"`
	Columns  []column `json:"columns"`
}

// Open loads or creates the store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create metrics store: %w", err)
	}

	var warnings []error
	for _, name := range legacyEntries {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			warnings = append(warnings, fmt.Errorf("remove earlier metrics store %s: %w", name, err))
		}
	}

	store, err := load(dir)
	if err != nil {
		return nil, err
	}
	store.warnings = append(warnings, store.warnings...)

	return store, nil
}

func load(dir string) (*Store, error) {
	var file columnsFile
	data, err := os.ReadFile(filepath.Join(dir, columnsName))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read metrics columns: %w", err)
	default:
		if err := strictjson.Decode(data, &file); err != nil || file.Version != storeVersion ||
			!agentcrypto.ValidUUID(file.StreamID) || file.Capacity < len(file.Columns) {
			file = columnsFile{}
		}
	}

	streamID := file.StreamID
	if streamID == "" {
		if streamID, err = agentcrypto.NewUUID(); err != nil {
			return nil, err
		}
	}

	store := newStore(dir, streamID)
	if file.Capacity > 0 {
		for _, t := range store.tiers {
			t.resize(file.Capacity)
			t.rewrite = false
		}
		store.columns = file.Columns
		for index, existing := range store.columns {
			if existing.Key != "" {
				store.index[existing.Key] = index
			}
		}
		for _, t := range store.tiers {
			if !t.spec.persist && t.spec.name != tierSpecs[tier10s].name {
				continue
			}
			if err := store.loadRing(t); err != nil {
				// The ring is written whole at the next flush.
				t.rewrite = true
				if t.spec.persist && !errors.Is(err, os.ErrNotExist) {
					store.warnings = append(store.warnings, err)
				}
			}
		}
	} else {
		store.columnsDirty = true
	}

	store.loadEvents(time.Now())

	return store, nil
}

func ringPath(dir string, t *tier) string {
	return filepath.Join(dir, t.spec.name+".ring")
}

func rowSize(capacity int) int {
	return 8 + capacity*8
}

// loadRing reads a ring file; a file of another layout is ignored.
func (s *Store) loadRing(t *tier) error {
	data, err := os.ReadFile(ringPath(s.dir, t))
	if err != nil {
		return err
	}
	if len(data) != ringHeader+t.spec.slots*rowSize(t.capacity) || string(data[:4]) != ringMagic ||
		binary.LittleEndian.Uint32(data[4:]) != uint32(t.stepS) ||
		binary.LittleEndian.Uint32(data[8:]) != uint32(t.spec.slots) ||
		binary.LittleEndian.Uint32(data[12:]) != uint32(t.capacity) {
		return fmt.Errorf("metrics ring %s has another layout and is rebuilt", t.spec.name)
	}

	for slot := range t.spec.slots {
		row := data[ringHeader+slot*rowSize(t.capacity):]
		t.starts[slot] = int64(binary.LittleEndian.Uint64(row))
		cells := t.cells[slot*t.capacity*2:][:t.capacity*2]
		for index := range cells {
			cells[index] = math.Float32frombits(binary.LittleEndian.Uint32(row[8+index*4:]))
		}
	}

	return nil
}

func (t *tier) header() []byte {
	header := make([]byte, ringHeader)
	copy(header, ringMagic)
	binary.LittleEndian.PutUint32(header[4:], uint32(t.stepS))
	binary.LittleEndian.PutUint32(header[8:], uint32(t.spec.slots))
	binary.LittleEndian.PutUint32(header[12:], uint32(t.capacity))

	return header
}

func (t *tier) row(slot int) []byte {
	row := make([]byte, rowSize(t.capacity))
	binary.LittleEndian.PutUint64(row, uint64(t.starts[slot]))
	cells := t.cells[slot*t.capacity*2:][:t.capacity*2]
	for index, value := range cells {
		binary.LittleEndian.PutUint32(row[8+index*4:], math.Float32bits(value))
	}

	return row
}

// ringWrite is the part of a ring to write: the whole file, or some rows.
type ringWrite struct {
	tier  int
	path  string
	whole []byte
	rows  map[int64][]byte
}

type writePlan struct {
	columns []byte
	rings   []ringWrite
	events  []protocol.MetricEvent
	compact []protocol.MetricEvent
}

// Run persists the store every interval until stop closes, and once more,
// with the 10-second ring, before it returns.
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

// Maintain frees columns of series gone for a week, expires old events,
// and writes what changed. With final it also writes the 10-second ring,
// which is otherwise kept only in memory. Writes run outside the lock, so
// Append and readers never wait for I/O. The columns file is written
// before the rows that may refer to a new column.
func (s *Store) Maintain(now time.Time, final bool) error {
	s.maintain.Lock()
	defer s.maintain.Unlock()

	s.mu.Lock()
	s.expireColumns(now)
	s.journal.expire(now)
	plan, err := s.planLocked(final)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	return s.execute(plan)
}

func (s *Store) planLocked(final bool) (writePlan, error) {
	var plan writePlan
	if s.columnsDirty {
		data, err := json.Marshal(columnsFile{
			Version: storeVersion, StreamID: s.streamID, Capacity: s.tiers[0].capacity, Columns: s.columns,
		})
		if err != nil {
			return writePlan{}, fmt.Errorf("encode metrics columns: %w", err)
		}
		plan.columns = data
		s.columnsDirty = false
	}

	for index, t := range s.tiers {
		if !t.spec.persist && !(final && index == tier10s) {
			continue
		}
		if final {
			t.close()
		}

		write := ringWrite{tier: index, path: ringPath(s.dir, t)}
		if t.rewrite || final && !t.spec.persist {
			var whole bytes.Buffer
			whole.Write(t.header())
			for slot := range t.spec.slots {
				whole.Write(t.row(slot))
			}
			write.whole = whole.Bytes()
			t.rewrite = false
		} else if len(t.dirty) > 0 {
			write.rows = make(map[int64][]byte, len(t.dirty))
			for slot := range t.dirty {
				write.rows[int64(ringHeader+slot*rowSize(t.capacity))] = t.row(slot)
			}
		}
		clear(t.dirty)
		if write.whole != nil || write.rows != nil {
			plan.rings = append(plan.rings, write)
		}
	}

	plan.events = s.journal.finished
	s.journal.finished = nil
	if s.journal.appended+len(plan.events) > 2*maxEvents {
		for _, stored := range s.journal.events {
			if !stored.event.Ongoing {
				plan.compact = append(plan.compact, stored.event)
			}
		}
		plan.events = nil
		s.journal.appended = len(plan.compact)
	} else {
		s.journal.appended += len(plan.events)
	}

	return plan, nil
}

func (s *Store) execute(plan writePlan) error {
	var errs []error
	if plan.columns != nil {
		if err := atomicWrite(filepath.Join(s.dir, columnsName), func(w io.Writer) error {
			_, err := w.Write(plan.columns)
			return err
		}); err != nil {
			// Rows must not refer to columns the file does not describe.
			return fmt.Errorf("write metrics columns: %w", err)
		}
	}

	for _, ring := range plan.rings {
		if ring.whole != nil {
			if err := atomicWrite(ring.path, func(w io.Writer) error {
				_, err := w.Write(ring.whole)
				return err
			}); err != nil {
				errs = append(errs, fmt.Errorf("write metrics ring: %w", err))
			}
			continue
		}
		if err := writeRows(ring.path, ring.rows); err != nil {
			if errors.Is(err, errRingMissing) {
				s.mu.Lock()
				s.tiers[ring.tier].rewrite = true
				s.mu.Unlock()
			}
			errs = append(errs, err)
		}
	}

	switch {
	case plan.compact != nil:
		if err := atomicWrite(filepath.Join(s.dir, eventsName), func(w io.Writer) error {
			return encodeEvents(w, plan.compact)
		}); err != nil {
			errs = append(errs, fmt.Errorf("write metrics events: %w", err))
		}
	case len(plan.events) > 0:
		if err := appendEvents(filepath.Join(s.dir, eventsName), plan.events); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeRows writes rows in place. When the ring file is missing the whole
// ring is written at the next flush.
func writeRows(path string, rows map[int64][]byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return errRingMissing
	}
	if err != nil {
		return fmt.Errorf("open metrics ring: %w", err)
	}

	var errs []error
	for offset, row := range rows {
		if _, err := file.WriteAt(row, offset); err != nil {
			errs = append(errs, fmt.Errorf("write metrics ring: %w", err))
			break
		}
	}

	return errors.Join(append(errs, file.Close())...)
}

var errRingMissing = errors.New("metrics ring file is missing")

func encodeEvents(w io.Writer, events []protocol.MetricEvent) error {
	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}

	return nil
}

func appendEvents(path string, events []protocol.MetricEvent) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open metrics events: %w", err)
	}

	err = encodeEvents(file, events)

	return errors.Join(err, file.Close())
}

// loadEvents reads finished events of the last week. A line that does not
// decode is skipped.
func (s *Store) loadEvents(now time.Time) {
	file, err := os.Open(filepath.Join(s.dir, eventsName))
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, maxEventsFile))
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		var event protocol.MetricEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || event.Ongoing {
			continue
		}
		s.journal.appended++
		s.journal.nextID = max(s.journal.nextID, event.ID)
		s.journal.events = append(s.journal.events, storedEvent{event: event})
	}
	if len(s.journal.events) > maxEvents {
		s.journal.events = s.journal.events[len(s.journal.events)-maxEvents:]
	}
	s.journal.expire(now)
}

// LoadWarnings returns problems found while opening the store; the store
// works without the affected data.
func (s *Store) LoadWarnings() []error {
	return s.warnings
}

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
