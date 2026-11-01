package metricstore

import (
	"math"
	"time"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// Event kinds.
const (
	EventCPUHigh             = "cpu_high"
	EventCPUSpike            = "cpu_spike"
	EventIOWaitHigh          = "iowait_high"
	EventMemoryHigh          = "memory_high"
	EventFilesystemFull      = "filesystem_full"
	EventContainerMemoryHigh = "container_memory_high"
	EventContainerStarted    = "container_started"
	EventContainerRestarted  = "container_restarted"
	EventContainerStopped    = "container_stopped"
	EventContainerOOM        = "container_oom"
	EventContainerHealth     = "container_health"
	EventHistoryEvicted      = "history_evicted"
)

const (
	eventRetention = 7 * 24 * time.Hour
	maxEvents      = 10000
)

// thresholdRule opens an event when a series stays at or above on for
// hold, and closes it when the series falls below off.
type thresholdRule struct {
	kind   string
	metric string
	on     float64
	off    float64
	hold   time.Duration
}

var thresholdRules = []thresholdRule{
	{kind: EventCPUHigh, metric: "cpu.usage_percent", on: 90, off: 80, hold: 30 * time.Second},
	{kind: EventIOWaitHigh, metric: "cpu.iowait_percent", on: 20, off: 10, hold: 30 * time.Second},
	{kind: EventMemoryHigh, metric: "memory.used_percent", on: 90, off: 85, hold: 30 * time.Second},
	{kind: EventFilesystemFull, metric: "fs.used_percent", on: 90, off: 88},
	{kind: EventContainerMemoryHigh, metric: "container.memory_used_percent", on: 90, off: 85, hold: 30 * time.Second},
}

// A spike is CPU usage that rises spikeRise points above its 5-minute
// average and stays there for spikeHold; it ends below half the rise.
const (
	spikeMetric = "cpu.usage_percent"
	spikeRise   = 30.0
	spikeHold   = 3 * time.Second
	// spikeAlpha weights an exponential average over about 5 minutes of
	// 1-second samples.
	spikeAlpha = 2.0 / 301
	// spikeWarmup is how many samples the average needs before it counts.
	spikeWarmup = 60
)

// condition tracks one rule for one subject.
type condition struct {
	since  time.Time
	event  uint64
	peak   float64
	peakAt time.Time
	// reported is the peak readers last received; smaller rises are not
	// sent again.
	reported float64
}

// raise records a new peak of an open event and tells readers when it
// rose by at least one unit.
func (state *condition) raise(at time.Time, value float64, journal *journal) {
	if value <= state.peak {
		return
	}
	state.peak, state.peakAt = value, at
	if state.peak-state.reported >= 1 {
		journal.update(state.event, state.peak, state.peakAt)
		state.reported = state.peak
	}
}

type detector struct {
	conditions map[string]*condition
	average    float64
	samples    int
}

func newDetector() *detector {
	return &detector{conditions: make(map[string]*condition)}
}

// observe runs the rules on one sample and opens, updates, or closes
// events in the journal.
func (d *detector) observe(at time.Time, series []Series, signals []signal, journal *journal) {
	seen := make(map[string]struct{}, len(series))
	check := func(key, name string, value float64) {
		metric, subject := SplitKey(key)
		for _, rule := range thresholdRules {
			if rule.metric != metric {
				continue
			}
			id := rule.kind + "|" + subject
			seen[id] = struct{}{}
			d.threshold(at, id, rule, subject, name, value, journal)
		}
	}
	for _, s := range series {
		check(s.Column.Key, s.Column.Name, s.Value)
		if s.Column.Key == spikeMetric {
			d.spike(at, s.Value, journal)
		}
	}
	for _, s := range signals {
		check(s.key, s.name, s.value)
	}

	// A subject that disappeared (an unmounted file system, a removed
	// container) ends its events.
	for id, state := range d.conditions {
		if _, present := seen[id]; present || id == spikeMetric {
			continue
		}
		if state.event != 0 {
			journal.end(state.event, at, state.peak, state.peakAt)
		}
		delete(d.conditions, id)
	}
}

func (d *detector) threshold(at time.Time, id string, rule thresholdRule, subject, name string, value float64, journal *journal) {
	state := d.conditions[id]
	if state == nil {
		state = &condition{}
		d.conditions[id] = state
	}

	if state.event != 0 {
		state.raise(at, value, journal)
		if value < rule.off {
			journal.end(state.event, at, state.peak, state.peakAt)
			*state = condition{}
		}
		return
	}

	if value < rule.on {
		state.since = time.Time{}
		return
	}
	if state.since.IsZero() {
		state.since, state.peak, state.peakAt = at, value, at
	}
	if value > state.peak {
		state.peak, state.peakAt = value, at
	}
	if at.Sub(state.since) >= rule.hold {
		state.event = journal.open(protocol.MetricEvent{
			Kind: rule.kind, Subject: subject, Name: name, Start: state.since,
		}, state.peak, state.peakAt)
		state.reported = state.peak
	}
}

func (d *detector) spike(at time.Time, value float64, journal *journal) {
	d.samples++
	if d.samples == 1 {
		d.average = value
	}
	rise := value - d.average

	state := d.conditions[spikeMetric]
	if state == nil {
		state = &condition{}
		d.conditions[spikeMetric] = state
	}

	switch {
	case state.event != 0:
		state.raise(at, value, journal)
		if rise < spikeRise/2 {
			journal.end(state.event, at, state.peak, state.peakAt)
			*state = condition{}
		}
	case d.samples < spikeWarmup || rise < spikeRise:
		state.since = time.Time{}
	default:
		if state.since.IsZero() {
			state.since, state.peak, state.peakAt = at, value, at
		}
		if value > state.peak {
			state.peak, state.peakAt = value, at
		}
		if at.Sub(state.since) >= spikeHold {
			state.event = journal.open(protocol.MetricEvent{Kind: EventCPUSpike, Start: state.since}, state.peak, state.peakAt)
			state.reported = state.peak
		}
	}

	// The average follows slowly and is not dragged up by the spike it
	// is measured against.
	if state.event == 0 && !math.IsNaN(value) {
		d.average += spikeAlpha * (value - d.average)
	}
}

// containerEvent turns a Docker lifecycle event into a journal event.
func containerEvent(event metrics.ContainerEvent) (protocol.MetricEvent, bool) {
	result := protocol.MetricEvent{
		Subject: metrics.ContainerKey(event.Name, event.Labels),
		Name:    event.Name,
		Start:   event.At,
	}
	switch event.Action {
	case "start":
		result.Kind = EventContainerStarted
	case "restart":
		result.Kind = EventContainerRestarted
	case "die":
		result.Kind = EventContainerStopped
		result.Detail = "exit_code=" + event.ExitCode
	case "oom":
		result.Kind = EventContainerOOM
	case "health_status":
		result.Kind = EventContainerHealth
		result.Detail = event.Health
	default:
		return protocol.MetricEvent{}, false
	}

	return result, true
}

// storedEvent is an event and the revision it last changed at, so readers
// receive each change once.
type storedEvent struct {
	event    protocol.MetricEvent
	revision uint64
}

// journal keeps the events of the last week, at most maxEvents. Finished
// events are appended to disk; ongoing ones live in memory until they end.
type journal struct {
	events   []storedEvent
	nextID   uint64
	revision uint64
	// finished holds events to append to the file at the next flush.
	finished []protocol.MetricEvent
	// appended counts the lines in the file, so it is compacted when it
	// holds twice as many events as are kept.
	appended int
}

func (j *journal) add(event protocol.MetricEvent) uint64 {
	j.nextID++
	j.revision++
	event.ID = j.nextID
	j.events = append(j.events, storedEvent{event: event, revision: j.revision})
	if len(j.events) > maxEvents {
		j.events = j.events[len(j.events)-maxEvents:]
	}
	if !event.Ongoing {
		j.finished = append(j.finished, event)
	}

	return event.ID
}

// instant records an event without a duration.
func (j *journal) instant(event protocol.MetricEvent) {
	j.add(event)
}

func (j *journal) open(event protocol.MetricEvent, peak float64, peakAt time.Time) uint64 {
	event.Ongoing = true
	event.Peak = round(peak)
	event.PeakAt = &peakAt

	return j.add(event)
}

func (j *journal) find(id uint64) *storedEvent {
	for index := len(j.events) - 1; index >= 0; index-- {
		if j.events[index].event.ID == id {
			return &j.events[index]
		}
	}

	return nil
}

func (j *journal) update(id uint64, peak float64, peakAt time.Time) {
	stored := j.find(id)
	if stored == nil {
		return
	}
	j.revision++
	stored.revision = j.revision
	stored.event.Peak = round(peak)
	stored.event.PeakAt = &peakAt
}

func (j *journal) end(id uint64, at time.Time, peak float64, peakAt time.Time) {
	stored := j.find(id)
	if stored == nil {
		return
	}
	j.revision++
	stored.revision = j.revision
	stored.event.Ongoing = false
	stored.event.End = &at
	stored.event.Peak = round(peak)
	stored.event.PeakAt = &peakAt
	j.finished = append(j.finished, stored.event)
}

// expire drops events that ended more than eventRetention ago.
func (j *journal) expire(now time.Time) {
	cut := 0
	for cut < len(j.events) {
		event := j.events[cut].event
		end := event.Start
		if event.End != nil {
			end = *event.End
		}
		if event.Ongoing || now.Sub(end) < eventRetention {
			break
		}
		cut++
	}
	j.events = j.events[cut:]
}

// overlapping returns up to limit events that overlap [from, to].
func (j *journal) overlapping(from, to time.Time, limit int) ([]protocol.MetricEvent, bool) {
	result := []protocol.MetricEvent{}
	for _, stored := range j.events {
		event := stored.event
		end := event.Start
		if event.End != nil {
			end = *event.End
		}
		if event.Start.After(to) || (!event.Ongoing && end.Before(from)) {
			continue
		}
		if len(result) == limit {
			return result, true
		}
		result = append(result, event)
	}

	return result, false
}

// changedAfter returns events changed after revision, and the newest
// revision.
func (j *journal) changedAfter(revision uint64) ([]protocol.MetricEvent, uint64) {
	var result []protocol.MetricEvent
	for _, stored := range j.events {
		if stored.revision > revision {
			result = append(result, stored.event)
		}
	}

	return result, j.revision
}
