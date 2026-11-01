package protocol

import "time"

// Metrics message types. A reader watches what it shows with metrics.watch
// and pulls history per chart with metrics.history; nothing is sent to a
// reader that does not watch.
const (
	MetricsWatchType         = "metrics.watch"
	MetricsWatchAcceptedType = "metrics.watch.accepted"
	MetricsSchemaType        = "metrics.schema"
	MetricsTickType          = "metrics.tick"
	MetricsDetailType        = "metrics.detail"
	MetricsEventType         = "metrics.event"
	MetricsHistoryType       = "metrics.history"
	MetricsHistoryResultType = "metrics.history.result"
	MetricsEventsType        = "metrics.events"
	MetricsEventsResultType  = "metrics.events.result"
)

// Watch scopes.
const (
	MetricsScopeOverview  = "overview"
	MetricsScopeNode      = "node"
	MetricsScopeContainer = "container"
	MetricsScopeProcesses = "processes"
)

// Bounds of metrics requests.
const (
	MetricsIntervalMinMS     = 1000
	MetricsIntervalMaxMS     = 10000
	MetricsIntervalDefaultMS = 2000
	MetricsLeaseMinS         = 10
	MetricsLeaseMaxS         = 300
	MetricsLeaseDefaultS     = 60
	MaxMetricsViews          = 8
	MaxMetricsProcesses      = 256
	DefaultMetricsProcesses  = 20
	MaxHistorySeries         = 64
	MaxEventsLimit           = 500
	DefaultEventsLimit       = 200
)

// History ranges.
const (
	MetricsRange5m  = "5m"
	MetricsRange1h  = "1h"
	MetricsRange6h  = "6h"
	MetricsRange24h = "24h"
	MetricsRange7d  = "7d"
)

// MetricsWatch says what the reader shows now. It replaces the previous
// watch of the session; an empty views list stops it. The watch ends after
// lease_s unless the reader sends metrics.watch again.
type MetricsWatch struct {
	Type       string        `json:"type"`
	RequestID  string        `json:"request_id"`
	IntervalMS int           `json:"interval_ms,omitempty"`
	LeaseS     int           `json:"lease_s,omitempty"`
	Views      []MetricsView `json:"views"`
}

// MetricsView is one screen: the overview, the node's details, one
// container, or the process table.
type MetricsView struct {
	Scope       string `json:"scope"`
	ContainerID string `json:"container_id,omitempty"`
	// Limit is the number of processes, by CPU, for the processes scope.
	Limit int `json:"limit,omitempty"`
}

// MetricsWatchAccepted confirms the watch with the settings in effect.
type MetricsWatchAccepted struct {
	Type       string        `json:"type"`
	RequestID  string        `json:"request_id"`
	StreamID   string        `json:"stream_id"`
	IntervalMS int           `json:"interval_ms"`
	LeaseS     int           `json:"lease_s"`
	Views      []MetricsView `json:"views"`
}

// MetricColumn describes one key series: its key, unit and the values that
// do not change from tick to tick.
type MetricColumn struct {
	// Index is the column's position in tick values within this watch.
	// Indices only grow and are never reused within a watch.
	Index int    `json:"i"`
	Key   string `json:"key"`
	Unit  string `json:"unit"`
	// Name is the container, interface, or mount point the series is about.
	Name        string   `json:"name,omitempty"`
	ContainerID string   `json:"container_id,omitempty"`
	TotalBytes  *uint64  `json:"total_bytes,omitempty"`
	LimitCores  *float64 `json:"limit_cores,omitempty"`
}

// MetricsSchema tells a watching reader which column each tick value
// belongs to. The first schema of a watch is full; later ones add columns
// (or describe them again when their fixed values change) and remove
// columns that went away.
type MetricsSchema struct {
	Type     string         `json:"type"`
	StreamID string         `json:"stream_id"`
	Version  uint64         `json:"version"`
	Full     bool           `json:"full"`
	Columns  []MetricColumn `json:"columns"`
	Removed  []int          `json:"removed,omitempty"`
}

// MetricsTick carries the current values of the overview. A keyframe has
// Values, indexed by column, with null for columns that are gone; other
// ticks have Changes, keyed by column index, with only the values that
// changed since the previous tick.
type MetricsTick struct {
	Type       string              `json:"type"`
	Version    uint64              `json:"version"`
	Sequence   uint64              `json:"sequence"`
	ObservedAt time.Time           `json:"observed_at"`
	Values     []*float64          `json:"values,omitempty"`
	Changes    map[string]*float64 `json:"changes,omitempty"`
}

// MetricsDetail carries the current reading of a detail view.
type MetricsDetail struct {
	Type       string            `json:"type"`
	Scope      string            `json:"scope"`
	Sequence   uint64            `json:"sequence"`
	ObservedAt time.Time         `json:"observed_at"`
	Node       *NodeMetrics      `json:"node,omitempty"`
	Container  *ContainerMetrics `json:"container,omitempty"`
	Processes  *ProcessMetrics   `json:"processes,omitempty"`
	Issues     []CollectionIssue `json:"collection_issues,omitempty"`
}

// MetricEvent is a notable change: a spike, a threshold crossed, a
// container that started, stopped, or ran out of memory. An event with a
// duration is sent when it begins, with ongoing set, and again when it
// ends, with the same id.
type MetricEvent struct {
	ID      uint64     `json:"id"`
	Kind    string     `json:"kind"`
	Subject string     `json:"subject,omitempty"`
	Name    string     `json:"name,omitempty"`
	Start   time.Time  `json:"start"`
	End     *time.Time `json:"end,omitempty"`
	Ongoing bool       `json:"ongoing,omitempty"`
	Peak    *float64   `json:"peak,omitempty"`
	PeakAt  *time.Time `json:"peak_at,omitempty"`
	Detail  string     `json:"detail,omitempty"`
}

// MetricsEventPush carries one new or updated event to a watching reader.
type MetricsEventPush struct {
	Type  string      `json:"type"`
	Event MetricEvent `json:"event"`
}

// MetricsHistory asks for the history of up to MaxHistorySeries series in
// one range. With since, only points from the bucket that holds since on
// are returned, so a reader that has a chart extends it.
type MetricsHistory struct {
	Type      string     `json:"type"`
	RequestID string     `json:"request_id"`
	Range     string     `json:"range"`
	Series    []string   `json:"series"`
	Since     *time.Time `json:"since,omitempty"`
}

// MetricsHistoryResult has one point per step from start. Avg and max are
// aligned with the points; null marks a step without data.
type MetricsHistoryResult struct {
	Type      string                `json:"type"`
	RequestID string                `json:"request_id"`
	StreamID  string                `json:"stream_id"`
	Range     string                `json:"range"`
	StepS     int                   `json:"step_s"`
	Start     time.Time             `json:"start"`
	Points    int                   `json:"points"`
	Series    []MetricHistorySeries `json:"series"`
	Unknown   []string              `json:"unknown,omitempty"`
}

// MetricHistorySeries is the history of one series.
type MetricHistorySeries struct {
	Key string     `json:"key"`
	Avg []*float64 `json:"avg"`
	Max []*float64 `json:"max"`
}

// MetricsEvents asks for the events that overlap a time range.
type MetricsEvents struct {
	Type      string    `json:"type"`
	RequestID string    `json:"request_id"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Limit     int       `json:"limit,omitempty"`
}

// MetricsEventsResult lists events oldest first; more is set when the limit
// cut the list.
type MetricsEventsResult struct {
	Type      string        `json:"type"`
	RequestID string        `json:"request_id"`
	Events    []MetricEvent `json:"events"`
	More      bool          `json:"more"`
}
