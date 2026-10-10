package metricstore

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// Thresholds that decide what compaction keeps. A series is any numeric
// field of a sample, addressed by its path (for example
// "cpu.total.usage_percent" or "network.network:2.rx_bytes_per_second").
const (
	// percentSpike is the in-window range, in percentage points, that marks
	// a spike in a *_percent series.
	percentSpike = 10.0
	// relativeSpike is the in-window range, relative to the window average,
	// that marks a spike in any other series.
	relativeSpike = 0.5
	// percentNoise and relativeNoise bound the change between neighbouring
	// windows that still counts as noise, so the windows are merged.
	percentNoise  = 2.0
	relativeNoise = 0.02
	// minimumMagnitude keeps tiny absolute values (idle counters) from
	// looking like large relative changes.
	minimumMagnitude = 1.0
)

// Aggregate summarizes one series over a window.
type Aggregate = protocol.MetricAggregate

// Rollup is a compacted window of samples of one metric type.
type Rollup = protocol.MetricRollup

// rollupBuilder accumulates samples of one metric type into a Rollup.
type rollupBuilder struct {
	rollup Rollup
	sums   map[string]float64
	counts map[string]int
}

func newRollupBuilder() *rollupBuilder {
	return &rollupBuilder{
		rollup: Rollup{Series: make(map[string]Aggregate)},
		sums:   make(map[string]float64),
		counts: make(map[string]int),
	}
}

func (b *rollupBuilder) add(sequence uint64, at, end time.Time, series map[string]float64) {
	if b.rollup.Samples == 0 || sequence < b.rollup.FirstSequence {
		b.rollup.FirstSequence = sequence
	}
	if sequence > b.rollup.LastSequence {
		b.rollup.LastSequence = sequence
	}
	if b.rollup.Start.IsZero() || at.Before(b.rollup.Start) {
		b.rollup.Start = at
	}
	if end.After(b.rollup.End) {
		b.rollup.End = end
	}
	b.rollup.Samples++

	for key, value := range series {
		aggregate, seen := b.rollup.Series[key]
		if !seen {
			aggregate = Aggregate{Min: value, Max: value, MaxAt: at}
		}
		if value < aggregate.Min {
			aggregate.Min = value
		}
		if value > aggregate.Max {
			aggregate.Max = value
			aggregate.MaxAt = at
		}

		b.sums[key] += value
		b.counts[key]++
		aggregate.Avg = b.sums[key] / float64(b.counts[key])
		b.rollup.Series[key] = aggregate
	}
}

// addRollup folds an already compacted window into the builder, weighting
// averages by sample count.
func (b *rollupBuilder) addRollup(rollup Rollup) {
	if b.rollup.Samples == 0 || rollup.FirstSequence < b.rollup.FirstSequence {
		b.rollup.FirstSequence = rollup.FirstSequence
	}
	if rollup.LastSequence > b.rollup.LastSequence {
		b.rollup.LastSequence = rollup.LastSequence
	}
	if b.rollup.Start.IsZero() || rollup.Start.Before(b.rollup.Start) {
		b.rollup.Start = rollup.Start
	}
	if rollup.End.After(b.rollup.End) {
		b.rollup.End = rollup.End
	}
	b.rollup.Samples += rollup.Samples

	for key, incoming := range rollup.Series {
		aggregate, seen := b.rollup.Series[key]
		if !seen {
			aggregate = incoming
		} else {
			if incoming.Min < aggregate.Min {
				aggregate.Min = incoming.Min
			}
			if incoming.Max > aggregate.Max {
				aggregate.Max = incoming.Max
				aggregate.MaxAt = incoming.MaxAt
			}
		}

		weight := max(rollup.Samples, 1)
		b.sums[key] += incoming.Avg * float64(weight)
		b.counts[key] += weight
		aggregate.Avg = b.sums[key] / float64(b.counts[key])
		b.rollup.Series[key] = aggregate
	}
}

func (b *rollupBuilder) result() Rollup { return b.rollup }

// hasSpike reports whether any series moved sharply inside the window.
func hasSpike(rollup Rollup) bool {
	for key, aggregate := range rollup.Series {
		spread := aggregate.Max - aggregate.Min
		if isPercent(key) {
			if spread >= percentSpike {
				return true
			}
			continue
		}

		magnitude := math.Max(math.Abs(aggregate.Avg), minimumMagnitude)
		if spread >= relativeSpike*magnitude && spread >= minimumMagnitude {
			return true
		}
	}

	return false
}

// similar reports whether two neighbouring windows differ only by noise in
// every series, so they can be merged without losing a visible change.
func similar(left, right Rollup) bool {
	if len(left.Series) != len(right.Series) {
		return false
	}

	for key, a := range left.Series {
		b, ok := right.Series[key]
		if !ok {
			return false
		}

		change := math.Abs(a.Avg - b.Avg)
		if isPercent(key) {
			if change >= percentNoise {
				return false
			}
			continue
		}

		magnitude := math.Max(math.Max(math.Abs(a.Avg), math.Abs(b.Avg)), minimumMagnitude)
		if change >= relativeNoise*magnitude {
			return false
		}
	}

	return true
}

func isPercent(key string) bool {
	return strings.HasSuffix(key, "_percent")
}

// flatten returns every numeric field of value keyed by its path. Arrays of
// objects are keyed by each element's identifier field, so a series keeps
// its key when array order changes. Process lists are skipped: they belong
// only to recent full samples.
func flatten(value any) map[string]float64 {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil
	}

	series := make(map[string]float64)
	walk("", decoded, series)

	return series
}

func walk(prefix string, value any, series map[string]float64) {
	switch typed := value.(type) {
	case float64:
		if prefix != "" && !math.IsNaN(typed) && !math.IsInf(typed, 0) {
			series[prefix] = typed
		}
	case map[string]any:
		for key, child := range typed {
			if key == "processes" || key == "collection_issues" {
				continue
			}
			walk(join(prefix, key), child, series)
		}
	case []any:
		for index, child := range typed {
			walk(join(prefix, elementKey(child, index)), child, series)
		}
	}
}

func elementKey(element any, index int) string {
	object, ok := element.(map[string]any)
	if !ok {
		return itoa(index)
	}

	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if key == "id" || strings.HasSuffix(key, "_id") {
			if identifier, ok := object[key].(string); ok && identifier != "" {
				return identifier
			}
		}
	}

	return itoa(index)
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}

	return prefix + "." + key
}

func itoa(value int) string { return strconv.Itoa(value) }

// seriesOf returns the series of one metric type of a record.
func seriesOf(record *Record, metricType string) map[string]float64 {
	switch metricType {
	case protocol.MetricTypeNode:
		return flatten(record.Node)
	case protocol.MetricTypeContainer:
		return flatten(record.Containers)
	default:
		return nil
	}
}
