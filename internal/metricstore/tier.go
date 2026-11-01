package metricstore

import (
	"math"
	"time"
)

// tierSpec is one ring of fixed-size buckets.
type tierSpec struct {
	name  string
	step  time.Duration
	slots int
	// persist writes the ring to disk as buckets close; the 10-second ring
	// is written only when the agent stops.
	persist bool
}

// The rings match the ranges a reader shows: 5 minutes at 1 second (live),
// an hour at 10 seconds, a day at a minute (6 hours as is, 24 hours in
// 5-minute steps), and a week at 30 minutes.
var tierSpecs = []tierSpec{
	{name: "live", step: time.Second, slots: 300},
	{name: "t1", step: 10 * time.Second, slots: 360},
	{name: "t2", step: time.Minute, slots: 1440, persist: true},
	{name: "t3", step: 30 * time.Minute, slots: 336, persist: true},
}

const (
	tierLive = iota
	tier10s
	tier1m
	tier30m
)

// tier keeps the average and maximum of every column per bucket. A slot is
// reused when its bucket ages out, so a ring never grows.
type tier struct {
	spec  tierSpec
	stepS int64
	// starts holds the start, in Unix seconds, of the bucket in each slot;
	// zero marks an empty slot.
	starts []int64
	// cells holds, per slot, capacity pairs of average and maximum. NaN
	// marks a column without data in that bucket.
	cells    []float32
	capacity int

	// The open bucket accumulates samples until a sample of a later bucket
	// arrives.
	open  int64
	sum   []float64
	count []uint32
	max   []float32

	// dirty holds slots written since the last flush; rewrite asks for the
	// whole file because its layout changed.
	dirty   map[int]struct{}
	rewrite bool
}

func newTier(spec tierSpec, capacity int) *tier {
	t := &tier{
		spec:   spec,
		stepS:  int64(spec.step / time.Second),
		starts: make([]int64, spec.slots),
		dirty:  make(map[int]struct{}),
	}
	t.resize(capacity)

	return t
}

// resize changes the number of columns, keeping the data of existing ones.
func (t *tier) resize(capacity int) {
	cells := make([]float32, t.spec.slots*capacity*2)
	for index := range cells {
		cells[index] = float32(math.NaN())
	}
	for slot := range t.spec.slots {
		for column := range min(capacity, t.capacity) {
			copy(cells[(slot*capacity+column)*2:][:2], t.cells[(slot*t.capacity+column)*2:][:2])
		}
	}

	t.cells = cells
	t.sum = append(t.sum, make([]float64, max(capacity-len(t.sum), 0))...)[:capacity]
	t.count = append(t.count, make([]uint32, max(capacity-len(t.count), 0))...)[:capacity]
	t.max = append(t.max, make([]float32, max(capacity-len(t.max), 0))...)[:capacity]
	t.capacity = capacity
	t.rewrite = true
}

func (t *tier) bucket(at int64) int64 {
	return at - mod(at, t.stepS)
}

func (t *tier) slot(bucket int64) int {
	return int(mod(bucket/t.stepS, int64(t.spec.slots)))
}

// add folds one sample into the open bucket, closing it first when the
// sample belongs to a later one. A sample older than the open bucket (the
// clock went back) is dropped.
func (t *tier) add(at int64, values []columnValue) {
	bucket := t.bucket(at)
	switch {
	case t.open == 0:
		t.open = bucket
	case bucket < t.open:
		return
	case bucket > t.open:
		t.close()
		t.open = bucket
	}

	for _, value := range values {
		v := float32(value.value)
		if t.count[value.column] == 0 || v > t.max[value.column] {
			t.max[value.column] = v
		}
		t.sum[value.column] += value.value
		t.count[value.column]++
	}
}

// close writes the open bucket into its slot.
func (t *tier) close() {
	if t.open == 0 {
		return
	}

	slot := t.slot(t.open)
	t.starts[slot] = t.open
	row := t.cells[slot*t.capacity*2:][:t.capacity*2]
	for column := range t.capacity {
		if t.count[column] == 0 {
			row[column*2] = float32(math.NaN())
			row[column*2+1] = float32(math.NaN())
			continue
		}
		row[column*2] = float32(t.sum[column] / float64(t.count[column]))
		row[column*2+1] = t.max[column]
		t.sum[column], t.count[column], t.max[column] = 0, 0, 0
	}
	t.dirty[slot] = struct{}{}
	t.open = 0
}

// point returns the average and maximum of a column in one bucket: from
// its slot when the bucket closed, or from the open bucket. since is when
// the column started to belong to its series.
func (t *tier) point(bucket int64, column int, since int64) (float64, float64, bool) {
	if bucket < since-mod(since, t.stepS) {
		return 0, 0, false
	}
	if bucket == t.open {
		if t.count[column] == 0 {
			return 0, 0, false
		}

		return t.sum[column] / float64(t.count[column]), float64(t.max[column]), true
	}

	slot := t.slot(bucket)
	if t.starts[slot] != bucket {
		return 0, 0, false
	}
	avg := t.cells[(slot*t.capacity+column)*2]
	peak := t.cells[(slot*t.capacity+column)*2+1]
	if math.IsNaN(float64(avg)) {
		return 0, 0, false
	}

	return float64(avg), float64(peak), true
}

// latestBucket is the newest bucket with data: the open one, or the newest
// closed one.
func (t *tier) latestBucket() int64 {
	if t.open != 0 {
		return t.open
	}

	newest := int64(0)
	for _, start := range t.starts {
		newest = max(newest, start)
	}

	return newest
}

// clearColumn forgets a column's data, for a column given to a new series.
func (t *tier) clearColumn(column int) {
	for slot := range t.spec.slots {
		t.cells[(slot*t.capacity+column)*2] = float32(math.NaN())
		t.cells[(slot*t.capacity+column)*2+1] = float32(math.NaN())
	}
	t.sum[column], t.count[column], t.max[column] = 0, 0, 0
}

type columnValue struct {
	column int
	value  float64
}

func mod(value, by int64) int64 {
	result := value % by
	if result < 0 {
		result += by
	}

	return result
}
