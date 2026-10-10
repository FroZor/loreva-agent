package metricstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

var base = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func sample(at time.Time, cpu float64) metrics.Snapshot {
	return metrics.Snapshot{
		ObservedAt:       at,
		Interval:         time.Second,
		ObservationScope: protocol.ObservationScopeHost,
		Node: protocol.NodeMetrics{
			CPU: protocol.CPUMetrics{Total: protocol.CPUUtilizationMetrics{UsagePercent: cpu}},
			Processes: protocol.ProcessMetrics{
				Items: []protocol.ProcessMetric{{Name: "agent"}},
			},
		},
	}
}

func fill(t *testing.T, store *Store, from time.Time, seconds int, cpu func(int) float64) {
	t.Helper()

	for second := range seconds {
		if err := store.Append(sample(from.Add(time.Duration(second)*time.Second), cpu(second))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQuietMinutesBecomeMergedRollupsAndSpikesStay(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Ten quiet minutes around 10% CPU, then one minute with a spike to 95%.
	fill(t, store, base, 600, func(int) float64 { return 10 })
	fill(t, store, base.Add(10*time.Minute), 60, func(second int) float64 {
		if second == 30 {
			return 95
		}
		return 10
	})

	if err := store.Maintain(base.Add(2*time.Hour), true); err != nil {
		t.Fatalf("Maintain() error = %v", err)
	}

	items := store.After(0, 10000)
	var quiet, spike int
	for _, item := range items {
		if item.Record != nil {
			t.Fatal("a compacted minute kept a raw sample")
		}

		cpu := item.Node.Series["cpu.total.usage_percent"]
		if item.Node.Start.Before(base.Add(10 * time.Minute)) {
			quiet++
			if cpu.Avg != 10 {
				t.Fatalf("quiet rollup = %+v", item.Node.Series)
			}
			continue
		}

		spike++
		if cpu.Max == 95 && !cpu.MaxAt.Equal(base.Add(10*time.Minute+30*time.Second)) {
			t.Fatalf("spike time = %v", cpu.MaxAt)
		}
	}
	if quiet != 1 {
		t.Fatalf("quiet minutes became %d rollups, want 1 merged rollup", quiet)
	}
	if spike != 6 {
		t.Fatalf("spike minute became %d windows, want six 10-second rollups", spike)
	}
}

func TestOldMinutesBecomeHourlyRollupsWithPeaks(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	fill(t, store, base, 3600, func(second int) float64 {
		if second == 1234 {
			return 90
		}
		return float64(10 + second%3)
	})
	if err := store.Maintain(base.Add(2*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err := store.Maintain(base.Add(26*time.Hour), true); err != nil {
		t.Fatal(err)
	}

	items := store.After(0, 10000)
	if len(items) != 1 || items[0].Record != nil {
		t.Fatalf("after a day the hour is %d items, want one rollup", len(items))
	}

	cpu := items[0].Node.Series["cpu.total.usage_percent"]
	if cpu.Max != 90 || !cpu.MaxAt.Equal(base.Add(1234*time.Second)) || cpu.Min != 10 {
		t.Fatalf("hourly CPU = %+v, want the peak and its time kept", cpu)
	}
	if items[0].Node.Samples != 3600 || items[0].Node.FirstSequence != 1 || items[0].Node.LastSequence != 3600 {
		t.Fatalf("hourly rollup = %+v", items[0].Node)
	}

	if err := store.Maintain(base.Add(8*24*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if left := store.After(0, 10); len(left) != 0 {
		t.Fatalf("data older than a week was kept: %d items", len(left))
	}
}

func TestCursorsAndReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	fill(t, store, base, 120, func(int) float64 { return 20 })
	store.SetCursor("device:a", 50)
	store.SetCursor("device:a", 40)
	if got := store.Cursor("device:a"); got != 50 {
		t.Fatalf("cursor moved back to %d", got)
	}
	if items := store.After(store.Cursor("device:a"), 1000); len(items) != 70 || items[0].Record.Sequence != 51 {
		t.Fatalf("After(50) returned %d items", len(items))
	}
	if err := store.Maintain(base.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	streamID := store.StreamID()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.StreamID() != streamID || reopened.Cursor("device:a") != 50 {
		t.Fatalf("reopened store lost its stream ID or cursor")
	}
	if items := reopened.After(0, 1000); len(items) != 120 {
		t.Fatalf("reopened store has %d samples, want 120", len(items))
	}
	if err := reopened.Append(sample(base.Add(3*time.Minute), 1)); err != nil {
		t.Fatal(err)
	}
	if items := reopened.After(120, 10); len(items) != 1 || items[0].Record.Sequence <= 120 {
		t.Fatal("sequences did not continue after reopening")
	}

	reopened.RemoveCursor("device:a")
	if reopened.Cursor("device:a") != 0 {
		t.Fatal("RemoveCursor() kept the cursor")
	}
}

func TestFlattenKeysArraysByIdentifier(t *testing.T) {
	series := flatten(protocol.NodeMetrics{
		Network: []protocol.NetworkMetrics{{InterfaceID: "network:2", RXBytesPerSecond: 7}},
		Processes: protocol.ProcessMetrics{
			Items: []protocol.ProcessMetric{{Name: "x", CPUPercent: 50}},
		},
	})

	if series["network.network:2.rx_bytes_per_second"] != 7 {
		t.Fatalf("network series = %v", series)
	}
	for key := range series {
		if len(key) >= 9 && key[:9] == "processes" {
			t.Fatalf("process data leaked into series: %s", key)
		}
	}
}

func TestUnreadableFileIsSetAside(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fill(t, store, base, 60, func(int) float64 { return 20 })
	if err := store.Maintain(base.Add(2*time.Minute), true); err != nil {
		t.Fatal(err)
	}

	broken := filepath.Join(dir, "minute", key(base.Unix()))
	if err := os.WriteFile(broken, []byte("not deflate"), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() with a broken file error = %v", err)
	}
	if len(reopened.LoadWarnings()) != 1 {
		t.Fatalf("LoadWarnings() = %v, want one", reopened.LoadWarnings())
	}
	if items := reopened.After(0, 1000); len(items) != 60 {
		t.Fatalf("reopened store has %d samples, want the 60 raw ones", len(items))
	}
	if _, err := os.Stat(broken + ".bad"); err != nil {
		t.Fatalf("broken file was not set aside: %v", err)
	}
}
