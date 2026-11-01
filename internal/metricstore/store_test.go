package metricstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// base is a whole hour, so 10-second, minute and 30-minute buckets all
// start on it.
var base = time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)

func sample(at time.Time, cpu float64, containers ...protocol.ContainerMetrics) metrics.Snapshot {
	keys := make(map[string]string, len(containers))
	for _, container := range containers {
		keys[container.ContainerID] = "name:" + container.Name
	}

	return metrics.Snapshot{
		ObservedAt:       at,
		Interval:         time.Second,
		ObservationScope: protocol.ObservationScopeHost,
		Node: protocol.NodeMetrics{
			CPU:    protocol.CPUMetrics{Total: protocol.CPUUtilizationMetrics{UsagePercent: cpu}},
			Memory: protocol.MemoryMetrics{TotalBytes: 1000, UsedBytes: 400},
			Storage: protocol.StorageMetrics{
				Devices:     []protocol.StorageDeviceMetrics{{DeviceID: "storage:sda", WriteBytesPerSecond: 10}, {DeviceID: "storage:sda1", WriteBytesPerSecond: 10}},
				Filesystems: []protocol.FilesystemMetrics{{Mountpoint: "/", TotalBytes: 100, UsedPercent: 40}},
			},
			Network: []protocol.NetworkMetrics{{InterfaceID: "network:2", RXBytesPerSecond: 5}, {InterfaceID: "network:9", RXBytesPerSecond: 7}},
		},
		Containers:      containers,
		ContainersFresh: true,
		ContainerKeys:   keys,
		Interfaces:      map[string]string{"network:2": "eth0"},
		Disks:           []string{"storage:sda"},
	}
}

func open(t *testing.T, dir string) *Store {
	t.Helper()

	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if warnings := store.LoadWarnings(); len(warnings) > 0 {
		t.Fatalf("load warnings: %v", warnings)
	}

	return store
}

func appendAll(t *testing.T, store *Store, snapshots ...metrics.Snapshot) {
	t.Helper()

	for _, snapshot := range snapshots {
		if err := store.Append(snapshot); err != nil {
			t.Fatal(err)
		}
	}
}

func history(t *testing.T, store *Store, name, key string, now time.Time) protocol.MetricHistorySeries {
	t.Helper()

	result, err := store.History(name, []string{key}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Series) != 1 {
		t.Fatalf("%s %s: series = %+v, unknown = %v", name, key, result.Series, result.Unknown)
	}

	return result.Series[0]
}

func value(t *testing.T, point *float64) float64 {
	t.Helper()

	if point == nil {
		t.Fatal("point is null")
	}

	return *point
}

func TestKeySeriesKeepOnlyWholeDisksAndRealInterfaces(t *testing.T) {
	snapshot := sample(base, 5, protocol.ContainerMetrics{ContainerID: "a", Name: "web"})
	keys := make(map[string]bool)
	for _, series := range KeySeries(&snapshot) {
		keys[series.Column.Key] = true
	}

	for _, want := range []string{
		"cpu.usage_percent", "memory.used_bytes", "memory.used_percent", "disk.write_bytes_per_second@storage:sda",
		"fs.used_percent@/", "net.rx_bytes_per_second@eth0", "containers.cpu_percent", "container.cpu_percent@name:web",
	} {
		if !keys[want] {
			t.Errorf("key series %q is missing from %v", want, keys)
		}
	}
	for _, unwanted := range []string{"disk.write_bytes_per_second@storage:sda1", "net.rx_bytes_per_second@network:9"} {
		if keys[unwanted] {
			t.Errorf("key series %q should be left out", unwanted)
		}
	}
	if metric, subject := SplitKey("net.rx_bytes_per_second@eth0.100"); metric != "net.rx_bytes_per_second" || subject != "eth0.100" {
		t.Fatalf("SplitKey = %q, %q", metric, subject)
	}
}

func TestEveryRangeKeepsTheAverageAndTheSpike(t *testing.T) {
	store := open(t, t.TempDir())

	// Two hours at 10 % with a 3-second spike to 95 % after 30 minutes.
	end := base.Add(2 * time.Hour)
	for at := base; at.Before(end); at = at.Add(time.Second) {
		cpu := 10.0
		if offset := at.Sub(base); offset >= 30*time.Minute && offset < 30*time.Minute+3*time.Second {
			cpu = 95
		}
		appendAll(t, store, sample(at, cpu))
	}
	now := end.Add(-time.Second)

	live := history(t, store, protocol.MetricsRange5m, "cpu.usage_percent", now)
	if len(live.Avg) != 300 || value(t, live.Avg[299]) != 10 {
		t.Fatalf("5m: %d points, last %v", len(live.Avg), live.Avg[299])
	}

	for _, name := range []string{protocol.MetricsRange6h, protocol.MetricsRange24h, protocol.MetricsRange7d} {
		series := history(t, store, name, "cpu.usage_percent", now)
		peak, quiet := 0.0, 0
		for index := range series.Max {
			if series.Max[index] == nil {
				continue
			}
			peak = max(peak, *series.Max[index])
			if *series.Avg[index] == 10 {
				quiet++
			}
		}
		if peak != 95 {
			t.Errorf("%s: peak = %v, want the 95 %% spike", name, peak)
		}
		if quiet == 0 {
			t.Errorf("%s: no point averages the quiet 10 %%", name)
		}
	}

	day, err := store.History(protocol.MetricsRange24h, []string{"cpu.usage_percent"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if day.StepS != 300 || day.Points != 288 {
		t.Fatalf("24h: step %d, %d points", day.StepS, day.Points)
	}

	hour := history(t, store, protocol.MetricsRange1h, "cpu.usage_percent", now)
	if len(hour.Avg) != 360 {
		t.Fatalf("1h: %d points", len(hour.Avg))
	}
}

func TestHistorySinceReturnsOnlyTheTail(t *testing.T) {
	store := open(t, t.TempDir())
	for offset := range 600 {
		appendAll(t, store, sample(base.Add(time.Duration(offset)*time.Second), 20))
	}

	since := base.Add(9 * time.Minute)
	result, err := store.History(protocol.MetricsRange1h, []string{"cpu.usage_percent", "fs.used_percent@/gone"}, &since, base.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if result.Points != 6 || !result.Start.Equal(since) {
		t.Fatalf("points = %d from %s, want 6 from %s", result.Points, result.Start, since)
	}
	if len(result.Unknown) != 1 || result.Unknown[0] != "fs.used_percent@/gone" {
		t.Fatalf("unknown = %v", result.Unknown)
	}
	if _, err := store.History("30d", []string{"cpu.usage_percent"}, nil, base); err == nil {
		t.Fatal("unknown range accepted")
	}
}

func TestStoreSurvivesARestartAndStaysTheSameSize(t *testing.T) {
	dir := t.TempDir()
	store := open(t, dir)
	for offset := range 3 * 60 {
		appendAll(t, store, sample(base.Add(time.Duration(offset)*time.Second), 30))
	}
	if err := store.Maintain(base.Add(3*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	size := storeSize(t, dir)

	reopened := open(t, dir)
	if reopened.StreamID() != store.StreamID() {
		t.Fatal("stream ID changed across a restart")
	}
	series := history(t, reopened, protocol.MetricsRange6h, "cpu.usage_percent", base.Add(3*time.Minute))
	present := 0
	for _, point := range series.Avg {
		if point != nil && *point == 30 {
			present++
		}
	}
	if present != 3 {
		t.Fatalf("%d minutes survived the restart, want 3", present)
	}

	// A day later the files have the same size: rings never grow.
	for offset := range 24 * 60 {
		appendAll(t, reopened, sample(base.Add(time.Duration(offset)*time.Minute), 30))
		if offset%30 == 0 {
			if err := reopened.Maintain(base.Add(time.Duration(offset)*time.Minute), false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := reopened.Maintain(base.Add(24*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if grown := storeSize(t, dir); grown > size+4096 {
		t.Fatalf("store grew from %d to %d bytes in a day", size, grown)
	}
}

func storeSize(t *testing.T, dir string) int64 {
	t.Helper()

	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}

	return total
}

func TestOpenRemovesTheEarlierStore(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"raw", "minute", "hour"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	open(t, dir)

	for _, name := range legacyEntries {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists", name)
		}
	}
}

func TestContainersGetHistoryAfterTheySettle(t *testing.T) {
	store := open(t, t.TempDir())
	web := protocol.ContainerMetrics{ContainerID: "a", Name: "web", CPU: protocol.ContainerCPUMetrics{UsagePercent: 50}}
	for offset := range 5 {
		appendAll(t, store, sample(base.Add(time.Duration(offset)*time.Second), 5, web))
	}
	if contains(store.Columns(), "container.cpu_percent@name:web") {
		t.Fatal("a container got history before it settled")
	}

	for offset := 5; offset < 20; offset++ {
		appendAll(t, store, sample(base.Add(time.Duration(offset)*time.Second), 5, web))
	}
	if !contains(store.Columns(), "container.cpu_percent@name:web") {
		t.Fatal("a settled container has no history")
	}

	// A recreated container with a new ID keeps the same history.
	web.ContainerID = "b"
	appendAll(t, store, sample(base.Add(20*time.Second), 5, web))
	series := history(t, store, protocol.MetricsRange5m, "container.cpu_percent@name:web", base.Add(20*time.Second))
	if value(t, series.Avg[len(series.Avg)-1]) != 50 {
		t.Fatalf("recreated container: %v", series.Avg[len(series.Avg)-1])
	}
}

func TestReusedColumnsDoNotShowTheirPreviousSeries(t *testing.T) {
	store := open(t, t.TempDir())
	snapshot := sample(base, 5)
	snapshot.Node.Storage.Filesystems = append(snapshot.Node.Storage.Filesystems, protocol.FilesystemMetrics{Mountpoint: "/old", UsedPercent: 77})
	appendAll(t, store, snapshot)

	// /old stops reporting; after a week its column is free again.
	later := base.Add(columnRetention + time.Hour)
	if err := store.Maintain(later, false); err != nil {
		t.Fatal(err)
	}
	if contains(store.Columns(), "fs.used_percent@/old") {
		t.Fatal("the column of a series gone for a week was kept")
	}

	snapshot = sample(later, 5)
	snapshot.Node.Storage.Filesystems = append(snapshot.Node.Storage.Filesystems, protocol.FilesystemMetrics{Mountpoint: "/new", UsedPercent: 11})
	appendAll(t, store, snapshot)
	series := history(t, store, protocol.MetricsRange7d, "fs.used_percent@/new", later)
	for index, point := range series.Avg[:len(series.Avg)-1] {
		if point != nil {
			t.Fatalf("point %d of the new series shows %v from the previous one", index, *point)
		}
	}
}

func contains(keys []string, key string) bool {
	for _, candidate := range keys {
		if candidate == key {
			return true
		}
	}

	return false
}

func TestEventsMarkSustainedLoadSpikesAndContainers(t *testing.T) {
	dir := t.TempDir()
	store := open(t, dir)
	revision := store.EventsRevision()

	at := base
	step := func(cpu float64, seconds int) {
		for range seconds {
			appendAll(t, store, sample(at, cpu))
			at = at.Add(time.Second)
		}
	}
	step(10, 120) // warm the average up
	step(60, 5)   // a spike
	step(10, 20)  // calm
	step(95, 40)  // sustained load
	step(10, 5)

	stopped := sample(at, 10)
	stopped.ContainerEvents = []metrics.ContainerEvent{{At: at, Name: "db", Action: "die", ExitCode: "137"}}
	appendAll(t, store, stopped)

	events, _ := store.Events(base, at, 100)
	kinds := make(map[string]protocol.MetricEvent)
	for _, event := range events {
		kinds[event.Kind] = event
	}
	if spike := kinds[EventCPUSpike]; spike.Peak == nil || *spike.Peak != 95 && *spike.Peak != 60 || spike.Ongoing {
		t.Errorf("spike = %+v", spike)
	}
	high, found := kinds[EventCPUHigh]
	if !found || high.Ongoing || high.End == nil || *high.Peak != 95 || !high.Start.Equal(base.Add(145*time.Second)) {
		t.Errorf("cpu_high = %+v", high)
	}
	if stoppedEvent := kinds[EventContainerStopped]; stoppedEvent.Detail != "exit_code=137" || stoppedEvent.Subject != "name:db" {
		t.Errorf("container_stopped = %+v", stoppedEvent)
	}

	changed, _ := store.EventsChanged(revision)
	if len(changed) < 3 {
		t.Fatalf("readers got %d event changes", len(changed))
	}

	if err := store.Maintain(at, true); err != nil {
		t.Fatal(err)
	}
	reopened := open(t, dir)
	again, _ := reopened.Events(base, at, 100)
	if len(again) != len(events) {
		t.Fatalf("%d events after a restart, want %d", len(again), len(events))
	}
}

func TestDemandCombinesReaders(t *testing.T) {
	store := open(t, t.TempDir())
	store.SetDemand("a", metrics.Demand{Processes: 20})
	store.SetDemand("b", metrics.Demand{Processes: 50, Containers: true})
	if demand := store.Demand(); demand.Processes != 50 || !demand.Containers || demand.Detail {
		t.Fatalf("demand = %+v", demand)
	}
	store.SetDemand("b", metrics.Demand{})
	if demand := store.Demand(); demand.Processes != 20 || demand.Containers {
		t.Fatalf("demand after b left = %+v", demand)
	}
}

func TestRoundKeepsChartPrecision(t *testing.T) {
	for input, want := range map[float64]float64{12.345: 12.3, 0.04: 0, 123456: 123000, 8123456789: 8120000000, -45.67: -45.7} {
		if got := *Round(input); got != want {
			t.Errorf("Round(%v) = %v, want %v", input, got, want)
		}
	}
}
