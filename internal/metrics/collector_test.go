package metrics

import (
	"math"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/shirou/gopsutil/v4/cpu"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestCPUUtilizationUsesCounterDeltas(t *testing.T) {
	previous := cpu.TimesStat{User: 10, System: 5, Idle: 85}
	current := cpu.TimesStat{User: 16, System: 9, Idle: 90}

	metric := cpuUtilization(previous, current)

	assertClose(t, "usage", metric.UsagePercent, 10.0/15.0*100)
	assertClose(t, "user", metric.UserPercent, 6.0/15.0*100)
	assertClose(t, "system", metric.SystemPercent, 4.0/15.0*100)
	assertClose(t, "idle", metric.IdlePercent, 5.0/15.0*100)
}

func TestCPUUtilizationRejectsResetCounters(t *testing.T) {
	previous := cpu.TimesStat{User: 100, Idle: 100}
	current := cpu.TimesStat{User: 1, Idle: 1}

	metric := cpuUtilization(previous, current)

	if metric != (protocol.CPUUtilizationMetrics{}) {
		t.Fatalf("metric after counter reset = %+v, want zeros", metric)
	}
}

func TestContainerCPUPercentUsesAllOnlineCPUs(t *testing.T) {
	previous := rawContainer{cpuTotal: 100, systemCPU: 1000, onlineCPUs: 4}
	current := rawContainer{cpuTotal: 200, systemCPU: 1400, onlineCPUs: 4}

	got := containerCPUPercent(previous, current)

	assertClose(t, "container CPU", got, 100)
}

func TestContainerCPUPercentWindowsCounterUnit(t *testing.T) {
	previous := rawContainer{
		readAt:       time.Unix(1, 0),
		cpuTotal:     100,
		cpuUnitNanos: 100,
	}
	current := rawContainer{
		readAt:       time.Unix(2, 0),
		cpuTotal:     1_000_100,
		cpuUnitNanos: 100,
	}

	got := containerCPUPercent(previous, current)

	assertClose(t, "Windows container CPU", got, 10)
}

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()

	if math.Abs(got-want) > 0.0001 {
		t.Fatalf("%s = %f, want %f", name, got, want)
	}
}

func TestCPULimitCores(t *testing.T) {
	tests := []struct {
		name      string
		resources container.Resources
		want      float64
	}{
		{name: "unlimited", resources: container.Resources{}, want: 0},
		{name: "cpus flag", resources: container.Resources{NanoCPUs: 1_500_000_000}, want: 1.5},
		{name: "quota with period", resources: container.Resources{CPUQuota: 50_000, CPUPeriod: 25_000}, want: 2},
		{name: "quota with default period", resources: container.Resources{CPUQuota: 250_000}, want: 2.5},
		{name: "cpuset only", resources: container.Resources{CpusetCpus: "0-2,5"}, want: 4},
		{name: "cpuset tighter than quota", resources: container.Resources{NanoCPUs: 3_000_000_000, CpusetCpus: "1"}, want: 1},
		{name: "quota tighter than cpuset", resources: container.Resources{NanoCPUs: 500_000_000, CpusetCpus: "0-3"}, want: 0.5},
		{name: "malformed cpuset ignored", resources: container.Resources{CpusetCpus: "3-1"}, want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertClose(t, test.name, cpuLimitCores(test.resources), test.want)
		})
	}
}

func TestCPUSetSize(t *testing.T) {
	tests := map[string]int{
		"":          0,
		"0":         1,
		"0-3":       4,
		"0-1,4,6-7": 5,
		"a":         0,
		"-1":        0,
		"1-":        0,
		"0-70000":   0,
	}

	for list, want := range tests {
		if got := cpusetSize(list); got != want {
			t.Errorf("cpusetSize(%q) = %d, want %d", list, got, want)
		}
	}
}

func TestContainerLimitCoresOnlyBelowOnlineCPUs(t *testing.T) {
	tests := []struct {
		name string
		raw  rawContainer
		want *float64
	}{
		{name: "unlimited", raw: rawContainer{onlineCPUs: 4}},
		{name: "limit above online CPUs", raw: rawContainer{onlineCPUs: 4, cpuLimitCores: 8}},
		{name: "limit equal to online CPUs", raw: rawContainer{onlineCPUs: 4, cpuLimitCores: 4}},
		{name: "limit below online CPUs", raw: rawContainer{onlineCPUs: 4, cpuLimitCores: 2}, want: new(2.0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := containerLimitCores(test.raw)
			if (got == nil) != (test.want == nil) || (got != nil && *got != *test.want) {
				t.Fatalf("containerLimitCores() = %v, want %v", got, test.want)
			}
		})
	}
}
