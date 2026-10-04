package metrics

import (
	"math"
	"testing"
	"time"

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

func TestValidateDockerEndpointRejectsUnprotectedTCP(t *testing.T) {
	t.Setenv("DOCKER_TLS_VERIFY", "")

	if err := validateDockerEndpoint("tcp://docker.example:2375"); err == nil {
		t.Fatal("unprotected Docker TCP endpoint was accepted")
	}
}

func TestValidateDockerEndpointAcceptsLocalSocket(t *testing.T) {
	if err := validateDockerEndpoint("unix:///var/run/docker.sock"); err != nil {
		t.Fatal(err)
	}
}

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()

	if math.Abs(got-want) > 0.0001 {
		t.Fatalf("%s = %f, want %f", name, got, want)
	}
}
