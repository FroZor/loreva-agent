//go:build linux

package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadContainerCgroupReadsCountersWithoutDocker(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "sys")
	proc := filepath.Join(root, "proc")
	t.Setenv("HOST_SYS", sys)
	t.Setenv("HOST_PROC", proc)

	id := "0123456789abcdef"
	dir := filepath.Join(sys, "fs", "cgroup", "system.slice", "docker-"+id+".scope")
	files := map[string]string{
		filepath.Join(sys, "fs", "cgroup", "cgroup.controllers"): "cpu memory io pids\n",
		filepath.Join(dir, "cpu.stat"):                           "usage_usec 2000000\nnr_periods 10\nnr_throttled 3\nthrottled_usec 500000\n",
		filepath.Join(dir, "memory.current"):                     "300\n",
		filepath.Join(dir, "memory.max"):                         "max\n",
		filepath.Join(dir, "memory.stat"):                        "file 50\ninactive_file 100\n",
		filepath.Join(dir, "memory.events"):                      "low 0\nhigh 0\nmax 0\noom 1\noom_kill 2\n",
		filepath.Join(dir, "io.stat"):                            "8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n8:16 rbytes=5 wbytes=5 rios=1 wios=1\n",
		filepath.Join(dir, "pids.current"):                       "4\n",
		filepath.Join(dir, "pids.max"):                           "100\n",
		filepath.Join(proc, "42", "cgroup"):                      "0::/../../system.slice/docker-" + id + ".scope\n",
		filepath.Join(proc, "42", "net", "dev"): "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo:     100       1    0    0    0     0          0         0      100       1    0    0    0     0       0          0\n" +
			"  eth0:    1000      10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0\n",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cgroupRoot := findCgroupRoot()
	if cgroupRoot == "" {
		t.Fatal("cgroup v2 root not found")
	}
	reading, err := readContainerCgroup(t.Context(), cgroupRoot, id, 42, true)
	if err != nil {
		t.Fatal(err)
	}

	if reading.cpuUsageNanos != 2e9 || reading.throttledPeriods != 3 || reading.throttledSeconds != 0.5 {
		t.Errorf("cpu = %+v", reading)
	}
	if reading.readBytes != 15 || reading.writeBytes != 25 || reading.readOps != 2 || reading.writeOps != 3 {
		t.Errorf("io = %+v", reading)
	}
	if reading.rxBytes != 1000 || reading.txBytes != 2000 {
		t.Errorf("network counted loopback: %+v", reading)
	}
	memory := reading.memory(1000)
	if memory.UsedBytes != 200 || memory.LimitBytes != 1000 || memory.UsedPercent != 20 || memory.OOMEventsTotal != 2 {
		t.Errorf("memory = %+v", memory)
	}

	// Two readings a second apart give the rate of one busy core.
	previous := reading.raw(4)
	reading.cpuUsageNanos += 1e9
	reading.readAt = previous.readAt.Add(time.Second)
	if usage := containerCPUPercent(previous, reading.raw(4)); usage != 100 {
		t.Errorf("cpu percent = %v", usage)
	}

	if _, err := readContainerCgroup(t.Context(), cgroupRoot, "../escape", 42, false); err == nil {
		t.Error("a container ID with a path accepted")
	}
}
