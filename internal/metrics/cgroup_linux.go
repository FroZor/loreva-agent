//go:build linux

package metrics

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/FroZor/loreva-agent/internal/hostfs"
)

// maxCgroupFile bounds one cgroup file; memory.stat is the largest at a few
// KiB.
const maxCgroupFile = 64 * 1024

// findCgroupRoot returns the host's unified cgroup v2 mount, or "" on
// cgroup v1 and hybrid hosts, where containers are read through the
// Docker stats API instead.
func findCgroupRoot() string {
	root := hostfs.Sys("fs", "cgroup")
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return ""
	}

	return root
}

// containerCgroupDir finds the container's cgroup below root. The systemd
// and cgroupfs drivers place it at fixed paths; otherwise the path is taken
// from /proc/<pid>/cgroup when it is not relative to a private namespace.
func containerCgroupDir(root, containerID string, pid int) (string, error) {
	if strings.ContainsAny(containerID, "/.") || containerID == "" {
		return "", errors.New("invalid container ID")
	}

	candidates := []string{
		filepath.Join(root, "system.slice", "docker-"+containerID+".scope"),
		filepath.Join(root, "docker", containerID),
	}
	if data, err := readBounded(hostfs.Proc(strconv.Itoa(pid), "cgroup")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			path, found := strings.CutPrefix(line, "0::")
			if found && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, "..") {
				candidates = append(candidates, filepath.Join(root, path))
			}
		}
	}

	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "cpu.stat")); err == nil {
			return dir, nil
		}
	}

	return "", errors.New("container cgroup not found")
}

// readContainerCgroup reads the container's counters straight from its
// cgroup and, unless it shares the host's network, from the network
// namespace of its main process. It costs dockerd nothing.
func readContainerCgroup(ctx context.Context, root, containerID string, pid int, withNetwork bool) (cgroupReading, error) {
	dir, err := containerCgroupDir(root, containerID, pid)
	if err != nil {
		return cgroupReading{}, err
	}

	reading := cgroupReading{readAt: time.Now().UTC()}

	cpuStat, err := readKeyValues(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return cgroupReading{}, err
	}
	reading.cpuUsageNanos = cpuStat["usage_usec"] * 1000
	reading.throttledPeriods = cpuStat["nr_throttled"]
	reading.throttledSeconds = float64(cpuStat["throttled_usec"]) / 1e6

	if reading.memoryCurrent, err = readUint(filepath.Join(dir, "memory.current")); err != nil {
		return cgroupReading{}, err
	}
	reading.memoryMax, _ = readLimit(filepath.Join(dir, "memory.max"))
	if memoryStat, err := readKeyValues(filepath.Join(dir, "memory.stat")); err == nil {
		reading.inactiveFile = memoryStat["inactive_file"]
		reading.fileBytes = memoryStat["file"]
	}
	if memoryEvents, err := readKeyValues(filepath.Join(dir, "memory.events")); err == nil {
		reading.oomKills = memoryEvents["oom_kill"]
	}

	readIOStat(filepath.Join(dir, "io.stat"), &reading)

	reading.pids, _ = readUint(filepath.Join(dir, "pids.current"))
	reading.pidsLimit, _ = readLimit(filepath.Join(dir, "pids.max"))

	if withNetwork {
		counters, err := gnet.IOCountersByFileWithContext(ctx, true, hostfs.Proc(strconv.Itoa(pid), "net", "dev"))
		if err != nil {
			return cgroupReading{}, fmt.Errorf("read container network: %w", err)
		}
		for _, counter := range counters {
			if counter.Name == "lo" {
				continue
			}
			reading.rxBytes += counter.BytesRecv
			reading.txBytes += counter.BytesSent
			reading.rxPackets += counter.PacketsRecv
			reading.txPackets += counter.PacketsSent
		}
	}

	return reading, nil
}

// readIOStat sums the per-device lines of io.stat, such as
// "8:0 rbytes=1 wbytes=2 rios=3 wios=4 dbytes=0 dios=0".
func readIOStat(path string, reading *cgroupReading) {
	data, err := readBounded(path)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for _, field := range fields[min(1, len(fields)):] {
			key, raw, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				reading.readBytes += value
			case "wbytes":
				reading.writeBytes += value
			case "rios":
				reading.readOps += value
			case "wios":
				reading.writeOps += value
			}
		}
	}
}

func readKeyValues(path string) (map[string]uint64, error) {
	data, err := readBounded(path)
	if err != nil {
		return nil, err
	}

	result := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		if value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64); err == nil {
			result[key] = value
		}
	}

	return result, nil
}

func readUint(path string) (uint64, error) {
	data, err := readBounded(path)
	if err != nil {
		return 0, err
	}

	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// readLimit reads a cgroup limit; "max" means none and returns 0.
func readLimit(path string) (uint64, error) {
	data, err := readBounded(path)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	if value == "max" {
		return 0, nil
	}

	return strconv.ParseUint(value, 10, 64)
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxCgroupFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCgroupFile {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxCgroupFile)
	}

	return data, nil
}
