package metricstore

import (
	"sort"
	"strings"

	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

// Series keys are "<metric>" for the node or "<metric>@<subject>" for one
// disk, file system, interface or container. Metric names never contain
// "@", so the key splits at the first one whatever the subject holds.
const subjectSeparator = "@"

// Units of key series.
const (
	unitPercent        = "%"
	unitBytes          = "B"
	unitBytesPerSecond = "B/s"
	unitNone           = ""
)

// Series is one key series in a sample: its value and what describes it.
type Series struct {
	Column protocol.MetricColumn
	Value  float64
	// container marks a container series, whose history column waits until
	// the container has lived a while.
	container bool
}

// signal is a value the event detector watches without storing it.
type signal struct {
	key   string
	name  string
	value float64
}

// KeySeries extracts the series kept in history from a sample, in a stable
// order: node series first, then containers by identity. Everything else in
// the sample (each CPU, processes, sensors, errors) is only shown live.
func KeySeries(snapshot *metrics.Snapshot) []Series {
	series, _ := keySeries(snapshot)

	return series
}

func keySeries(snapshot *metrics.Snapshot) ([]Series, []signal) {
	node := snapshot.Node
	var result []Series
	var signals []signal
	add := func(key, unit string, value float64, describe func(*protocol.MetricColumn)) {
		column := protocol.MetricColumn{Key: key, Unit: unit}
		if describe != nil {
			describe(&column)
		}
		result = append(result, Series{Column: column, Value: value})
	}

	add("cpu.usage_percent", unitPercent, node.CPU.Total.UsagePercent, nil)
	add("cpu.iowait_percent", unitPercent, node.CPU.Total.IOWaitPercent, nil)
	add("cpu.steal_percent", unitPercent, node.CPU.Total.StealPercent, nil)
	if node.CPU.LoadAverage != nil {
		add("load.1m", unitNone, node.CPU.LoadAverage.OneMinute, nil)
	}

	memoryTotal := node.Memory.TotalBytes
	add("memory.used_bytes", unitBytes, float64(node.Memory.UsedBytes), func(column *protocol.MetricColumn) {
		column.TotalBytes = optional(memoryTotal)
	})
	if memoryTotal > 0 {
		add("memory.used_percent", unitPercent, float64(node.Memory.UsedBytes)/float64(memoryTotal)*100, nil)
	}
	add("swap.used_bytes", unitBytes, float64(node.Memory.SwapUsedBytes), func(column *protocol.MetricColumn) {
		column.TotalBytes = optional(node.Memory.SwapTotalBytes)
	})
	if node.TCP != nil {
		add("tcp.established", unitNone, float64(node.TCP.Established), nil)
	}

	disks := make(map[string]struct{}, len(snapshot.Disks))
	for _, id := range snapshot.Disks {
		disks[id] = struct{}{}
	}
	for _, device := range node.Storage.Devices {
		if _, key := disks[device.DeviceID]; !key {
			continue
		}
		subject := subjectSeparator + device.DeviceID
		add("disk.read_bytes_per_second"+subject, unitBytesPerSecond, device.ReadBytesPerSecond, nil)
		add("disk.write_bytes_per_second"+subject, unitBytesPerSecond, device.WriteBytesPerSecond, nil)
		add("disk.io_utilization_percent"+subject, unitPercent, device.IOUtilizationPercent, nil)
	}

	for _, filesystem := range node.Storage.Filesystems {
		add("fs.used_percent"+subjectSeparator+filesystem.Mountpoint, unitPercent, filesystem.UsedPercent, func(column *protocol.MetricColumn) {
			column.Name = filesystem.Mountpoint
			column.TotalBytes = optional(filesystem.TotalBytes)
		})
	}

	for _, network := range node.Network {
		name, key := snapshot.Interfaces[network.InterfaceID]
		if !key {
			continue
		}
		describe := func(column *protocol.MetricColumn) { column.Name = name }
		add("net.rx_bytes_per_second"+subjectSeparator+name, unitBytesPerSecond, network.RXBytesPerSecond, describe)
		add("net.tx_bytes_per_second"+subjectSeparator+name, unitBytesPerSecond, network.TXBytesPerSecond, describe)
	}

	containers := make([]protocol.ContainerMetrics, len(snapshot.Containers))
	copy(containers, snapshot.Containers)
	identity := func(container protocol.ContainerMetrics) string {
		if key := snapshot.ContainerKeys[container.ContainerID]; key != "" {
			return key
		}

		return "id:" + container.ContainerID
	}
	sort.Slice(containers, func(left, right int) bool { return identity(containers[left]) < identity(containers[right]) })

	var totalCPU, totalMemory float64
	for _, container := range containers {
		totalCPU += container.CPU.UsagePercent
		totalMemory += float64(container.Memory.UsedBytes)
	}
	if len(containers) > 0 {
		add("containers.cpu_percent", unitPercent, totalCPU, nil)
		add("containers.memory_used_bytes", unitBytes, totalMemory, nil)
	}

	for _, container := range containers {
		subject := identity(container)
		describe := func(column *protocol.MetricColumn) {
			column.ContainerID = container.ContainerID
			column.Name = container.Name
		}
		first := len(result)
		add("container.cpu_percent@"+subject, unitPercent, container.CPU.UsagePercent, func(column *protocol.MetricColumn) {
			describe(column)
			column.LimitCores = container.CPU.LimitCores
		})
		add("container.memory_used_bytes@"+subject, unitBytes, float64(container.Memory.UsedBytes), func(column *protocol.MetricColumn) {
			describe(column)
			column.TotalBytes = optional(container.Memory.LimitBytes)
		})
		add("container.rx_bytes_per_second@"+subject, unitBytesPerSecond, container.Network.RXBytesPerSecond, describe)
		add("container.tx_bytes_per_second@"+subject, unitBytesPerSecond, container.Network.TXBytesPerSecond, describe)
		add("container.read_bytes_per_second@"+subject, unitBytesPerSecond, container.Storage.ReadBytesPerSecond, describe)
		add("container.write_bytes_per_second@"+subject, unitBytesPerSecond, container.Storage.WriteBytesPerSecond, describe)
		for index := first; index < len(result); index++ {
			result[index].container = true
		}

		if container.Memory.LimitBytes > 0 && container.Memory.LimitBytes < memoryTotal {
			signals = append(signals, signal{key: "container.memory_used_percent@" + subject, name: container.Name, value: container.Memory.UsedPercent})
		}
	}

	return result, signals
}

// SplitKey returns the metric and the subject of a series key.
func SplitKey(key string) (metric, subject string) {
	metric, subject, _ = strings.Cut(key, subjectSeparator)

	return metric, subject
}

func optional(value uint64) *uint64 {
	if value == 0 {
		return nil
	}

	return &value
}
