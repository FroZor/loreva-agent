// Package metrics collects bounded host telemetry snapshots.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

// Snapshot contains one aggregate host metrics sample.
type Snapshot struct {
	CollectedAt          time.Time `json:"collected_at"`
	CPUPercent           float64   `json:"cpu_percent"`
	MemoryTotalBytes     uint64    `json:"memory_total_bytes"`
	MemoryAvailableBytes uint64    `json:"memory_available_bytes"`
	MemoryUsedBytes      uint64    `json:"memory_used_bytes"`
	MemoryUsedPercent    float64   `json:"memory_used_percent"`
}

// Collector gathers host metrics.
type Collector struct{}

// NewCollector creates a host metrics collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers one aggregate CPU and memory sample.
func (c *Collector) Collect(ctx context.Context) (Snapshot, error) {
	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return Snapshot{}, fmt.Errorf("collect CPU metrics: %w", err)
	}
	if len(cpuPercent) == 0 {
		return Snapshot{}, errors.New("collect CPU metrics: no aggregate value returned")
	}

	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("collect memory metrics: %w", err)
	}

	return Snapshot{
		CollectedAt:          time.Now().UTC(),
		CPUPercent:           cpuPercent[0],
		MemoryTotalBytes:     memory.Total,
		MemoryAvailableBytes: memory.Available,
		MemoryUsedBytes:      memory.Used,
		MemoryUsedPercent:    memory.UsedPercent,
	}, nil
}
