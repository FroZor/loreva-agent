package metrics

import (
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

type kernelCounters struct {
	contextSwitches    uint64
	interrupts         uint64
	pageFaults         uint64
	majorPageFaults    uint64
	bootTime           uint64
	hasContextSwitches bool
	hasInterrupts      bool
	hasPageFaults      bool
	hasMajorPageFaults bool
}

// applyKernelRates fills the per-second rates of counters both samples have.
func applyKernelRates(previous, current *kernelCounters, interval time.Duration, cpu *protocol.CPUMetrics, memory *protocol.MemoryMetrics) {
	seconds := interval.Seconds()
	if previous == nil || current == nil || seconds <= 0 {
		return
	}

	perSecond := func(had, has bool, before, after uint64) *float64 {
		if !had || !has {
			return nil
		}
		value := float64(counterDeltaUint(before, after)) / seconds
		return &value
	}
	cpu.ContextSwitchesPerSecond = perSecond(previous.hasContextSwitches, current.hasContextSwitches, previous.contextSwitches, current.contextSwitches)
	cpu.InterruptsPerSecond = perSecond(previous.hasInterrupts, current.hasInterrupts, previous.interrupts, current.interrupts)
	memory.PageFaultsPerSecond = perSecond(previous.hasPageFaults, current.hasPageFaults, previous.pageFaults, current.pageFaults)
	memory.MajorPageFaultsPerSecond = perSecond(previous.hasMajorPageFaults, current.hasMajorPageFaults, previous.majorPageFaults, current.majorPageFaults)
}
