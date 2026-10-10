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
	tcp                *tcpCounters
}

// tcpCounters are read from the TCP MIB (/proc/net/snmp) and socket
// statistics (/proc/net/sockstat and sockstat6) of the host's network
// namespace.
type tcpCounters struct {
	established   uint64
	timeWait      uint64
	orphaned      uint64
	inUse         uint64
	activeOpens   uint64
	passiveOpens  uint64
	attemptFails  uint64
	resetsSent    uint64
	retransmitted uint64
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

// tcpMetrics reports TCP gauges with rates over the interval; it is nil
// until both samples have read the TCP counters.
func tcpMetrics(previous, current *kernelCounters, interval time.Duration) *protocol.TCPMetrics {
	seconds := interval.Seconds()
	if previous == nil || current == nil || previous.tcp == nil || current.tcp == nil || seconds <= 0 {
		return nil
	}

	before, after := previous.tcp, current.tcp
	perSecond := func(before, after uint64) float64 {
		return float64(counterDeltaUint(before, after)) / seconds
	}

	return &protocol.TCPMetrics{
		Established:                    after.established,
		TimeWait:                       after.timeWait,
		Orphaned:                       after.orphaned,
		InUse:                          after.inUse,
		ActiveOpensPerSecond:           perSecond(before.activeOpens, after.activeOpens),
		PassiveOpensPerSecond:          perSecond(before.passiveOpens, after.passiveOpens),
		FailedAttemptsPerSecond:        perSecond(before.attemptFails, after.attemptFails),
		ResetsSentPerSecond:            perSecond(before.resetsSent, after.resetsSent),
		RetransmittedSegmentsPerSecond: perSecond(before.retransmitted, after.retransmitted),
	}
}
