//go:build linux

package metrics

import (
	"bufio"
	"bytes"
	"os"
	"strconv"

	"github.com/FroZor/loreva-agent/internal/hostfs"
)

// readKernelCounters reads scheduler and paging counters. gopsutil is not
// used for page faults: it scales the pgfault event counts by 4096 as if
// they were bytes.
func readKernelCounters() (kernelCounters, bool) {
	var counters kernelCounters

	stat, err := os.ReadFile(hostfs.Proc("stat"))
	if err != nil {
		return counters, false
	}
	vmstat, err := os.ReadFile(hostfs.Proc("vmstat"))
	if err != nil {
		return counters, false
	}

	fields := counterFields(stat)
	counters.contextSwitches, counters.hasContextSwitches = fields["ctxt"]
	counters.interrupts, counters.hasInterrupts = fields["intr"]
	counters.bootTime = fields["btime"]

	fields = counterFields(vmstat)
	counters.pageFaults, counters.hasPageFaults = fields["pgfault"]
	counters.majorPageFaults, counters.hasMajorPageFaults = fields["pgmajfault"]

	return counters, true
}

// counterFields maps the first number after each line's key, which is the
// total for /proc/stat's "intr" line.
func counterFields(data []byte) map[string]uint64 {
	fields := make(map[string]uint64)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		key, rest, found := bytes.Cut(scanner.Bytes(), []byte(" "))
		if !found {
			continue
		}
		value, _, _ := bytes.Cut(bytes.TrimLeft(rest, " "), []byte(" "))
		number, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			continue
		}
		fields[string(key)] = number
	}

	return fields
}
