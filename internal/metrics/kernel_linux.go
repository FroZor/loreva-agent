//go:build linux

package metrics

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/hostnet"
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

	if tcp, ok := readTCPCounters(); ok {
		counters.tcp = &tcp
	}

	return counters, true
}

// readTCPCounters reads the host network namespace's TCP counters. The TCP
// MIB counts IPv4 and IPv6 together; sockstat splits sockets in use by
// family, while orphans and TIME-WAIT are shared.
func readTCPCounters() (tcpCounters, bool) {
	var counters tcpCounters

	snmp, err := os.ReadFile(hostnet.NetPath("snmp"))
	if err != nil {
		return counters, false
	}
	sockstat, err := os.ReadFile(hostnet.NetPath("sockstat"))
	if err != nil {
		return counters, false
	}

	mib := tableFields(snmp, "Tcp:")
	counters.established = mib["CurrEstab"]
	counters.activeOpens = mib["ActiveOpens"]
	counters.passiveOpens = mib["PassiveOpens"]
	counters.attemptFails = mib["AttemptFails"]
	counters.resetsSent = mib["OutRsts"]
	counters.retransmitted = mib["RetransSegs"]

	sockets := pairFields(sockstat, "TCP:")
	counters.inUse = sockets["inuse"]
	counters.orphaned = sockets["orphan"]
	counters.timeWait = sockets["tw"]
	if sockstat6, err := os.ReadFile(hostnet.NetPath("sockstat6")); err == nil {
		counters.inUse += pairFields(sockstat6, "TCP6:")["inuse"]
	}

	return counters, true
}

// tableFields reads the /proc/net/snmp layout: a header line of names and
// a value line, both starting with prefix.
func tableFields(data []byte, prefix string) map[string]uint64 {
	fields := make(map[string]uint64)
	var names []string
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, found := strings.CutPrefix(line, prefix)
		if !found {
			continue
		}
		if names == nil {
			names = strings.Fields(rest)
			continue
		}
		for index, value := range strings.Fields(rest) {
			if index >= len(names) {
				break
			}
			// CurrEstab and the like are unsigned; RtoMax may be -1.
			if number, err := strconv.ParseUint(value, 10, 64); err == nil {
				fields[names[index]] = number
			}
		}
		break
	}

	return fields
}

// pairFields reads a sockstat line such as "TCP: inuse 5 orphan 0 tw 2".
func pairFields(data []byte, prefix string) map[string]uint64 {
	fields := make(map[string]uint64)
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, found := strings.CutPrefix(line, prefix)
		if !found {
			continue
		}
		words := strings.Fields(rest)
		for index := 0; index+1 < len(words); index += 2 {
			if number, err := strconv.ParseUint(words[index+1], 10, 64); err == nil {
				fields[words[index]] = number
			}
		}
		break
	}

	return fields
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
