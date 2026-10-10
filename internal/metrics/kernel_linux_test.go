//go:build linux

package metrics

import "testing"

func TestCounterFieldsTakesFirstNumber(t *testing.T) {
	fields := counterFields([]byte("cpu  1 2 3\nintr 9001 0 5 7\nctxt 123456\nbtime 1700000000\n"))

	for key, want := range map[string]uint64{"intr": 9001, "ctxt": 123456, "btime": 1700000000, "cpu": 1} {
		if fields[key] != want {
			t.Errorf("%s = %d, want %d", key, fields[key], want)
		}
	}
}

func TestTCPCounterTablesAreParsed(t *testing.T) {
	snmp := []byte("Ip: Forwarding DefaultTTL\nIp: 1 64\n" +
		"Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n" +
		"Tcp: 1 200 120000 -1 4174 812 58 101 12 919 892 31 0 77 0\n")
	mib := tableFields(snmp, "Tcp:")
	if mib["CurrEstab"] != 12 || mib["ActiveOpens"] != 4174 || mib["RetransSegs"] != 31 || mib["OutRsts"] != 77 {
		t.Fatalf("TCP MIB = %v", mib)
	}
	if _, found := mib["MaxConn"]; found {
		t.Fatal("MaxConn -1 is not a counter")
	}

	sockstat := []byte("sockets: used 140\nTCP: inuse 9 orphan 1 tw 4 alloc 11 mem 2\nUDP: inuse 3 mem 1\n")
	sockets := pairFields(sockstat, "TCP:")
	if sockets["inuse"] != 9 || sockets["orphan"] != 1 || sockets["tw"] != 4 {
		t.Fatalf("sockstat = %v", sockets)
	}
}
