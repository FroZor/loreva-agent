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
