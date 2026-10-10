//go:build linux

package specifications

import (
	"slices"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	for value, want := range map[string][]int{
		"0-3":        {0, 1, 2, 3},
		"0,2,4-5\n":  {0, 2, 4, 5},
		"":           nil,
		"7-3,x,9":    {9},
		"0-99999999": nil,
	} {
		if got := parseCPUList(value); !slices.Equal(got, want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestParseCacheSize(t *testing.T) {
	for value, want := range map[string]uint64{"32K": 32768, "36864K": 37748736, "2M": 2097152, "512": 512, "bad": 0} {
		if got := parseCacheSize(value); got != want {
			t.Errorf("parseCacheSize(%q) = %d, want %d", value, got, want)
		}
	}
}

func TestChassisType(t *testing.T) {
	for value, want := range map[string]string{"1": "other", "2": "", "17": "main_server_chassis", "23": "rack_mount_chassis", "99": "", "x": ""} {
		if got := chassisType(value); got != want {
			t.Errorf("chassisType(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestPlaceholderDMIValue(t *testing.T) {
	for _, value := range []string{"To Be Filled By O.E.M.", "Default string", "Not Specified", ""} {
		if !placeholderDMIValue(value) {
			t.Errorf("%q is not treated as a placeholder", value)
		}
	}
	if placeholderDMIValue("Hetzner") {
		t.Error("a real vendor is treated as a placeholder")
	}
}
