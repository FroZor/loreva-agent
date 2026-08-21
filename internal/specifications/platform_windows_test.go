//go:build windows

package specifications

import "testing"

func TestWindowsPCIIdentifiers(t *testing.T) {
	vendor, device := windowsPCIIdentifiers(`PCI\VEN_10DE&DEV_2684&SUBSYS_00000000`)
	if vendor != "0x10de" || device != "0x2684" {
		t.Fatalf("vendor=%q device=%q", vendor, device)
	}
}

func TestWindowsMemoryType(t *testing.T) {
	if memoryType := windowsMemoryType(34); memoryType != "DDR5" {
		t.Fatalf("memory type = %q", memoryType)
	}
	if memoryType := windowsMemoryType(0); memoryType != "" {
		t.Fatalf("unknown memory type = %q", memoryType)
	}
}
