//go:build windows

package specifications

import (
	"context"
	"testing"
	"time"
)

func TestReadWindowsSpecificationsCapturesOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	document, err := readWindowsSpecifications(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if document.Memory == nil || document.GPUs == nil || document.Storage == nil || document.Network == nil {
		t.Fatal("Windows collector returned null collections")
	}
}

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
