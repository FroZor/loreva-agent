//go:build linux

package procfs

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestParseStatHandlesParenthesesInName(t *testing.T) {
	boot := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	line := "4242 (my (odd) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 7 0 12345 104857600 2560 18446744073709551615"

	process, ok := parseStat([]byte(line), boot, 4096)
	if !ok {
		t.Fatal("stat line was rejected")
	}
	want := Process{
		PID:        4242,
		ParentPID:  1,
		Name:       "my (odd) name",
		State:      StateSleeping,
		StartedAt:  boot.Add(123450 * time.Millisecond),
		CPUSeconds: 3,
		Threads:    7,
		VMSBytes:   104857600,
		RSSBytes:   2560 * 4096,
	}
	if process != want {
		t.Fatalf("process = %+v, want %+v", process, want)
	}
}

func TestNormalizeState(t *testing.T) {
	for code, want := range map[string]string{
		"R": StateRunning, "S": StateSleeping, "D": StateBlocked, "Z": StateZombie,
		"T": StateStopped, "t": StateStopped, "I": StateIdle, "?": StateSleeping,
	} {
		if got := normalizeState(code); got != want {
			t.Errorf("state %q = %q, want %q", code, got, want)
		}
	}
}

func TestContainerIDFromCgroup(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, line := range []string{
		"0::/system.slice/docker-" + id + ".scope\n",
		"12:pids:/docker/" + id + "\n",
	} {
		if got := containerIDPattern.FindStringSubmatch(line); got == nil || got[1] != id {
			t.Errorf("container ID of %q = %v", line, got)
		}
	}
}

func TestCommandLineKeepsArgumentsAndReportsCut(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cmdline")

	if err := os.WriteFile(path, []byte("mysql\x00-p secret\x00--host=db\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments, truncated := readCommandLine(path)
	if truncated || !slices.Equal(arguments, []string{"mysql", "-p secret", "--host=db"}) {
		t.Fatalf("arguments = %q, truncated = %v", arguments, truncated)
	}

	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), maxCommandLine+10), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments, truncated = readCommandLine(path)
	if !truncated || len(arguments) != 1 || len(arguments[0]) != maxCommandLine {
		t.Fatalf("long command line: %d arguments, truncated = %v", len(arguments), truncated)
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if arguments, _ := readCommandLine(path); arguments == nil || len(arguments) != 0 {
		t.Fatalf("kernel thread arguments = %q", arguments)
	}
}
