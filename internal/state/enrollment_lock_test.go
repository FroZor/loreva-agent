package state

import (
	"errors"
	"testing"
)

func TestEnrollmentLockIsExclusiveAndReusable(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.TryLockEnrollment()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.TryLockEnrollment(); !errors.Is(err, ErrEnrollmentLocked) {
		t.Fatalf("second TryLockEnrollment() error = %v, want ErrEnrollmentLocked", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := store.TryLockEnrollment()
	if err != nil {
		t.Fatalf("TryLockEnrollment() after Close error = %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionAndProcessLocksAreIndependent(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	connection, err := store.TryLockConnection()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close connection lock: %v", err)
		}
	}()

	if _, err := store.TryLockConnection(); !errors.Is(err, ErrConnectionActive) {
		t.Fatalf("second TryLockConnection() error = %v, want ErrConnectionActive", err)
	}

	process, err := store.TryLockProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := process.Close(); err != nil {
			t.Errorf("close process lock: %v", err)
		}
	}()

	if _, err := store.TryLockProcess(); !errors.Is(err, ErrAgentRunning) {
		t.Fatalf("second TryLockProcess() error = %v, want ErrAgentRunning", err)
	}
}
