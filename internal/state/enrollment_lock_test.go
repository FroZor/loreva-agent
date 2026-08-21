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
