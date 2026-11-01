package state

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLockConnectionWaitsForRelease(t *testing.T) {
	store := newWaitTestStore(t)

	held, err := store.TryLockConnection()
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan error, 1)
	go func() {
		lock, err := store.LockConnection(t.Context())
		if err == nil {
			err = lock.Close()
		}
		acquired <- err
	}()

	select {
	case err := <-acquired:
		t.Fatalf("lock acquired while held: %v", err)
	case <-time.After(2 * pollInterval):
	}

	if err := held.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection lock release was not observed")
	}
}

func TestLockConnectionStopsWithContext(t *testing.T) {
	store := newWaitTestStore(t)

	held, err := store.TryLockConnection()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 2*pollInterval)
	defer cancel()

	if _, err := store.LockConnection(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LockConnection() error = %v, want deadline exceeded", err)
	}
}

func TestWaitUntilConnectionDisabled(t *testing.T) {
	store := newWaitTestStore(t)

	disabled := make(chan error, 1)
	go func() {
		disabled <- store.WaitUntilConnectionDisabled(t.Context())
	}()

	if err := store.SetConnectionEnabled(false); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-disabled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disabled connection was not observed")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*pollInterval)
	defer cancel()

	if err := store.WaitUntilConnectionEnabled(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("WaitUntilConnectionEnabled() returned for a disabled connection")
	}
}

func TestAgentRunning(t *testing.T) {
	store := newWaitTestStore(t)

	running, err := store.AgentRunning()
	if err != nil {
		t.Fatal(err)
	}
	if running {
		t.Fatal("AgentRunning() = true without a process lock")
	}

	lock, err := store.TryLockProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	running, err = store.AgentRunning()
	if err != nil {
		t.Fatal(err)
	}
	if !running {
		t.Fatal("AgentRunning() = false while the process lock is held")
	}
}

func newWaitTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return store
}
