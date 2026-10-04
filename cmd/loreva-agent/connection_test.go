package main

import (
	"context"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/state"
)

func TestConnectionPreferenceWatcherCancelsActiveRun(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	runCtx, cancelRun := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go watchConnectionPreference(runCtx, store, cancelRun, result)

	if err := store.SetConnectionEnabled(false); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection preference watcher did not stop the active run")
	}

	select {
	case <-runCtx.Done():
	default:
		t.Fatal("connection preference watcher did not cancel the run context")
	}
}

func TestWaitForConnectionRelease(t *testing.T) {
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	lock, err := store.TryLockConnection()
	if err != nil {
		t.Fatal(err)
	}

	released := make(chan error, 1)
	go func() {
		released <- waitForConnectionRelease(store, 2*time.Second)
	}()

	time.Sleep(2 * connectionStatePollInterval)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-released:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection lock release was not observed")
	}
}
