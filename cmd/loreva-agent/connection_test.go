package main

import (
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/state"
)

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

	time.Sleep(500 * time.Millisecond)
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
