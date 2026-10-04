package state

import "testing"

func TestConnectionPreferenceDefaultsToEnabledAndPersists(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	enabled, err := store.ConnectionEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("new state directory disabled connections")
	}

	if err := store.SetConnectionEnabled(false); err != nil {
		t.Fatal(err)
	}

	enabled, err = store.ConnectionEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("disabled connection preference was not persisted")
	}

	if err := store.CompleteConfiguration(); err != nil {
		t.Fatal(err)
	}

	mode, err := store.ConnectionMode()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ConnectionModeDisconnected {
		t.Fatalf("CompleteConfiguration() mode = %q, want disconnected", mode)
	}

	if err := store.SetConnectionEnabled(true); err != nil {
		t.Fatal(err)
	}

	enabled, err = store.ConnectionEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("enabled connection preference was not persisted")
	}

	if err := store.RequireConfiguration(); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteConfiguration(); err != nil {
		t.Fatal(err)
	}

	mode, err = store.ConnectionMode()
	if err != nil {
		t.Fatal(err)
	}
	if mode != ConnectionModeEnabled {
		t.Fatalf("CompleteConfiguration() mode = %q, want enabled", mode)
	}
}
