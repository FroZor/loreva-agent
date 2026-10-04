package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/FroZor/loreva-agent/internal/state"
)

const connectionStatePollInterval = 250 * time.Millisecond

func runDisconnect(arguments []string) error {
	store, err := connectionCommandStore("disconnect", arguments)
	if err != nil {
		return err
	}
	if _, err := store.LoadIdentity(); err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return errors.New("agent is not configured")
		}

		return fmt.Errorf("load enrolled identity: %w", err)
	}

	if err := store.SetConnectionEnabled(false); err != nil {
		return err
	}
	if err := waitForConnectionRelease(store, 10*time.Second); err != nil {
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, "Loreva Agent disconnected.")
	return err
}

func runConnect(arguments []string) error {
	store, err := connectionCommandStore("connect", arguments)
	if err != nil {
		return err
	}
	if _, err := store.LoadIdentity(); err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return errors.New("agent is not configured; run configure first")
		}

		return fmt.Errorf("load enrolled identity: %w", err)
	}

	if err := store.SetConnectionEnabled(true); err != nil {
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, "Loreva Agent connection enabled.")
	return err
}

func runStatus(arguments []string) error {
	store, err := connectionCommandStore("status", arguments)
	if err != nil {
		return err
	}

	identity, identityErr := store.LoadIdentity()
	if identityErr != nil && !errors.Is(identityErr, state.ErrNotFound) {
		return fmt.Errorf("load enrolled identity: %w", identityErr)
	}

	mode, err := store.ConnectionMode()
	if err != nil {
		return err
	}

	running, err := agentProcessRunning(store)
	if err != nil {
		return err
	}

	status := "unconfigured"
	if identityErr == nil {
		status = "stopped"
		if mode == state.ConnectionModeRequiresConfiguration {
			status = "requires_configuration"
		} else if running && mode == state.ConnectionModeEnabled {
			status = "running"
		} else if mode == state.ConnectionModeDisconnected {
			status = "disconnected"
		}
	}

	if _, err := fmt.Fprintf(os.Stdout, "Status: %s\n", status); err != nil {
		return fmt.Errorf("write agent status: %w", err)
	}
	if identity != nil {
		if _, err := fmt.Fprintf(os.Stdout, "Node ID: %s\nPortal: %s\n", identity.NodeID, identity.PortalURL); err != nil {
			return fmt.Errorf("write agent identity status: %w", err)
		}
	}

	return nil
}

func connectionCommandStore(command string, arguments []string) (*state.Store, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent identity directory")
	if err := flags.Parse(arguments); err != nil {
		return nil, fmt.Errorf("parse %s arguments: %w", command, err)
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("%s does not accept positional arguments", command)
	}

	return state.New(*stateDir)
}

func waitForConnectionRelease(store *state.Store, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(connectionStatePollInterval)
	defer ticker.Stop()

	for {
		lock, err := store.TryLockConnection()
		if err == nil {
			return lock.Close()
		}
		if !errors.Is(err, state.ErrConnectionActive) {
			return err
		}

		select {
		case <-ctx.Done():
			return errors.New("agent did not stop its connection within 10 seconds")
		case <-ticker.C:
		}
	}
}

func agentProcessRunning(store *state.Store) (bool, error) {
	lock, err := store.TryLockProcess()
	if err == nil {
		return false, lock.Close()
	}
	if errors.Is(err, state.ErrAgentRunning) {
		return true, nil
	}

	return false, err
}
