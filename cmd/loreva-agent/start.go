package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"

	"github.com/FroZor/loreva-agent/internal/config"
	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/state"
)

const defaultContainerBootstrapPath = "/run/secrets/bootstrap.json"

func runStart(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	configPath := flags.String("config", defaultContainerBootstrapPath, "bootstrap JSON file used for first enrollment")
	stateDir := flags.String("state-dir", "", "agent identity directory")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse start arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("start does not accept positional arguments")
	}

	store, err := state.New(*stateDir)
	if err != nil {
		return err
	}
	if err := store.Claim(); err != nil {
		return err
	}

	if err := setUp(store, *configPath, logger); err != nil {
		return err
	}

	return runAgent([]string{"--state-dir", store.Dir()}, logger)
}

// setUp prepares an empty store on the first start: it enrolls with the
// portal bootstrap when one is mounted, and otherwise sets the node up for
// direct access, so `docker compose up` alone is enough.
func setUp(store *state.Store, configPath string, logger *slog.Logger) error {
	configured, err := isConfigured(store)
	if err != nil || configured {
		return err
	}

	bootstrap, err := config.LoadFile(configPath)
	if errors.Is(err, fs.ErrNotExist) {
		return initDirect(store, logger)
	}
	if err != nil {
		return err
	}

	bootstrap.StateDir = store.Dir()

	return enrollBootstrap(bootstrap, false, logger, nil)
}

// isConfigured reports whether the store holds a portal identity or a direct
// access node.
func isConfigured(store *state.Store) (bool, error) {
	_, err := store.LoadIdentity()
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return false, fmt.Errorf("load enrolled identity: %w", err)
	}

	_, err = store.LoadNode()
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return false, fmt.Errorf("load node identity: %w", err)
	}

	return false, nil
}

func initDirect(store *state.Store, logger *slog.Logger) error {
	node, err := direct.Init(store, direct.InitOptions{})
	if err != nil {
		return err
	}

	logger.Info("node initialized for direct access; run `loreva-agent invite` in the agent container to connect a device",
		"node_id", node.NodeID, "tcp_port", node.ListenPort)

	return nil
}
