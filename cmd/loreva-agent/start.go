package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/FroZor/loreva-agent/internal/config"
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

	_, err = store.LoadIdentity()
	if err == nil {
		return runAgent([]string{"--state-dir", store.Dir()}, logger)
	}
	if !errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("load enrolled identity: %w", err)
	}

	bootstrap, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	bootstrap.StateDir = store.Dir()

	if err := enrollBootstrap(bootstrap, false, logger); err != nil {
		return err
	}

	return runAgent([]string{"--state-dir", store.Dir()}, logger)
}
