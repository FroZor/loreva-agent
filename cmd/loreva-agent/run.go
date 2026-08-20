package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/state"
)

func runAgent(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent identity directory")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse run arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("run does not accept positional arguments")
	}

	store, err := state.New(*stateDir)
	if err != nil {
		return err
	}

	identity, err := store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("load enrolled identity: %w", err)
	}

	runner, err := session.New(store, identity)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = runner.Run(ctx, func(endpoint string) {
		logger.Info("agent connected", "node_id", identity.NodeID, "endpoint", endpoint)
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}
