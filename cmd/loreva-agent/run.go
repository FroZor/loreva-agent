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

	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
)

// runAgent runs every mode the state directory is set up for: direct access
// when node.json exists and the portal session when identity.json exists.
func runAgent(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent state directory")

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
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("load enrolled identity: %w", err)
	}
	node, err := store.LoadNode()
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("load node identity: %w", err)
	}
	if identity == nil && node == nil {
		return errors.New("agent is not set up; run `loreva-agent init` for direct access or enroll it with a portal")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var services []func(context.Context) error
	if node != nil {
		services = append(services, func(ctx context.Context) error {
			return direct.Run(ctx, store, node, direct.Options{
				Version:        version,
				PortalEnrolled: identity != nil,
				Collectors:     direct.Collectors{Specifications: specifications.Collect, Network: networkinfo.Collect},
				Logger:         logger,
			})
		})
	}
	if identity != nil {
		services = append(services, func(ctx context.Context) error {
			return runPortal(ctx, store, identity, logger)
		})
	}

	return runServices(ctx, services)
}

// runServices runs services until the first one returns, then stops the rest.
func runServices(ctx context.Context, services []func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan error, len(services))
	for _, service := range services {
		go func() { results <- service(ctx) }()
	}

	err := <-results
	cancel()
	for range len(services) - 1 {
		err = errors.Join(err, <-results)
	}

	return err
}

func runPortal(ctx context.Context, store *state.Store, identity *state.Identity, logger *slog.Logger) error {
	runner, err := session.New(store, identity, session.Collectors{
		Specifications: specifications.Collect,
		Network:        networkinfo.Collect,
	})
	if err != nil {
		return err
	}

	err = runner.Run(ctx, session.Events{
		Connected: func(endpoint string) {
			logger.Info("agent connected", "node_id", identity.NodeID, "endpoint", endpoint)
		},
		Retrying: func(retry session.ConnectionRetry) {
			logger.Warn(
				"agent reconnect scheduled",
				"error", retry.Err,
				"retry_in", retry.RetryIn,
			)
		},
		ReportRejected: func(rejection session.NodeReportRejection) {
			if rejection.Retryable {
				logger.Warn(
					"node report rejected; retry scheduled",
					"type", rejection.Type,
					"code", rejection.Code,
					"retry_in", rejection.RetryIn,
				)
				return
			}

			logger.Error(
				"node report rejected; report disabled",
				"type", rejection.Type,
				"code", rejection.Code,
			)
		},
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	if session.IsTerminal(err) {
		logger.Error("agent blocked; operator action is required", "error", err)
		<-ctx.Done()

		return nil
	}

	return err
}
