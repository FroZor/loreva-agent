package portal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/FroZor/loreva-agent/internal/nodeapi"
	"github.com/FroZor/loreva-agent/internal/state"
)

// Supervise keeps the portal session up while the connection preference is
// enabled, pausing on disconnect and when the identity is rejected.
func Supervise(ctx context.Context, store *state.Store, collectors nodeapi.Collectors, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	for {
		if err := store.WaitUntilConnectionEnabled(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}

			return err
		}

		connectionLock, err := store.LockConnection(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}

			return err
		}

		enabled, err := store.ConnectionEnabled()
		if err != nil {
			closeLock(connectionLock, "release connection lock", logger)
			return err
		}
		if !enabled {
			closeLock(connectionLock, "release connection lock", logger)
			continue
		}

		runErr := runConnection(ctx, store, collectors, connectionLock, logger)
		if runErr == nil || errors.Is(runErr, context.Canceled) {
			if ctx.Err() != nil {
				return nil
			}

			continue
		}
		if IsTerminal(runErr) {
			logger.Error("agent disconnected; configuration is required", "error", runErr)
			if err := store.RequireConfiguration(); err != nil {
				return errors.Join(runErr, err)
			}

			continue
		}

		return runErr
	}
}

func runConnection(
	ctx context.Context,
	store *state.Store,
	collectors nodeapi.Collectors,
	connectionLock *state.Lock,
	logger *slog.Logger,
) error {
	defer closeLock(connectionLock, "release connection lock", logger)

	identity, err := store.LoadIdentity()
	if err != nil {
		return fmt.Errorf("load enrolled identity: %w", err)
	}

	runner, err := New(store, identity, collectors)
	if err != nil {
		return err
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	preferenceResult := make(chan error, 1)
	go watchConnectionPreference(runCtx, store, cancelRun, preferenceResult)

	err = runner.Run(runCtx, sessionEvents(identity, logger))
	cancelRun()
	if preferenceErr := <-preferenceResult; preferenceErr != nil {
		return errors.Join(err, preferenceErr)
	}

	return err
}

func sessionEvents(identity *state.Identity, logger *slog.Logger) Events {
	return Events{
		Connected: func(endpoint string) {
			logger.Info("agent connected", "node_id", identity.NodeID, "endpoint", endpoint)
		},
		Retrying: func(retry ConnectionRetry) {
			logger.Warn(
				"agent reconnect scheduled",
				"error", retry.Err,
				"retry_in", retry.RetryIn,
			)
		},
		ReportRejected: func(rejection nodeapi.NodeReportRejection) {
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
				"node report rejected; request discarded",
				"type", rejection.Type,
				"code", rejection.Code,
			)
		},
	}
}

func watchConnectionPreference(
	ctx context.Context,
	store *state.Store,
	cancelRun context.CancelFunc,
	result chan<- error,
) {
	err := store.WaitUntilConnectionDisabled(ctx)
	if ctx.Err() != nil {
		result <- nil
		return
	}

	cancelRun()
	result <- err
}

func closeLock(lock *state.Lock, operation string, logger *slog.Logger) {
	if err := lock.Close(); err != nil {
		logger.Warn(operation, "error", err)
	}
}
