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
	"path/filepath"
	"syscall"
	"time"

	"github.com/FroZor/loreva-agent/internal/containerfiles"
	"github.com/FroZor/loreva-agent/internal/containerinfo"
	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/dockerapi"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/metricstore"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/nodeapi"
	"github.com/FroZor/loreva-agent/internal/publicip"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/workload"
)

const (
	metricsInterval       = time.Second
	metricsCollectTimeout = 900 * time.Millisecond
	// metricsMaintenanceInterval is how often the store compacts and writes.
	metricsMaintenanceInterval = 30 * time.Second
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
	if err := store.Claim(); err != nil {
		return err
	}

	processLock, err := store.TryLockProcess()
	if err != nil {
		return err
	}
	defer closeStateLock(processLock, "release agent process lock", logger)

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

	// The portal and paired devices share one metrics store and one workload
	// manager, so they see the same samples and the same containers.
	metricCollector := metrics.NewCollector(ctx)
	defer func() {
		if err := metricCollector.Close(); err != nil {
			logger.Warn("close metrics collector", "error", err)
		}
	}()

	// Every sample goes into the store; each reader reads from its own cursor.
	metricStore, err := metricstore.Open(filepath.Join(store.Dir(), "metrics"))
	if err != nil {
		return err
	}
	logMetricsError := func(err error) { logger.Warn("metrics store", "error", err) }
	for _, warning := range metricStore.LoadWarnings() {
		logMetricsError(warning)
	}
	go metricStore.Collect(ctx, metricCollector.Collect, metricsInterval, metricsCollectTimeout, logMetricsError)

	// Stop maintenance before returning, so its final flush finishes first.
	stopMaintenance := make(chan struct{})
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		metricStore.Run(stopMaintenance, metricsMaintenanceInterval, logMetricsError)
	}()
	defer func() {
		close(stopMaintenance)
		<-maintenanceDone
	}()

	workloadManager, err := workload.New(ctx, workload.Config{StateDir: store.Dir()})
	if err != nil {
		return err
	}
	defer func() {
		if err := workloadManager.Close(); err != nil {
			logger.Warn("close workload manager", "error", err)
		}
	}()

	containers := openContainerServices(ctx, logger)
	defer containers.close()

	collectors := nodeapi.Collectors{
		Specifications: specifications.Collect,
		Network:        networkinfo.NewCollector(publicip.NewResolver(publicip.SettingsFromEnvironment())).Collect,
		Metrics:        metricStore,
		Processes:      metricCollector.InspectProcess,
		Workloads:      workloadManager,
		Containers:     containers.io,
		Files:          containers.files,
		Inventory:      containers.inventory,
		Logger:         logger,
	}

	var services []func(context.Context) error
	if node != nil {
		services = append(services, func(ctx context.Context) error {
			return direct.Run(ctx, store, node, direct.Options{
				Version:        version,
				PortalEnrolled: identity != nil,
				Collectors:     collectors,
				Logger:         logger,
			})
		})
	}
	if identity != nil {
		services = append(services, func(ctx context.Context) error {
			return session.Supervise(ctx, store, collectors, logger)
		})
	}

	return runServices(ctx, services)
}

// containerServices are the Docker-backed services of a session; they are
// nil when the node has no Docker.
type containerServices struct {
	io        nodeapi.ContainerIO
	files     nodeapi.ContainerFiles
	inventory nodeapi.ContainerInventory
	close     func()
}

// openContainerServices connects the container list, logs, consoles, and the
// file manager to Docker. Without Docker the node still runs; container
// requests are then refused.
func openContainerServices(ctx context.Context, logger *slog.Logger) containerServices {
	engine, err := dockerapi.Connect()
	if err != nil {
		logger.Warn("containers, their logs, consoles, and files are unavailable", "error", err)
		return containerServices{close: func() {}}
	}

	files := containerfiles.New(engine, logger)
	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if err := files.RemoveStale(cleanupCtx); err != nil {
		logger.Warn("remove stale file helpers", "error", err)
	}
	cancel()

	return containerServices{
		io:        containerio.New(engine),
		files:     files,
		inventory: containerinfo.New(engine),
		close: func() {
			files.Close()
			if err := engine.Close(); err != nil {
				logger.Warn("close Docker client", "error", err)
			}
		},
	}
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

func closeStateLock(lock *state.Lock, operation string, logger *slog.Logger) {
	if err := lock.Close(); err != nil {
		logger.Warn(operation, "error", err)
	}
}
