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
	"time"

	"github.com/FroZor/loreva-agent/internal/config"
	"github.com/FroZor/loreva-agent/internal/enrollment"
	"github.com/FroZor/loreva-agent/internal/state"
)

func runEnroll(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	portal := flags.String("portal", "", "portal WSS base URL")
	token := flags.String("token", "", "short-lived enrollment token")
	portalCAPath := flags.String("portal-ca", "", "PEM certificate file for a self-hosted portal")
	allowDevelopmentWS := flags.Bool("allow-development-ws", false, "allow ws:// only for a loopback development portal")
	stateDir := flags.String("state-dir", "", "agent identity directory")
	configPath := flags.String("config", "", "bootstrap JSON file")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse enroll arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("enroll does not accept positional arguments")
	}

	encodedConfig := os.Getenv("LOREVA_CONFIG_BASE64")
	usingFlags := *portal != "" || *token != "" || *portalCAPath != "" || *allowDevelopmentWS
	configuredInputs := 0

	if usingFlags {
		configuredInputs++
	}
	if *configPath != "" {
		configuredInputs++
	}
	if encodedConfig != "" {
		configuredInputs++
	}

	if configuredInputs != 1 {
		return errors.New("use exactly one bootstrap source: --portal/--token, --config, or LOREVA_CONFIG_BASE64")
	}

	bootstrap := &config.Bootstrap{
		PortalURL:          *portal,
		EnrollmentToken:    *token,
		StateDir:           *stateDir,
		AllowDevelopmentWS: *allowDevelopmentWS,
	}

	var err error

	if *configPath != "" {
		if *configPath == "-" {
			bootstrap, err = config.LoadReader(os.Stdin)
		} else {
			bootstrap, err = config.LoadFile(*configPath)
		}
	} else if encodedConfig != "" {
		bootstrap, err = config.LoadBase64(encodedConfig)
	} else if *portalCAPath != "" {
		bootstrap.PortalCA, err = config.LoadPortalCA(*portalCAPath)
	}

	if err != nil {
		return err
	}

	if *stateDir != "" {
		bootstrap.StateDir = *stateDir
	}

	return enrollBootstrap(bootstrap, false, logger, os.Stdout)
}

func enrollBootstrap(bootstrap *config.Bootstrap, replaceIdentity bool, logger *slog.Logger, output io.Writer) error {
	if bootstrap == nil {
		return errors.New("bootstrap config is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	identity, err := enrollment.Enroll(ctx, enrollment.Options{
		PortalURL:          bootstrap.PortalURL,
		Token:              bootstrap.EnrollmentToken,
		PortalCAPEM:        bootstrap.PortalCA,
		StateDir:           bootstrap.StateDir,
		Version:            version,
		AllowDevelopmentWS: bootstrap.AllowDevelopmentWS,
		ReplaceIdentity:    replaceIdentity,
		OnRetry: func(err error, delay time.Duration) {
			logger.Warn("agent enrollment retry", "error", err, "retry_in", delay.String())
		},
		OnWarning: func(err error) {
			logger.Warn("agent enrollment warning", "error", err)
		},
	})
	if err != nil {
		return err
	}

	store, err := state.New(bootstrap.StateDir)
	if err != nil {
		return err
	}
	if err := store.CompleteConfiguration(); err != nil {
		return fmt.Errorf("identity configured but connection state was not updated: %w", err)
	}

	if output == nil {
		logger.Info("agent enrollment completed", "node_id", identity.NodeID, "state_dir", store.Dir())
		return nil
	}

	if err := writeEnrollmentResult(output, identity.NodeID); err != nil {
		logger.Warn("write enrollment result", "error", err)
	}

	return nil
}

func writeEnrollmentResult(output io.Writer, nodeID string) error {
	if _, err := fmt.Fprintf(output, "Loreva Agent configured successfully.\nNode ID: %s\n", nodeID); err != nil {
		return fmt.Errorf("write enrollment result: %w", err)
	}

	return nil
}
