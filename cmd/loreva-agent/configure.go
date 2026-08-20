package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/FroZor/loreva-agent/internal/config"
)

func runConfigure(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	encoded := flags.String("bootstrap", "", "portal-issued padded Base64 bootstrap")
	resetPending := flags.Bool("reset-pending", false, "discard an incomplete enrollment before retrying")
	stateDir := flags.String("state-dir", "", "agent identity directory")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse configure arguments: %w", err)
	}
	if flags.NArg() != 0 || *encoded == "" {
		return errors.New("configure requires exactly --bootstrap <base64>")
	}

	bootstrap, err := config.LoadServerBootstrap(*encoded)
	if err != nil {
		return err
	}

	if *stateDir != "" {
		bootstrap.StateDir = *stateDir
	}

	return enrollBootstrap(bootstrap, *resetPending, logger)
}
