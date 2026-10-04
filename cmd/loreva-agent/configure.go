package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/FroZor/loreva-agent/internal/config"
	"golang.org/x/term"
)

func runConfigure(arguments []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	encoded := flags.String("bootstrap", "", "use - to read the portal bootstrap from stdin")
	stateDir := flags.String("state-dir", "", "agent identity directory")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse configure arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("configure does not accept positional arguments")
	}

	bootstrap, err := loadPortalBootstrap(*encoded)
	if err != nil {
		return err
	}

	if *stateDir != "" {
		bootstrap.StateDir = *stateDir
	}

	return enrollBootstrap(bootstrap, true, logger, os.Stdout)
}

func loadPortalBootstrap(encoded string) (*config.Bootstrap, error) {
	if encoded == "-" {
		return config.LoadServerBootstrapReader(os.Stdin)
	}
	if encoded != "" {
		return nil, errors.New("bootstrap values are not accepted in process arguments; use --bootstrap -")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("configure requires an interactive terminal or --bootstrap -")
	}

	if _, err := fmt.Fprint(os.Stderr, "Portal bootstrap: "); err != nil {
		return nil, fmt.Errorf("write bootstrap prompt: %w", err)
	}

	secret, readErr := term.ReadPassword(int(os.Stdin.Fd()))
	_, newlineErr := fmt.Fprintln(os.Stderr)
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read portal bootstrap: %w", readErr), newlineErr)
	}
	if newlineErr != nil {
		return nil, fmt.Errorf("finish bootstrap prompt: %w", newlineErr)
	}

	return config.LoadServerBootstrap(string(secret))
}
