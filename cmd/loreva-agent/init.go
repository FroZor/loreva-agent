package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"

	"github.com/FroZor/loreva-agent/internal/direct"
	"github.com/FroZor/loreva-agent/internal/state"
)

const serviceStateDir = "/var/lib/loreva-agent"

func runInit(arguments []string, _ *slog.Logger) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent state directory")
	port := flags.Int("port", 0, "TCP port for devices; default is a free random port in 20000-32000")
	var endpoints []string
	flags.Func("endpoint", "public IP or IP:port to advertise in invites (repeatable)", func(value string) error {
		endpoints = append(endpoints, value)
		return nil
	})

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse init arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("init does not accept positional arguments")
	}

	store, err := state.New(localStateDir(*stateDir))
	if err != nil {
		return err
	}
	if err := store.Claim(); err != nil {
		return err
	}

	node, err := direct.Init(store, direct.InitOptions{ListenPort: *port, Endpoints: endpoints})
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(os.Stdout, "Loreva Agent node initialized.\nNode ID: %s\nTCP port: %d (allow it in the firewall if inbound traffic is filtered)\n"+
		"Next: start the agent, then run `sudo loreva-agent invite` to connect a device.\n", node.NodeID, node.ListenPort)

	return err
}

// localStateDir chooses the state directory for node-local commands. On
// Linux, root defaults to the service directory so `sudo loreva-agent
// invite` reaches the installed agent.
func localStateDir(flagValue string) string {
	if flagValue != "" || os.Getenv("LOREVA_STATE_DIR") != "" {
		return flagValue
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return serviceStateDir
	}

	return ""
}
