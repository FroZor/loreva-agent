package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
)

var version = "dev"

// command is one CLI subcommand.
type command func(arguments []string, logger *slog.Logger) error

// commands maps subcommands to their handlers. "run" is also the default
// when no subcommand is given, which keeps existing service units working.
var commands = map[string]command{
	"run":        runAgent,
	"start":      runStart,
	"enroll":     runEnroll,
	"configure":  runConfigure,
	"init":       runInit,
	"invite":     runInvite,
	"devices":    runDevices,
	"device":     runDevice,
	"connect":    runConnect,
	"disconnect": runDisconnect,
	"status":     runStatus,
	// files-helper runs inside the file helper container.
	"files-helper": runFilesHelper,
}

// setupCommands print human-readable errors to stderr instead of JSON
// service logs on stdout. files-helper is one of them because its stdout
// carries the helper protocol.
var setupCommands = []string{"configure", "enroll", "init", "invite", "devices", "device", "connect", "disconnect", "status", "files-helper"}

func main() {
	arguments := os.Args[1:]
	logger := commandLogger(arguments)

	if err := run(arguments, logger); err != nil {
		if isSetupCommand(arguments) {
			if _, writeErr := fmt.Fprintln(os.Stderr, "Error:", err); writeErr != nil {
				logger.Error("write setup error", "error", writeErr)
			}

			os.Exit(1)
		}

		logger.Error("loreva agent stopped", "error", err)
		os.Exit(1)
	}
}

func commandLogger(arguments []string) *slog.Logger {
	if isSetupCommand(arguments) {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, attribute slog.Attr) slog.Attr {
				if len(groups) == 0 && attribute.Key == slog.TimeKey {
					return slog.Attr{}
				}

				return attribute
			},
		}))
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

func isSetupCommand(arguments []string) bool {
	return len(arguments) > 0 && slices.Contains(setupCommands, arguments[0])
}

func run(arguments []string, logger *slog.Logger) error {
	if len(arguments) == 1 && (arguments[0] == "--version" || arguments[0] == "version") {
		fmt.Println(version)
		return nil
	}

	if len(arguments) == 0 {
		return runAgent(nil, logger)
	}

	handler, found := commands[arguments[0]]
	if found {
		return handler(arguments[1:], logger)
	}
	if arguments[0] != "" && arguments[0][0] == '-' {
		return runAgent(arguments, logger)
	}

	return errors.New("unknown command " + arguments[0] + "; commands: run, init, invite, devices, device, enroll, configure, start, connect, disconnect, status")
}
