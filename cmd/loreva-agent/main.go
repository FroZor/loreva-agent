package main

import (
	"fmt"
	"log/slog"
	"os"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("loreva agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(arguments []string, logger *slog.Logger) error {
	if len(arguments) == 1 && (arguments[0] == "--version" || arguments[0] == "version") {
		fmt.Println(version)
		return nil
	}

	if len(arguments) > 0 && arguments[0] == "enroll" {
		return runEnroll(arguments[1:], logger)
	}

	if len(arguments) > 0 && arguments[0] == "configure" {
		return runConfigure(arguments[1:], logger)
	}

	if len(arguments) > 0 && arguments[0] == "start" {
		return runStart(arguments[1:], logger)
	}

	if len(arguments) > 0 && arguments[0] == "run" {
		arguments = arguments[1:]
	}

	return runAgent(arguments, logger)
}
