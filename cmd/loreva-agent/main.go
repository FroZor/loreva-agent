package main

import (
	"fmt"
	"log/slog"
	"os"
)

var version = "dev"

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
	return len(arguments) > 0 && (arguments[0] == "configure" || arguments[0] == "enroll")
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
