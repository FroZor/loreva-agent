package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/pairing"
)

// runDevice is the reference device client, used for testing and scripting:
//
//	loreva-agent device pair --credentials FILE [--name NAME] < invite
//	loreva-agent device call --credentials FILE [METHOD] PATH
func runDevice(arguments []string, _ *slog.Logger) error {
	if len(arguments) == 0 {
		return errors.New("usage: loreva-agent device pair|call --credentials FILE ...")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch arguments[0] {
	case "pair":
		return runDevicePair(ctx, arguments[1:])
	case "call":
		return runDeviceCall(ctx, arguments[1:])
	default:
		return fmt.Errorf("unknown device command %q", arguments[0])
	}
}

func runDevicePair(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("device pair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	credentialsPath := flags.String("credentials", "", "file to create for this device's credentials")
	name := flags.String("name", "", "device name shown on the node (default: host name)")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse device pair arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("the invite is read from standard input, not from arguments")
	}
	if *credentialsPath == "" {
		return errors.New("--credentials is required")
	}
	deviceName := *name
	if deviceName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return errors.New("could not read the host name; pass --name")
		}

		deviceName = hostname
	}

	encoded, err := readInvite()
	if err != nil {
		return err
	}
	invite, err := pairing.ParseInvite(encoded)
	if err != nil {
		return err
	}

	file, err := client.CreateCredentials(*credentialsPath)
	if err != nil {
		return err
	}

	credentials, err := client.Pair(ctx, invite, client.PairOptions{
		DeviceName: deviceName,
		ShowSAS: func(sas string) {
			fmt.Fprintf(os.Stderr, "Code: %s\nApprove on the node only if it shows the same code. Waiting...\n", sas)
		},
	})
	if err != nil {
		return errors.Join(err, file.Discard())
	}

	if err := file.Write(credentials); err != nil {
		return err
	}

	_, err = fmt.Fprintf(os.Stdout, "Paired with node %s as device %s.\n", credentials.NodeID, credentials.DeviceID)

	return err
}

// readInvite reads the invite without echo from a terminal, or as one line
// from piped input, so it never appears in process arguments.
func readInvite() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Connection key: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read connection key: %w", err)
		}

		return string(secret), nil
	}

	line, err := bufio.NewReader(io.LimitReader(os.Stdin, 8192)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read connection key: %w", err)
	}

	return line, nil
}

func runDeviceCall(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("device call", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	credentialsPath := flags.String("credentials", "", "credentials file created by device pair")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse device call arguments: %w", err)
	}

	method, path := http.MethodGet, ""
	switch flags.NArg() {
	case 1:
		path = flags.Arg(0)
	case 2:
		method, path = strings.ToUpper(flags.Arg(0)), flags.Arg(1)
	default:
		return errors.New("usage: loreva-agent device call --credentials FILE [METHOD] PATH")
	}
	if !strings.HasPrefix(path, "/v1/") {
		return errors.New("path must start with /v1/")
	}

	credentials, err := client.LoadCredentials(*credentialsPath)
	if err != nil {
		return err
	}
	session, err := client.Connect(ctx, credentials)
	if err != nil {
		return err
	}
	defer session.Close()

	body, err := session.Do(ctx, method, path, nil)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(body)

	return err
}
