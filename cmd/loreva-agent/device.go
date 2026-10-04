package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/FroZor/loreva-agent/internal/client"
	"github.com/FroZor/loreva-agent/internal/pairing"
)

const (
	maxInviteLine = 8 * 1024
	// maxSidecarLine bounds one frame on standard input; the node accepts
	// frames up to 64 KiB.
	maxSidecarLine = 64 * 1024
)

// Sidecar events on standard output, besides the node's own frames.
const (
	sidecarPairingCode      = "pairing.code"
	sidecarPairingCompleted = "pairing.completed"
	sidecarError            = "sidecar.error"
)

// runDevice is the device side of direct access. Loreva App runs it as a
// sidecar process and talks JSON lines over standard input and output, so
// the tunnel, the pairing cryptography, and the session live in this
// binary and the app opens no network port:
//
//	loreva-agent device pair --credentials FILE [--name NAME] < key
//	loreva-agent device pair --json [--name NAME] < key
//	loreva-agent device connect --credentials FILE|-
func runDevice(arguments []string, _ *slog.Logger) error {
	if len(arguments) == 0 {
		return errors.New("usage: loreva-agent device pair|connect ...")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch arguments[0] {
	case "pair":
		return runDevicePair(ctx, arguments[1:])
	case "connect":
		return runDeviceConnect(ctx, arguments[1:])
	default:
		return fmt.Errorf("unknown device command %q", arguments[0])
	}
}

type sidecarEvent struct {
	Type        string              `json:"type"`
	Code        string              `json:"code,omitempty"`
	Message     string              `json:"message,omitempty"`
	Credentials *client.Credentials `json:"credentials,omitempty"`
}

func runDevicePair(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("device pair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	credentialsPath := flags.String("credentials", "", "file to create for this device's credentials")
	name := flags.String("name", "", "device name shown on the node (default: host name)")
	jsonOutput := flags.Bool("json", false, "print JSON events, including the credentials, instead of writing a file")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse device pair arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("the connection key is read from standard input, not from arguments")
	}
	if (*credentialsPath == "") == !*jsonOutput {
		return errors.New("pass exactly one of --credentials FILE and --json")
	}
	deviceName := *name
	if deviceName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return errors.New("could not read the host name; pass --name")
		}

		deviceName = hostname
	}

	if *jsonOutput {
		err := pairAndPrint(ctx, deviceName, json.NewEncoder(os.Stdout))
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(sidecarEvent{Type: sidecarError, Code: errorCode(err), Message: err.Error()})
		}

		return err
	}

	return pairToFile(ctx, deviceName, *credentialsPath)
}

func pairAndPrint(ctx context.Context, deviceName string, output *json.Encoder) error {
	invite, err := readInvite()
	if err != nil {
		return err
	}

	credentials, err := client.Pair(ctx, invite, client.PairOptions{
		DeviceName: deviceName,
		ShowSAS: func(sas string) {
			_ = output.Encode(sidecarEvent{Type: sidecarPairingCode, Code: sas})
		},
	})
	if err != nil {
		return err
	}

	return output.Encode(sidecarEvent{Type: sidecarPairingCompleted, Credentials: credentials})
}

func pairToFile(ctx context.Context, deviceName, path string) error {
	invite, err := readInvite()
	if err != nil {
		return err
	}

	file, err := client.CreateCredentials(path)
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

// readInvite reads the connection key without echo from a terminal, or as
// one line from piped input, so it never appears in process arguments.
func readInvite() (*pairing.Invite, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Connection key: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read connection key: %w", err)
		}

		return pairing.ParseInvite(string(secret))
	}

	line, err := bufio.NewReader(io.LimitReader(os.Stdin, maxInviteLine)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read connection key: %w", err)
	}

	return pairing.ParseInvite(line)
}

// runDeviceConnect bridges standard input and output to a device session:
// every line on standard input is one frame to the node, and every frame
// from the node is one line on standard output, starting with session.hello.
// With --credentials - the first input line is the credentials JSON, so an
// app can keep it in the operating system keychain instead of a file.
func runDeviceConnect(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("device connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	credentialsPath := flags.String("credentials", "", "credentials file created by device pair, or - for standard input")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse device connect arguments: %w", err)
	}
	if flags.NArg() != 0 || *credentialsPath == "" {
		return errors.New("usage: loreva-agent device connect --credentials FILE|-")
	}

	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 0, 4096), maxSidecarLine)

	credentials, err := loadSidecarCredentials(*credentialsPath, input)
	if err != nil {
		return err
	}

	session, err := client.Connect(ctx, credentials)
	if err != nil {
		return err
	}
	defer session.Close()

	return bridge(ctx, session, input, os.Stdout)
}

func loadSidecarCredentials(path string, input *bufio.Scanner) (*client.Credentials, error) {
	if path != "-" {
		return client.LoadCredentials(path)
	}

	if !input.Scan() {
		return nil, errors.Join(errors.New("expected credentials JSON on the first input line"), input.Err())
	}

	return client.ParseCredentials(input.Bytes())
}

// bridge copies frames in both directions until either side closes.
func bridge(ctx context.Context, session *client.Session, input *bufio.Scanner, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	hello, err := json.Marshal(session.Hello)
	if err != nil {
		return err
	}
	if _, err := output.Write(append(hello, '\n')); err != nil {
		return err
	}

	inputDone := make(chan error, 1)
	go func() {
		for input.Scan() {
			if err := session.Write(ctx, input.Bytes()); err != nil {
				inputDone <- err
				return
			}
		}

		inputDone <- input.Err()
	}()

	frames := make(chan []byte)
	readDone := make(chan error, 1)
	go func() {
		for {
			frame, err := session.Read(ctx)
			if err != nil {
				readDone <- err
				return
			}

			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-inputDone:
			// The app closed standard input: it is done with the session.
			return err
		case err := <-readDone:
			return fmt.Errorf("node session ended: %w", err)
		case frame := <-frames:
			var line bytes.Buffer
			if err := json.Compact(&line, frame); err != nil {
				return fmt.Errorf("node sent a frame that is not valid JSON: %w", err)
			}
			line.WriteByte('\n')

			if _, err := output.Write(line.Bytes()); err != nil {
				return err
			}
		}
	}
}

func errorCode(err error) string {
	if remote, ok := errors.AsType[*client.RemoteError](err); ok {
		return remote.Code
	}

	switch {
	case errors.Is(err, client.ErrPairingRejected):
		return "pairing_rejected"
	case errors.Is(err, client.ErrPairingExpired):
		return "pairing_expired"
	default:
		return "failed"
	}
}
