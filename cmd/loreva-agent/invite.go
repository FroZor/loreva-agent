package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/state"
)

func runInvite(arguments []string, _ *slog.Logger) error {
	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent state directory")
	ttl := flags.Duration("ttl", 15*time.Minute, "invite lifetime, from 1m to 1h")
	noConfirm := flags.Bool("no-confirm", false, "approve the first device without comparing codes (automation only; weaker)")
	var endpoints []string
	flags.Func("endpoint", "public IP or IP:port to put first in the invite (repeatable)", func(value string) error {
		endpoints = append(endpoints, value)
		return nil
	})

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse invite arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("invite does not accept positional arguments")
	}
	if !*noConfirm && !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("invite needs an interactive terminal to confirm the device; use --no-confirm only for automation")
	}

	store, err := state.New(localStateDir(*stateDir))
	if err != nil {
		return err
	}
	conn, err := control.Dial(store.Dir())
	if err != nil {
		return err
	}
	defer conn.Close()

	err = conn.Send(control.Message{
		Type:       control.TypeInviteCreate,
		TTLSeconds: int(ttl.Seconds()),
		Endpoints:  endpoints,
		NoConfirm:  *noConfirm,
	})
	if err != nil {
		return err
	}

	return followInvite(conn, bufio.NewReader(os.Stdin), os.Stdout, *noConfirm)
}

// followInvite prints the invite and walks the operator through pairing
// until a device is paired, rejected, or the invite expires.
// With noConfirm the agent approves the device itself and no answer is read.
func followInvite(conn *control.Conn, input *bufio.Reader, output io.Writer, noConfirm bool) error {
	for {
		message, err := conn.Receive()
		if err != nil {
			return fmt.Errorf("agent closed the connection: %w", err)
		}

		switch message.Type {
		case control.TypeInviteCreated:
			fmt.Fprintf(output, "Connection key (single use, valid until %s):\n\n%s\n\n"+
				"Paste it into Loreva App. Keep this command running until the device is paired.\n",
				message.ExpiresAt.Local().Format(time.DateTime), message.Invite)

		case control.TypePairingRequested:
			fmt.Fprintf(output, "\nDevice %q wants to connect.\nDevice key: %s\nCode: %s\n",
				message.DeviceName, message.Fingerprint, message.SAS)
			if noConfirm {
				continue
			}

			approve, err := confirmPairing(input, output)
			if err != nil {
				return err
			}

			err = conn.Send(control.Message{Type: control.TypePairingDecision, PairingID: message.PairingID, Approve: approve})
			if err != nil {
				return err
			}

		case control.TypePairingCompleted:
			fmt.Fprintf(output, "Device %q paired. Device ID: %s\n", message.DeviceName, message.DeviceID)
			return nil

		case control.TypePairingRejected:
			return errors.New("pairing rejected; the connection key can no longer be used")

		case control.TypeInviteExpired:
			return errors.New("the connection key expired; run invite again")

		case control.TypeError:
			return errors.New(message.Error)
		}
	}
}

// confirmPairing asks the operator to compare the code. Anything but "y"
// or "yes" rejects the device.
func confirmPairing(input *bufio.Reader, output io.Writer) (bool, error) {
	fmt.Fprint(output, "Approve only if the device shows the same code. Approve? [y/N]: ")
	answer, err := input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read answer: %w", err)
	}

	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes", nil
}
