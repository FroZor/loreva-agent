package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/state"
)

// runDevices lists or removes paired devices on this node:
//
//	loreva-agent devices [list]
//	loreva-agent devices remove DEVICE_ID
func runDevices(arguments []string, _ *slog.Logger) error {
	flags := flag.NewFlagSet("devices", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	stateDir := flags.String("state-dir", "", "agent state directory")

	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse devices arguments: %w", err)
	}

	request, err := devicesRequest(flags.Args())
	if err != nil {
		return err
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

	if err := conn.Send(request); err != nil {
		return err
	}
	response, err := conn.Receive()
	if err != nil {
		return fmt.Errorf("read agent response: %w", err)
	}

	switch response.Type {
	case control.TypeDevices:
		return printDevices(os.Stdout, response.Devices)
	case control.TypeDeviceRemoved:
		_, err := fmt.Fprintf(os.Stdout, "Device %s removed.\n", response.DeviceID)
		return err
	case control.TypeError:
		return errors.New(response.Error)
	default:
		return fmt.Errorf("unexpected agent response %q", response.Type)
	}
}

func devicesRequest(arguments []string) (control.Message, error) {
	switch {
	case len(arguments) == 0 || len(arguments) == 1 && arguments[0] == "list":
		return control.Message{Type: control.TypeDevicesList}, nil
	case len(arguments) == 2 && arguments[0] == "remove":
		return control.Message{Type: control.TypeDeviceRemove, DeviceID: arguments[1]}, nil
	default:
		return control.Message{}, errors.New("usage: loreva-agent devices [list | remove DEVICE_ID]")
	}
}

func printDevices(output io.Writer, devices []control.Device) error {
	if len(devices) == 0 {
		_, err := fmt.Fprintln(output, "No paired devices.")
		return err
	}

	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tNAME\tKEY PIN\tPAIRED")
	for _, device := range devices {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", device.ID, device.Name, device.CertificatePin, device.PairedAt.Local().Format(time.DateTime))
	}

	return table.Flush()
}
