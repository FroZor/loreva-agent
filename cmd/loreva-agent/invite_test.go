package main

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/FroZor/loreva-agent/internal/control"
)

func TestFollowInvite(t *testing.T) {
	for _, test := range []struct {
		name        string
		answer      string
		wantApprove bool
	}{
		{name: "approve", answer: "y\n", wantApprove: true},
		{name: "default rejects", answer: "\n", wantApprove: false},
		{name: "other answer rejects", answer: "maybe\n", wantApprove: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cliSide, agentSide := net.Pipe()
			agent := control.NewConn(agentSide)
			defer agent.Close()

			decisions := make(chan control.Message, 1)
			go func() {
				_ = agent.Send(control.Message{Type: control.TypeInviteCreated, Invite: "loreva://connect/test"})
				_ = agent.Send(control.Message{Type: control.TypePairingRequested, PairingID: "p", DeviceName: "laptop", SAS: "ABCD-EFGH"})

				decision, err := agent.Receive()
				if err != nil {
					close(decisions)
					return
				}
				decisions <- decision

				if decision.Approve {
					_ = agent.Send(control.Message{Type: control.TypePairingCompleted, DeviceName: "laptop", DeviceID: "d"})
				} else {
					_ = agent.Send(control.Message{Type: control.TypePairingRejected})
				}
			}()

			var output bytes.Buffer
			err := followInvite(control.NewConn(cliSide), bufio.NewReader(strings.NewReader(test.answer)), &output, false)

			decision := <-decisions
			if decision.Type != control.TypePairingDecision || decision.PairingID != "p" || decision.Approve != test.wantApprove {
				t.Fatalf("decision = %+v, want approve %v", decision, test.wantApprove)
			}
			if test.wantApprove != (err == nil) {
				t.Fatalf("followInvite() error = %v", err)
			}
			if !strings.Contains(output.String(), "loreva://connect/test") || !strings.Contains(output.String(), "ABCD-EFGH") {
				t.Fatalf("output = %q", output.String())
			}
		})
	}
}

func TestDevicesRequest(t *testing.T) {
	for _, arguments := range [][]string{nil, {"list"}} {
		if request, err := devicesRequest(arguments); err != nil || request.Type != control.TypeDevicesList {
			t.Errorf("devicesRequest(%q) = %+v, %v", arguments, request, err)
		}
	}

	request, err := devicesRequest([]string{"remove", "id"})
	if err != nil || request.Type != control.TypeDeviceRemove || request.DeviceID != "id" {
		t.Errorf("devicesRequest(remove) = %+v, %v", request, err)
	}
	if _, err := devicesRequest([]string{"remove"}); err == nil {
		t.Error("devicesRequest(remove without ID) succeeded")
	}
}
