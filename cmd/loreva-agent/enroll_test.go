package main

import (
	"bytes"
	"testing"
)

func TestWriteEnrollmentResult(t *testing.T) {
	const nodeID = "65a1876f-a715-45fc-9ac0-e4bc31067059"

	var output bytes.Buffer
	if err := writeEnrollmentResult(&output, nodeID); err != nil {
		t.Fatal(err)
	}

	want := "Loreva Agent configured successfully.\nNode ID: " + nodeID + "\n"
	if output.String() != want {
		t.Fatalf("writeEnrollmentResult() = %q, want %q", output.String(), want)
	}
}

func TestIsSetupCommand(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
		want      bool
	}{
		{name: "configure", arguments: []string{"configure"}, want: true},
		{name: "connect", arguments: []string{"connect"}, want: true},
		{name: "disconnect", arguments: []string{"disconnect"}, want: true},
		{name: "enroll", arguments: []string{"enroll"}, want: true},
		{name: "status", arguments: []string{"status"}, want: true},
		{name: "run", arguments: []string{"run"}, want: false},
		{name: "empty", arguments: nil, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isSetupCommand(test.arguments); got != test.want {
				t.Fatalf("isSetupCommand() = %t, want %t", got, test.want)
			}
		})
	}
}
