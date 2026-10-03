package strictjson

import (
	"encoding/json"
	"testing"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		data string
		ok   bool
	}{
		{name: "valid", data: `{"name":"agent"}`, ok: true},
		{name: "duplicate", data: `{"name":"agent","name":"portal"}`},
		{name: "nested duplicate", data: `{"name":"agent","nested":{"id":1,"id":2}}`},
		{name: "case-insensitive duplicate", data: `{"name":"agent","NAME":"portal"}`},
		{name: "mixed-case duplicate", data: `{"name":"agent","nAmE":"portal"}`},
		{name: "unknown", data: `{"name":"agent","unknown":true}`},
		{name: "multiple values", data: `{"name":"agent"} {"name":"portal"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var target struct {
				Name string `json:"name"`
			}

			err := Decode([]byte(test.data), &target)
			if test.ok && err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("Decode() accepted invalid JSON")
			}
		})
	}
}

func TestDecodeRejectsCaseFoldedDuplicates(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "upper case", data: `{"kind":"node.report","KIND":"exec"}`},
		{name: "upper case first", data: `{"KIND":"exec","kind":"node.report"}`},
		{name: "kelvin sign", data: `{"kind":"node.report","\u212aind":"exec"}`},
		{name: "nested", data: `{"kind":"node.report","args":{"id":"a","ID":"b"}}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var target struct {
				Kind string          `json:"kind"`
				Args json.RawMessage `json:"args"`
			}

			if err := Decode([]byte(test.data), &target); err == nil {
				t.Fatalf("Decode() accepted %s as kind %q", test.data, target.Kind)
			}
		})
	}
}

func TestDecodeRejectsNilTarget(t *testing.T) {
	if err := Decode([]byte(`{}`), nil); err == nil {
		t.Fatal("Decode() accepted a nil target")
	}
}
