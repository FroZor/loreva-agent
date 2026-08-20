package strictjson

import "testing"

func TestDecode(t *testing.T) {
	tests := []struct {
		name string
		data string
		ok   bool
	}{
		{name: "valid", data: `{"name":"agent"}`, ok: true},
		{name: "duplicate", data: `{"name":"agent","name":"portal"}`},
		{name: "nested duplicate", data: `{"name":"agent","nested":{"id":1,"id":2}}`},
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

func TestDecodeRejectsNilTarget(t *testing.T) {
	if err := Decode([]byte(`{}`), nil); err == nil {
		t.Fatal("Decode() accepted a nil target")
	}
}
