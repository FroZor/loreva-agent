package sources

import (
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestValidate(t *testing.T) {
	valid := protocol.Sources{
		Generation: 1,
		ExpiresAt:  time.Now().Add(time.Hour),
		Items: []protocol.SourceItem{{
			URL:             "wss://gateway.example/agent/v1/connect",
			Priority:        0,
			Weight:          1,
			SecurityProfile: protocol.SecurityProfile,
		}},
	}

	tests := []struct {
		name   string
		change func(*protocol.Sources)
	}{
		{name: "valid"},
		{name: "expired", change: func(pool *protocol.Sources) { pool.ExpiresAt = time.Now().Add(-time.Second) }},
		{name: "unsupported scheme", change: func(pool *protocol.Sources) { pool.Items[0].URL = "ws://gateway.example/agent/v1/connect" }},
		{name: "unexpected path", change: func(pool *protocol.Sources) { pool.Items[0].URL = "wss://gateway.example/other" }},
		{name: "duplicate", change: func(pool *protocol.Sources) { pool.Items = append(pool.Items, pool.Items[0]) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := valid
			pool.Items = append([]protocol.SourceItem(nil), valid.Items...)

			if test.change != nil {
				test.change(&pool)
			}

			err := Validate(pool)
			if test.change == nil && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.change != nil && err == nil {
				t.Fatal("Validate() accepted invalid source pool")
			}
		})
	}
}
