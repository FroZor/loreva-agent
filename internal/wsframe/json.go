// Package wsframe reads and writes protocol JSON in WebSocket text frames.
package wsframe

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// ReadJSON reads one text frame and strictly decodes its JSON payload.
func ReadJSON(ctx context.Context, conn *websocket.Conn, target any) error {
	data, err := ReadRawJSON(ctx, conn)
	if err != nil {
		return err
	}

	return protocol.DecodeStrict(data, target)
}

// ReadRawJSON reads one WebSocket text frame.
func ReadRawJSON(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	messageType, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if messageType != websocket.MessageText {
		return nil, errors.New("protocol messages must be WebSocket text frames")
	}

	return data, nil
}

// WriteJSON encodes value and writes it as one WebSocket text frame.
func WriteJSON(ctx context.Context, conn *websocket.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return conn.Write(ctx, websocket.MessageText, data)
}
