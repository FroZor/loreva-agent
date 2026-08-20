package wsframe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestReadRawJSONRejectsBinaryFrame(t *testing.T) {
	conn := dialFrameServer(t, websocket.MessageBinary, []byte(`{"type":"test"}`))

	if _, err := ReadRawJSON(context.Background(), conn); err == nil {
		t.Fatal("ReadRawJSON() accepted a binary frame")
	}
}

func TestReadJSONRejectsAmbiguousInput(t *testing.T) {
	tests := []string{
		`{"type":"one","type":"two"}`,
		`{"type":"one","unknown":true}`,
		`{"type":"one"} {"type":"two"}`,
	}

	for _, data := range tests {
		conn := dialFrameServer(t, websocket.MessageText, []byte(data))
		var target struct {
			Type string `json:"type"`
		}

		if err := ReadJSON(context.Background(), conn, &target); err == nil {
			t.Fatalf("ReadJSON() accepted %s", data)
		}
	}
}

func TestWriteJSONUsesTextFrame(t *testing.T) {
	result := make(chan websocket.MessageType, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(response, request, nil)
		if err != nil {
			return
		}
		defer closeTestConnection(t, conn)

		messageType, _, err := conn.Read(request.Context())
		if err == nil {
			result <- messageType
		}
	}))
	t.Cleanup(server.Close)

	conn, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestConnection(t, conn) })

	if err := WriteJSON(context.Background(), conn, struct {
		Type string `json:"type"`
	}{Type: "test"}); err != nil {
		t.Fatal(err)
	}

	select {
	case messageType := <-result:
		if messageType != websocket.MessageText {
			t.Fatalf("WriteJSON() frame type = %v", messageType)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive the JSON frame")
	}
}

func dialFrameServer(t *testing.T, messageType websocket.MessageType, data []byte) *websocket.Conn {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(response, request, nil)
		if err != nil {
			return
		}
		defer closeTestConnection(t, conn)

		_ = conn.Write(request.Context(), messageType, data)
	}))
	t.Cleanup(server.Close)

	conn, _, err := websocket.Dial(context.Background(), websocketURL(server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestConnection(t, conn) })

	return conn
}

func websocketURL(serverURL string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http")
}

func closeTestConnection(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	if err := conn.CloseNow(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test WebSocket connection: %v", err)
	}
}
