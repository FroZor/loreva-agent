package portal

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/nodeapi"
)

func TestPeerIdentityRejectionIsTerminal(t *testing.T) {
	runner := &Runner{masterEndpoint: "wss://portal.example/agent/v1/connect"}

	err := runner.peerFailure(runner.masterEndpoint, &nodeapi.IdentityRejection{Err: errors.New("node_not_registered")})
	if !IsTerminal(err) {
		t.Fatalf("identity rejection was not terminal: %v", err)
	}
}

func TestPeerErrorPassesThroughWithoutBecomingTerminal(t *testing.T) {
	runner := &Runner{masterEndpoint: "wss://portal.example/agent/v1/connect"}
	cause := errors.New("malformed rejection")

	err := runner.peerFailure(runner.masterEndpoint, cause)
	if err != cause {
		t.Fatalf("peerFailure() = %v, want the error unchanged", err)
	}
	if IsTerminal(err) {
		t.Fatalf("plain peer error became terminal: %v", err)
	}
	if runner.peerFailure(runner.masterEndpoint, nil) != nil {
		t.Fatal("peerFailure(nil) returned an error")
	}
}

func newWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	connections := make(chan *websocket.Conn, 1)
	errorsChannel := make(chan error, 1)
	done := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			errorsChannel <- err
			return
		}

		connections <- conn
		<-done
	}))

	client, _, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}

	var serverConnection *websocket.Conn
	select {
	case serverConnection = <-connections:
	case err := <-errorsChannel:
		server.Close()
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		server.Close()
		t.Fatal("timed out establishing WebSocket test pair")
	}

	t.Cleanup(func() {
		close(done)
		closeTestWebSocket(t, client)
		closeTestWebSocket(t, serverConnection)
		server.Close()
	})

	return client, serverConnection
}

func closeTestWebSocket(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	err := conn.CloseNow()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close test WebSocket: %v", err)
	}
}
