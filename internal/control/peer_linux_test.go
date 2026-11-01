package control

import (
	"net"
	"path/filepath"
	"testing"
)

func TestAuthorizePeerAcceptsOwnUser(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "c.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer server.Close()

	if err := AuthorizePeer(server); err != nil {
		t.Fatalf("AuthorizePeer() error = %v for the agent's own user", err)
	}
}

func TestAuthorizePeerRejectsNonUnixConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := AuthorizePeer(server); err == nil {
		t.Fatal("AuthorizePeer() accepted a connection that is not a Unix socket")
	}
}
