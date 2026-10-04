package control

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// AuthorizePeer accepts only root and the agent's own user, using the
// kernel-reported credentials of the connecting process (SO_PEERCRED).
func AuthorizePeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("control connection is not a Unix socket")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("access control socket: %w", err)
	}

	var credentials *unix.Ucred
	var credentialsErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialsErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("access control socket: %w", err)
	}
	if credentialsErr != nil {
		return fmt.Errorf("read control peer credentials: %w", credentialsErr)
	}

	if credentials.Uid != 0 && int(credentials.Uid) != os.Getuid() {
		return fmt.Errorf("control peer uid %d is not allowed", credentials.Uid)
	}

	return nil
}
