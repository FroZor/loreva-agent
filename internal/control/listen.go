package control

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// Listen creates the control socket in stateDir, replacing a stale socket
// left by a crashed agent. It never removes anything that is not a socket.
func Listen(stateDir string) (net.Listener, error) {
	path := SocketPath(stateDir)
	if err := checkSocketPath(path); err != nil {
		return nil, err
	}

	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("control socket path exists and is not a socket: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale control socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect control socket path: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errors.Join(fmt.Errorf("secure control socket: %w", err), listener.Close())
	}

	return listener, nil
}
