//go:build !linux

package control

import (
	"errors"
	"net"
)

// AuthorizePeer rejects every peer: peer credential checks are implemented
// only on Linux, the one supported node platform.
func AuthorizePeer(net.Conn) error {
	return errors.New("the control socket is supported only on Linux")
}
