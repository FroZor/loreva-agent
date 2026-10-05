package containerio

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Source RCON packet types,
// https://developer.valvesoftware.com/wiki/Source_RCON_Protocol.
const (
	rconResponseValue = 0
	rconExecCommand   = 2
	rconAuthResponse  = 2
	rconAuth          = 3

	rconAuthID    = 1
	rconCommandID = 2

	// rconMaxPacket bounds an incoming packet; servers send at most 4096
	// bytes of body per packet.
	rconMaxPacket = 64 * 1024
	// rconReplyIdle ends a reply that may span several packets.
	rconReplyIdle = 300 * time.Millisecond
)

func (s *Service) sendRCON(ctx context.Context, target consoleTarget, command string) (string, error) {
	conn, err := s.dialer.DialContext(ctx, "tcp", target.address)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", fmt.Errorf("set RCON deadline: %w", err)
		}
	}

	if err := writeRCONPacket(conn, rconAuthID, rconAuth, target.password); err != nil {
		return "", err
	}
	if err := readRCONAuth(conn); err != nil {
		return "", err
	}

	if err := writeRCONPacket(conn, rconCommandID, rconExecCommand, command); err != nil {
		return "", err
	}

	return readRCONReply(ctx, conn)
}

func writeRCONPacket(conn net.Conn, id, packetType int32, body string) error {
	var packet bytes.Buffer
	length := int32(4 + 4 + len(body) + 2)
	for _, value := range []int32{length, id, packetType} {
		if err := binary.Write(&packet, binary.LittleEndian, value); err != nil {
			return err
		}
	}
	packet.WriteString(body)
	packet.Write([]byte{0, 0})

	if _, err := conn.Write(packet.Bytes()); err != nil {
		return fmt.Errorf("write RCON packet: %w", err)
	}

	return nil
}

type rconPacket struct {
	id         int32
	packetType int32
	body       []byte
}

func readRCONPacket(reader io.Reader) (rconPacket, error) {
	var length int32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return rconPacket{}, err
	}
	if length < 10 || length > rconMaxPacket {
		return rconPacket{}, fmt.Errorf("RCON packet length %d is out of range", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return rconPacket{}, err
	}

	return rconPacket{
		id:         int32(binary.LittleEndian.Uint32(data[0:4])),
		packetType: int32(binary.LittleEndian.Uint32(data[4:8])),
		body:       bytes.TrimRight(data[8:], "\x00"),
	}, nil
}

// readRCONAuth waits for the authentication answer. Source servers send an
// empty response value first; an ID of -1 means the password was wrong.
func readRCONAuth(conn net.Conn) error {
	for range 2 {
		packet, err := readRCONPacket(conn)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
		}
		if packet.packetType != rconAuthResponse {
			continue
		}
		if packet.id == -1 {
			return ErrConsoleAuthFailed
		}

		return nil
	}

	return fmt.Errorf("%w: no RCON authentication answer", ErrConsoleUnreachable)
}

// readRCONReply collects response packets for the command until the server
// goes quiet, since long replies are split over several packets.
func readRCONReply(ctx context.Context, conn net.Conn) (string, error) {
	var reply bytes.Buffer
	received := false

	for reply.Len() <= MaxOutputBytes {
		if received {
			if err := conn.SetReadDeadline(idleDeadline(ctx, rconReplyIdle)); err != nil {
				return "", err
			}
		}

		packet, err := readRCONPacket(conn)
		if err != nil {
			if received && errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if received && errors.Is(err, io.EOF) {
				break
			}

			return "", fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
		}
		if packet.id != rconCommandID || packet.packetType != rconResponseValue {
			continue
		}

		reply.Write(packet.body)
		received = true
	}

	return reply.String(), nil
}

// idleDeadline is now plus idle, but never later than the context deadline.
func idleDeadline(ctx context.Context, idle time.Duration) time.Time {
	deadline := time.Now().Add(idle)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}

	return deadline
}
