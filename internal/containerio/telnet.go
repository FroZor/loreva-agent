package containerio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	telnetPromptIdle  = 2 * time.Second
	telnetBannerIdle  = 500 * time.Millisecond
	telnetCommandIdle = time.Second
	// telnetMaxRead bounds everything read in one telnet exchange.
	telnetMaxRead = 256 * 1024
)

// Telnet bytes, RFC 854.
const (
	telnetSE   = 240
	telnetSB   = 250
	telnetWill = 251
	telnetDont = 254
	telnetIAC  = 255
)

// sendTelnet logs in to a line-based telnet console, such as the one of
// 7 Days to Die, sends the command, and returns what the server printed
// until it went quiet.
func (s *Service) sendTelnet(ctx context.Context, target consoleTarget, command string) (string, error) {
	conn, err := s.dialer.DialContext(ctx, "tcp", target.address)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
	}
	defer conn.Close()

	session := &telnetSession{conn: conn}
	if target.password != "" {
		if _, err := session.readUntil(ctx, telnetPromptIdle, containsFold("password")); err != nil {
			return "", err
		}
		if err := session.writeLine(ctx, target.password); err != nil {
			return "", err
		}

		answer, err := session.readUntil(ctx, telnetPromptIdle, containsFold("successful", "incorrect"))
		if err != nil {
			return "", err
		}
		if !strings.Contains(strings.ToLower(answer), "successful") {
			return "", ErrConsoleAuthFailed
		}
	}

	// Skip the greeting the server prints after logon.
	if _, err := session.readUntil(ctx, telnetBannerIdle, nil); err != nil {
		return "", err
	}

	if err := session.writeLine(ctx, command); err != nil {
		return "", err
	}
	output, err := session.readUntil(ctx, telnetCommandIdle, nil)
	if err != nil {
		return "", err
	}

	// Leave politely; the reply is already complete.
	_ = session.writeLine(ctx, "exit")

	return output, nil
}

type telnetSession struct {
	conn net.Conn
	read int
}

func (t *telnetSession) writeLine(ctx context.Context, line string) error {
	if err := t.conn.SetWriteDeadline(idleDeadline(ctx, commandTimeout)); err != nil {
		return err
	}
	if _, err := t.conn.Write([]byte(line + "\r\n")); err != nil {
		return fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
	}

	return nil
}

// readUntil reads until stop accepts the text read so far or the server is
// quiet for idle. It returns the text without telnet commands.
func (t *telnetSession) readUntil(ctx context.Context, idle time.Duration, stop func(string) bool) (string, error) {
	var raw bytes.Buffer
	buffer := make([]byte, 4096)

	for {
		if err := t.conn.SetReadDeadline(idleDeadline(ctx, idle)); err != nil {
			return "", err
		}

		count, err := t.conn.Read(buffer)
		raw.Write(buffer[:count])
		t.read += count
		text := string(stripTelnetCommands(raw.Bytes()))

		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			if ctx.Err() != nil {
				return "", fmt.Errorf("%w: %v", ErrConsoleUnreachable, ctx.Err())
			}
			return text, nil
		case errors.Is(err, io.EOF):
			return text, nil
		case err != nil:
			return "", fmt.Errorf("%w: %v", ErrConsoleUnreachable, err)
		case t.read > telnetMaxRead:
			return text, nil
		case stop != nil && stop(text):
			return text, nil
		}
	}
}

func containsFold(words ...string) func(string) bool {
	return func(text string) bool {
		lower := strings.ToLower(text)
		for _, word := range words {
			if strings.Contains(lower, word) {
				return true
			}
		}

		return false
	}
}

// stripTelnetCommands removes IAC command sequences and keeps escaped 0xFF.
func stripTelnetCommands(data []byte) []byte {
	result := make([]byte, 0, len(data))
	for index := 0; index < len(data); index++ {
		if data[index] != telnetIAC {
			result = append(result, data[index])
			continue
		}
		if index+1 >= len(data) {
			break
		}

		command := data[index+1]
		switch {
		case command == telnetIAC:
			result = append(result, telnetIAC)
			index++
		case command >= telnetWill && command <= telnetDont:
			index += 2
		case command == telnetSB:
			end := bytes.Index(data[index:], []byte{telnetIAC, telnetSE})
			if end < 0 {
				return result
			}
			index += end + 1
		default:
			index++
		}
	}

	return result
}
