package containerio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

var testID = strings.Repeat("ab", 32)

func TestValidateCommand(t *testing.T) {
	tests := map[string]bool{
		"list":                     true,
		"say привет":               true,
		"":                         false,
		"   ":                      false,
		"say hi\nop attacker":      false,
		"say hi\rop attacker":      false,
		"stop\x00":                 false,
		"\x1b[2J":                  false,
		strings.Repeat("a", 1024):  true,
		strings.Repeat("a", 1025):  false,
		string([]byte{0xff, 0xfe}): false,
	}

	for command, valid := range tests {
		if err := ValidateCommand(command); (err == nil) != valid {
			t.Errorf("ValidateCommand(%q) error = %v, want valid %v", command, err, valid)
		}
	}
}

func inspection(labels map[string]string, env []string, openStdin bool) client.ContainerInspectResult {
	return client.ContainerInspectResult{Container: container.InspectResponse{
		State:      &container.State{Running: true},
		HostConfig: &container.HostConfig{NetworkMode: "bridge"},
		Config:     &container.Config{Labels: labels, Env: env, OpenStdin: openStdin},
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{
			"bridge": {IPAddress: netip.MustParseAddr("172.17.0.5")},
		}},
	}}
}

func TestResolveConsole(t *testing.T) {
	tests := []struct {
		name    string
		input   client.ContainerInspectResult
		want    consoleTarget
		wantErr error
	}{
		{
			name:  "open stdin without labels",
			input: inspection(nil, nil, true),
			want:  consoleTarget{adapter: AdapterStdin},
		},
		{
			name:    "no stdin and no labels",
			input:   inspection(nil, nil, false),
			wantErr: ErrNoConsole,
		},
		{
			name:  "rcon with default port and password variable",
			input: inspection(map[string]string{ConsoleLabel: "rcon"}, []string{"RCON_PASSWORD=secret"}, false),
			want:  consoleTarget{adapter: AdapterRCON, address: "172.17.0.5:25575", password: "secret"},
		},
		{
			name: "rcon with custom port and password variable",
			input: inspection(map[string]string{
				ConsoleLabel: "rcon", ConsolePortLabel: "27015", ConsolePasswordEnvLabel: "ADMIN_PASS",
			}, []string{"ADMIN_PASS=pw"}, false),
			want: consoleTarget{adapter: AdapterRCON, address: "172.17.0.5:27015", password: "pw"},
		},
		{
			name:    "rcon without password",
			input:   inspection(map[string]string{ConsoleLabel: "rcon"}, nil, false),
			wantErr: ErrConsoleMisconfigured,
		},
		{
			name:  "telnet without password",
			input: inspection(map[string]string{ConsoleLabel: "telnet"}, nil, false),
			want:  consoleTarget{adapter: AdapterTelnet, address: "172.17.0.5:8081"},
		},
		{
			name:    "bad port",
			input:   inspection(map[string]string{ConsoleLabel: "telnet", ConsolePortLabel: "70000"}, nil, false),
			wantErr: ErrConsoleMisconfigured,
		},
		{
			name:    "bad password variable name",
			input:   inspection(map[string]string{ConsoleLabel: "rcon", ConsolePasswordEnvLabel: "A=B"}, nil, false),
			wantErr: ErrConsoleMisconfigured,
		},
		{
			name:    "stdin label without open stdin",
			input:   inspection(map[string]string{ConsoleLabel: "stdin"}, nil, false),
			wantErr: ErrConsoleMisconfigured,
		},
		{
			name:    "unknown adapter",
			input:   inspection(map[string]string{ConsoleLabel: "ssh"}, nil, true),
			wantErr: ErrConsoleMisconfigured,
		},
		{
			name:    "explicitly none",
			input:   inspection(map[string]string{ConsoleLabel: "none"}, nil, true),
			wantErr: ErrNoConsole,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveConsole(test.input)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("resolveConsole() = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestResolveConsoleHostNetwork(t *testing.T) {
	input := inspection(map[string]string{ConsoleLabel: "telnet"}, nil, false)
	input.Container.HostConfig.NetworkMode = "host"

	got, err := resolveConsole(input)
	if err != nil || got.address != "127.0.0.1:8081" {
		t.Fatalf("resolveConsole() = %+v, %v", got, err)
	}
}

func TestCleanOutput(t *testing.T) {
	got := cleanOutput("\x1b[32mThere are 0\x1b[0m players\r\n\tok\x07" + string([]byte{0xff}))
	if got != "There are 0 players\n\tok�" {
		t.Fatalf("cleanOutput() = %q", got)
	}

	long := cleanOutput(strings.Repeat("я", MaxOutputBytes))
	if len(long) > MaxOutputBytes {
		t.Fatalf("output has %d bytes", len(long))
	}
}

func TestStripTelnetCommands(t *testing.T) {
	data := []byte{'a', telnetIAC, telnetWill, 1, 'b', telnetIAC, telnetIAC, telnetIAC, telnetSB, 24, 1, telnetIAC, telnetSE, 'c'}

	if got := stripTelnetCommands(data); !bytes.Equal(got, []byte{'a', 'b', telnetIAC, 'c'}) {
		t.Fatalf("stripTelnetCommands() = %q", got)
	}
}

// pipeDialer hands the client side of a pipe to the service and serves the
// other side with server.
type pipeDialer struct {
	server func(net.Conn)
}

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	clientSide, serverSide := net.Pipe()
	go func() {
		defer serverSide.Close()
		d.server(serverSide)
	}()

	return clientSide, nil
}

func fakeRCONServer(password string, replies ...string) func(net.Conn) {
	return func(conn net.Conn) {
		auth, err := readRCONPacket(conn)
		if err != nil || auth.packetType != rconAuth {
			return
		}
		id := auth.id
		if string(auth.body) != password {
			id = -1
		}
		// Source servers send an empty response value before the answer.
		_ = writeRCONPacket(conn, auth.id, rconResponseValue, "")
		_ = writeRCONPacket(conn, id, rconAuthResponse, "")

		command, err := readRCONPacket(conn)
		if err != nil {
			return
		}
		for _, reply := range replies {
			_ = writeRCONPacket(conn, command.id, rconResponseValue, reply+":"+string(command.body))
		}
		// Keep the connection open like a real server.
		_, _ = io.Copy(io.Discard, conn)
	}
}

func TestSendRCON(t *testing.T) {
	service := &Service{dialer: pipeDialer{server: fakeRCONServer("secret", "first", "second")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := service.sendRCON(ctx, consoleTarget{adapter: AdapterRCON, address: "x", password: "secret"}, "list")
	if err != nil || output != "first:listsecond:list" {
		t.Fatalf("sendRCON() = %q, %v", output, err)
	}

	_, err = service.sendRCON(ctx, consoleTarget{adapter: AdapterRCON, address: "x", password: "wrong"}, "list")
	if !errors.Is(err, ErrConsoleAuthFailed) {
		t.Fatalf("wrong password error = %v", err)
	}
}

func fakeTelnetServer(password string) func(net.Conn) {
	return func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		_, _ = conn.Write([]byte{telnetIAC, telnetWill, 1})
		_, _ = conn.Write([]byte("*** Connected with 7DTD server.\r\nPlease enter password:\r\n"))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) != password {
			_, _ = conn.Write([]byte("Password incorrect, please enter password:\r\n"))
			return
		}
		_, _ = conn.Write([]byte("Logon successful.\r\n\r\nServer IP: 0.0.0.0\r\n"))

		command, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("Executing command '" + strings.TrimSpace(command) + "'\r\nTotal of 0 in the game\r\n"))
		_, _ = io.Copy(io.Discard, reader)
	}
}

func TestSendTelnet(t *testing.T) {
	service := &Service{dialer: pipeDialer{server: fakeTelnetServer("secret")}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := service.sendTelnet(ctx, consoleTarget{adapter: AdapterTelnet, address: "x", password: "secret"}, "lp")
	if err != nil {
		t.Fatalf("sendTelnet() error = %v", err)
	}
	if !strings.Contains(output, "Executing command 'lp'") || strings.Contains(output, "Server IP") {
		t.Fatalf("sendTelnet() output = %q", output)
	}

	_, err = service.sendTelnet(ctx, consoleTarget{adapter: AdapterTelnet, address: "x", password: "wrong"}, "lp")
	if !errors.Is(err, ErrConsoleAuthFailed) {
		t.Fatalf("wrong password error = %v", err)
	}
}

// fakeEngine serves one container's inspection and log.
type fakeEngine struct {
	inspection client.ContainerInspectResult
	log        []byte
}

func (f fakeEngine) ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	return f.inspection, nil
}

func (f fakeEngine) ContainerLogs(context.Context, string, client.ContainerLogsOptions) (client.ContainerLogsResult, error) {
	return io.NopCloser(bytes.NewReader(f.log)), nil
}

func (f fakeEngine) ContainerAttach(context.Context, string, client.ContainerAttachOptions) (client.ContainerAttachResult, error) {
	return client.ContainerAttachResult{}, errors.New("not supported")
}

func multiplexed(stream byte, data string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(data)))

	return append(header, data...)
}

func TestLogsDemultiplexesStdoutAndStderr(t *testing.T) {
	big := strings.Repeat("x", MaxChunkBytes+10)
	log := append(multiplexed(1, "out\n"), multiplexed(2, "err\n")...)
	log = append(log, multiplexed(1, big)...)
	service := New(fakeEngine{inspection: inspection(nil, nil, false), log: log})

	stream, err := service.Logs(context.Background(), testID, LogOptions{Tail: 10})
	if err != nil {
		t.Fatalf("Logs() error = %v", err)
	}
	defer stream.Close()

	var stdout, stderr strings.Builder
	chunks := 0
	err = stream.Copy(func(source Stream, data []byte) error {
		if len(data) > MaxChunkBytes {
			t.Fatalf("chunk of %d bytes", len(data))
		}
		chunks++
		if source == Stderr {
			stderr.Write(data)
		} else {
			stdout.Write(data)
		}
		return nil
	})
	if err != nil || stdout.String() != "out\n"+big || stderr.String() != "err\n" || chunks != 4 {
		t.Fatalf("Copy() = %v, stdout %d bytes, stderr %q, %d chunks", err, stdout.Len(), stderr.String(), chunks)
	}
}

func TestLogsRejectsBadInput(t *testing.T) {
	service := New(fakeEngine{inspection: inspection(nil, nil, false)})

	if _, err := service.Logs(context.Background(), "abc", LogOptions{}); !errors.Is(err, ErrInvalidContainerID) {
		t.Fatalf("short ID error = %v", err)
	}
	if _, err := service.Logs(context.Background(), testID, LogOptions{Tail: MaxLogTail + 1}); err == nil {
		t.Fatal("tail above the limit was accepted")
	}
}
