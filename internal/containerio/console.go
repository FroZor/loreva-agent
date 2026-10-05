package containerio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/moby/moby/client"
)

// Adapter is how console commands reach a container.
type Adapter string

const (
	AdapterNone   Adapter = "none"
	AdapterStdin  Adapter = "stdin"
	AdapterRCON   Adapter = "rcon"
	AdapterTelnet Adapter = "telnet"
)

// Container labels that select the console adapter. Without ConsoleLabel a
// container with an open stdin uses stdin and any other has no console.
const (
	ConsoleLabel            = "dev.loreva.console"
	ConsolePortLabel        = "dev.loreva.console.port"
	ConsolePasswordEnvLabel = "dev.loreva.console.password_env"
)

const (
	// MaxCommandBytes bounds one console command.
	MaxCommandBytes = 1024
	// MaxOutputBytes bounds the reply text returned for one command.
	MaxOutputBytes = 8 * 1024

	defaultRCONPort        = 25575
	defaultRCONPasswordEnv = "RCON_PASSWORD"
	defaultTelnetPort      = 8081
	commandTimeout         = 10 * time.Second
)

var (
	// ErrNoConsole means the container has no console the agent can use.
	ErrNoConsole = errors.New("container has no console: open stdin or set the " + ConsoleLabel + " label")
	// ErrInvalidCommand means the command is empty, too long, or not one line of text.
	ErrInvalidCommand = fmt.Errorf("command must be one line of 1 to %d bytes of text without control characters", MaxCommandBytes)
	// ErrConsoleMisconfigured means the console labels or password are unusable.
	ErrConsoleMisconfigured = errors.New("console labels of the container are not usable")
	// ErrConsoleUnreachable means the console port did not answer.
	ErrConsoleUnreachable = errors.New("console port of the container did not answer")
	// ErrConsoleAuthFailed means the console rejected the password.
	ErrConsoleAuthFailed = errors.New("console rejected the password")
)

var (
	environmentNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	terminalSequencePattern = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")
)

// CommandResult is the outcome of one delivered command. Output holds the
// reply of RCON and telnet consoles; stdin output appears in the log.
type CommandResult struct {
	Adapter Adapter
	Output  string
}

// ValidateCommand reports whether command is one line of printable text.
func ValidateCommand(command string) error {
	if len(command) == 0 || len(command) > MaxCommandBytes || !utf8.ValidString(command) {
		return ErrInvalidCommand
	}
	if strings.TrimSpace(command) == "" {
		return ErrInvalidCommand
	}
	for _, character := range command {
		if unicode.IsControl(character) {
			return ErrInvalidCommand
		}
	}

	return nil
}

// ConsoleAdapter reports which console a container offers.
func (s *Service) ConsoleAdapter(ctx context.Context, containerID string) (Adapter, error) {
	inspection, err := s.inspect(ctx, containerID)
	if err != nil {
		return "", err
	}

	target, err := resolveConsole(inspection)
	if errors.Is(err, ErrNoConsole) {
		return AdapterNone, nil
	}
	if err != nil {
		return "", err
	}

	return target.adapter, nil
}

// SendCommand delivers one command to the console of a running container.
func (s *Service) SendCommand(ctx context.Context, containerID, command string) (CommandResult, error) {
	if err := ValidateCommand(command); err != nil {
		return CommandResult{}, err
	}

	inspection, err := s.inspect(ctx, containerID)
	if err != nil {
		return CommandResult{}, err
	}
	target, err := resolveConsole(inspection)
	if err != nil {
		return CommandResult{}, err
	}
	if !inspection.Container.State.Running {
		return CommandResult{}, ErrNotRunning
	}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	var output string
	switch target.adapter {
	case AdapterStdin:
		err = s.sendStdin(ctx, containerID, command)
	case AdapterRCON:
		output, err = s.sendRCON(ctx, target, command)
	case AdapterTelnet:
		output, err = s.sendTelnet(ctx, target, command)
	}
	if err != nil {
		return CommandResult{}, err
	}

	return CommandResult{Adapter: target.adapter, Output: cleanOutput(output)}, nil
}

func (s *Service) sendStdin(ctx context.Context, containerID, command string) error {
	attached, err := s.engine.ContainerAttach(ctx, containerID, client.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
	})
	if err != nil {
		return fmt.Errorf("attach to container stdin: %w", err)
	}
	defer attached.HijackedResponse.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := attached.HijackedResponse.Conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set stdin deadline: %w", err)
		}
	}
	if _, err := attached.HijackedResponse.Conn.Write([]byte(command + "\n")); err != nil {
		return fmt.Errorf("write to container stdin: %w", err)
	}
	if err := attached.HijackedResponse.CloseWrite(); err != nil {
		return fmt.Errorf("finish container stdin write: %w", err)
	}

	return nil
}

// consoleTarget is a resolved console. The password never leaves the node.
type consoleTarget struct {
	adapter  Adapter
	address  string
	password string
}

func resolveConsole(inspection client.ContainerInspectResult) (consoleTarget, error) {
	config := inspection.Container.Config
	adapter := Adapter(config.Labels[ConsoleLabel])
	if adapter == "" {
		if config.OpenStdin {
			return consoleTarget{adapter: AdapterStdin}, nil
		}

		return consoleTarget{}, ErrNoConsole
	}

	switch adapter {
	case AdapterNone:
		return consoleTarget{}, ErrNoConsole
	case AdapterStdin:
		if !config.OpenStdin {
			return consoleTarget{}, fmt.Errorf("%w: stdin console needs a container created with an open stdin", ErrConsoleMisconfigured)
		}

		return consoleTarget{adapter: AdapterStdin}, nil
	case AdapterRCON:
		return networkConsole(inspection, AdapterRCON, defaultRCONPort, defaultRCONPasswordEnv, true)
	case AdapterTelnet:
		return networkConsole(inspection, AdapterTelnet, defaultTelnetPort, "", false)
	default:
		return consoleTarget{}, fmt.Errorf("%w: %s must be stdin, rcon, telnet, or none", ErrConsoleMisconfigured, ConsoleLabel)
	}
}

// networkConsole reads the port and password of an RCON or telnet console.
// The agent connects to the container's own address, so the console port
// does not need to be published on the host.
func networkConsole(
	inspection client.ContainerInspectResult,
	adapter Adapter,
	defaultPort int,
	defaultPasswordEnv string,
	passwordRequired bool,
) (consoleTarget, error) {
	labels := inspection.Container.Config.Labels

	port := defaultPort
	if value, ok := labels[ConsolePortLabel]; ok {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			return consoleTarget{}, fmt.Errorf("%w: %s must be a TCP port", ErrConsoleMisconfigured, ConsolePortLabel)
		}
		port = parsed
	}

	passwordEnv := defaultPasswordEnv
	if value, ok := labels[ConsolePasswordEnvLabel]; ok {
		passwordEnv = value
	}
	password := ""
	if passwordEnv != "" {
		if !environmentNamePattern.MatchString(passwordEnv) {
			return consoleTarget{}, fmt.Errorf("%w: %s must name an environment variable", ErrConsoleMisconfigured, ConsolePasswordEnvLabel)
		}
		password = environmentValue(inspection.Container.Config.Env, passwordEnv)
	}
	if passwordRequired && password == "" {
		return consoleTarget{}, fmt.Errorf("%w: the container sets no %s password", ErrConsoleMisconfigured, adapter)
	}

	host, err := containerHost(inspection)
	if err != nil {
		return consoleTarget{}, err
	}

	return consoleTarget{
		adapter:  adapter,
		address:  net.JoinHostPort(host, strconv.Itoa(port)),
		password: password,
	}, nil
}

func environmentValue(environment []string, name string) string {
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && key == name {
			return value
		}
	}

	return ""
}

// containerHost returns the address the agent reaches the container on.
func containerHost(inspection client.ContainerInspectResult) (string, error) {
	if hostConfig := inspection.Container.HostConfig; hostConfig != nil && hostConfig.NetworkMode.IsHost() {
		return "127.0.0.1", nil
	}

	settings := inspection.Container.NetworkSettings
	if settings == nil {
		return "", fmt.Errorf("%w: the container has no network address", ErrConsoleMisconfigured)
	}

	names := make([]string, 0, len(settings.Networks))
	for name := range settings.Networks {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		endpoint := settings.Networks[name]
		if endpoint != nil && endpoint.IPAddress.IsValid() {
			return endpoint.IPAddress.String(), nil
		}
	}

	return "", fmt.Errorf("%w: the container has no network address", ErrConsoleMisconfigured)
}

// cleanOutput keeps console replies printable and bounded.
func cleanOutput(output string) string {
	output = strings.ToValidUTF8(output, "\uFFFD")
	output = terminalSequencePattern.ReplaceAllString(output, "")

	var builder strings.Builder
	for _, character := range output {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			continue
		}
		if builder.Len()+utf8.RuneLen(character) > MaxOutputBytes {
			break
		}
		builder.WriteRune(character)
	}

	return builder.String()
}
