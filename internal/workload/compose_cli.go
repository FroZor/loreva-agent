package workload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	composetypes "github.com/compose-spec/compose-go/v2/types"
)

const maxComposeOutputBytes = 16 << 10

type composeCLI struct {
	path            string
	dockerHost      string
	dockerTLSVerify string
	dockerCertPath  string
	configDir       string
	tempDir         string
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func openComposeCLI(ctx context.Context, dockerHost, stateRoot string) (*composeCLI, error) {
	path, err := exec.LookPath("docker")
	if err != nil {
		return nil, errors.New("docker CLI was not found")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve docker CLI path: %w", err)
	}

	configDir := filepath.Join(stateRoot, "docker-cli")
	tempDir := filepath.Join(stateRoot, "tmp")
	for _, directory := range []string{configDir, tempDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create Docker CLI state directory: %w", err)
		}
	}

	cli := &composeCLI{
		path:            path,
		dockerHost:      dockerHost,
		dockerTLSVerify: os.Getenv("DOCKER_TLS_VERIFY"),
		dockerCertPath:  os.Getenv("DOCKER_CERT_PATH"),
		configDir:       configDir,
		tempDir:         tempDir,
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = cli.run(probeCtx, "", "compose", "version", "--short")
	cancel()
	if err != nil {
		return nil, fmt.Errorf("probe Docker Compose: %w", err)
	}

	return cli, nil
}

func (cli *composeCLI) runProject(
	ctx context.Context,
	workingDir string,
	project *composetypes.Project,
	arguments ...string,
) (resultErr error) {
	content, err := project.MarshalYAML()
	if err != nil {
		return fmt.Errorf("render resolved Compose project: %w", err)
	}

	file, err := os.CreateTemp(workingDir, ".loreva-compose-*.yaml")
	if err != nil {
		return fmt.Errorf("create resolved Compose project: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				resultErr = errors.Join(resultErr, closeErr)
			}
		}
		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, removeErr)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect resolved Compose project: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write resolved Compose project: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync resolved Compose project: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close resolved Compose project: %w", err)
	}
	closed = true

	commandArguments := []string{
		"compose", "--project-name", project.Name, "--file", file.Name(),
	}
	commandArguments = append(commandArguments, arguments...)

	return cli.run(ctx, workingDir, commandArguments...)
}

func (cli *composeCLI) run(ctx context.Context, workingDir string, arguments ...string) error {
	command := exec.CommandContext(ctx, cli.path, arguments...)
	command.Dir = workingDir
	command.Env = cli.environment()

	output := &boundedOutput{limit: maxComposeOutputBytes}
	command.Stdout = output
	command.Stderr = output

	if err := command.Run(); err != nil {
		message := sanitizeRuntimeMessage(output.String())
		if message == "" {
			return fmt.Errorf("docker compose command failed: %w", err)
		}

		return fmt.Errorf("docker compose command failed: %w: %s", err, message)
	}

	return nil
}

func (cli *composeCLI) environment() []string {
	keys := []string{"LANG", "LC_ALL", "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR"}
	environment := make([]string, 0, len(keys)+6)
	for _, key := range keys {
		if value, exists := os.LookupEnv(key); exists {
			environment = append(environment, key+"="+value)
		}
	}

	environment = append(environment,
		"COMPOSE_ANSI=never",
		"DOCKER_CONFIG="+cli.configDir,
		"DOCKER_HOST="+cli.dockerHost,
		"HOME="+cli.configDir,
		"TEMP="+cli.tempDir,
		"TMP="+cli.tempDir,
		"TMPDIR="+cli.tempDir,
	)
	if cli.dockerTLSVerify != "" {
		environment = append(environment, "DOCKER_TLS_VERIFY="+cli.dockerTLSVerify)
	}
	if cli.dockerCertPath != "" {
		environment = append(environment, "DOCKER_CERT_PATH="+cli.dockerCertPath)
	}

	return environment
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		_, _ = output.buffer.Write(data[:min(remaining, len(data))])
	}

	return len(data), nil
}

func (output *boundedOutput) String() string {
	return strings.TrimSpace(output.buffer.String())
}
