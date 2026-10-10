// Package containerfiles gives the file manager access to the volumes and
// mounted folders of one container. The agent itself runs without access to
// Docker's data, so it asks Docker for a helper container that shares only
// the target's volumes (--volumes-from), has no network, a read-only root
// file system, and three capabilities, and runs the agent binary as
// `loreva-agent files-helper`. Docker documents the same --volumes-from
// approach for volume backups.
package containerfiles

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"regexp"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"

	"github.com/FroZor/loreva-agent/internal/containerio"
	"github.com/FroZor/loreva-agent/internal/fileops"
)

var (
	// ErrNoVolumes means the container has no volume or mounted folder to
	// browse.
	ErrNoVolumes = errors.New("the container has no volumes or mounted folders")
	// ErrBusy means too many containers have a file helper at once.
	ErrBusy = errors.New("too many containers have the file manager open")
	// ErrUnavailable means the helper could not be started.
	ErrUnavailable = errors.New("the file helper could not be started")
)

// Labels on helper containers.
const (
	RoleLabel   = "dev.loreva.role"
	RoleHelper  = "files-helper"
	TargetLabel = "dev.loreva.target"
)

const (
	// maxHelpers bounds the helper containers that run at once.
	maxHelpers = 8
	// idleTimeout stops a helper that served no call for this long.
	idleTimeout = 2 * time.Minute
	// startTimeout bounds importing the image and starting a helper.
	startTimeout = time.Minute
	// helperMemoryBytes and helperPids bound one helper's resources.
	helperMemoryBytes = 256 * 1024 * 1024
	helperPids        = 64
	// maxStderrLine bounds a helper error line in the agent log.
	maxStderrLine = 1024
)

var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Engine is the part of the Docker client the manager uses.
type Engine interface {
	ContainerInspect(ctx context.Context, containerID string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	ContainerCreate(ctx context.Context, options client.ContainerCreateOptions) (client.ContainerCreateResult, error)
	ContainerAttach(ctx context.Context, containerID string, options client.ContainerAttachOptions) (client.ContainerAttachResult, error)
	ContainerStart(ctx context.Context, containerID string, options client.ContainerStartOptions) (client.ContainerStartResult, error)
	ContainerRemove(ctx context.Context, containerID string, options client.ContainerRemoveOptions) (client.ContainerRemoveResult, error)
	ContainerList(ctx context.Context, options client.ContainerListOptions) (client.ContainerListResult, error)
	ImageInspect(ctx context.Context, imageID string, options ...client.ImageInspectOption) (client.ImageInspectResult, error)
	ImageImport(ctx context.Context, source client.ImageImportSource, ref string, options client.ImageImportOptions) (client.ImageImportResult, error)
	ImageList(ctx context.Context, options client.ImageListOptions) (client.ImageListResult, error)
	ImageRemove(ctx context.Context, imageID string, options client.ImageRemoveOptions) (client.ImageRemoveResult, error)
}

// Call is one file operation in flight; see fileops.Call.
type Call interface {
	Response(ctx context.Context) (fileops.Response, error)
	Read(ctx context.Context, buffer []byte) (int, error)
	Write(ctx context.Context, data []byte) error
	Close()
}

// Manager runs one helper per container that has the file manager open and
// stops it when it has been idle.
type Manager struct {
	engine     Engine
	logger     *slog.Logger
	executable string
	// ctx bounds the helper connections; Close cancels it.
	ctx    context.Context
	cancel context.CancelFunc

	imageMu sync.Mutex
	image   string

	mu      sync.Mutex
	helpers map[string]*helper
}

// helper is a running helper container.
type helper struct {
	target string
	ready  chan struct{}
	err    error
	client *fileops.Client
	conn   client.HijackedResponse
	id     string
	users  int
	idle   *time.Timer
}

// New returns a manager that starts helpers through engine.
func New(engine Engine, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		engine:     engine,
		logger:     logger,
		executable: executablePath,
		ctx:        ctx,
		cancel:     cancel,
		helpers:    make(map[string]*helper),
	}
}

// RemoveStale removes helpers left behind by an agent that stopped
// abruptly.
func (m *Manager) RemoveStale(ctx context.Context) error {
	filters := make(client.Filters).Add("label", RoleLabel+"="+RoleHelper)
	result, err := m.engine.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return fmt.Errorf("list file helpers: %w", err)
	}

	var errs []error
	for _, summary := range result.Items {
		if _, err := m.engine.ContainerRemove(ctx, summary.ID, client.ContainerRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Close stops every helper.
func (m *Manager) Close() {
	m.cancel()

	m.mu.Lock()
	helpers := m.helpers
	m.helpers = make(map[string]*helper)
	m.mu.Unlock()

	for _, current := range helpers {
		<-current.ready
		current.close()
	}
}

// Start runs a file operation in the volumes of a container. The caller
// must Close the call.
func (m *Manager) Start(ctx context.Context, containerID string, request fileops.Request) (Call, error) {
	if !containerIDPattern.MatchString(containerID) {
		return nil, containerio.ErrInvalidContainerID
	}

	current, err := m.acquire(ctx, containerID)
	if err != nil {
		return nil, err
	}
	call, err := current.client.Start(request)
	if err != nil {
		m.release(current)
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	return &managedCall{Call: call, release: func() { m.release(current) }}, nil
}

type managedCall struct {
	*fileops.Call
	once    sync.Once
	release func()
}

func (c *managedCall) Close() {
	c.Call.Close()
	c.once.Do(c.release)
}

func (m *Manager) acquire(ctx context.Context, target string) (*helper, error) {
	m.mu.Lock()
	current := m.helpers[target]
	if current != nil && current.stopped() {
		delete(m.helpers, target)
		current.close()
		current = nil
	}
	starting := current == nil
	if starting {
		if len(m.helpers) >= maxHelpers {
			m.mu.Unlock()
			return nil, ErrBusy
		}
		current = &helper{target: target, ready: make(chan struct{})}
		m.helpers[target] = current
	}
	current.users++
	if current.idle != nil {
		current.idle.Stop()
		current.idle = nil
	}
	m.mu.Unlock()

	if starting {
		current.err = m.start(current)
		close(current.ready)
	}

	select {
	case <-current.ready:
	case <-ctx.Done():
		m.release(current)
		return nil, ctx.Err()
	}
	if current.err != nil {
		m.mu.Lock()
		if m.helpers[target] == current {
			delete(m.helpers, target)
		}
		current.users--
		m.mu.Unlock()
		return nil, current.err
	}

	return current, nil
}

func (m *Manager) release(current *helper) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current.users--
	if current.users > 0 || m.helpers[current.target] != current {
		return
	}
	current.idle = time.AfterFunc(idleTimeout, func() {
		// A caller that gave up waiting may release a helper that is
		// still starting.
		<-current.ready
		m.mu.Lock()
		stop := current.users == 0 && m.helpers[current.target] == current
		if stop {
			delete(m.helpers, current.target)
		}
		m.mu.Unlock()
		if stop {
			current.close()
		}
	})
}

// start creates, attaches, and starts the helper for current.target and
// tells it which mounts it serves.
func (m *Manager) start(current *helper) error {
	ctx, cancel := context.WithTimeout(m.ctx, startTimeout)
	defer cancel()

	mounts, err := m.targetMounts(ctx, current.target)
	if err != nil {
		return err
	}
	image, err := m.ensureImage(ctx)
	if err != nil {
		m.logger.Warn("file helper image unavailable", "error", err)
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	created, err := m.engine.ContainerCreate(ctx, helperOptions(image, current.target))
	if errdefs.IsNotFound(err) {
		// The image was removed, for example by `docker image prune -a`;
		// the next attempt imports it again.
		m.forgetImage()
	}
	if err != nil {
		m.logger.Warn("create file helper", "container_id", current.target, "error", err)
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	current.id = created.ID

	// The connection must outlive the start timeout, so it uses the
	// manager's context.
	attached, err := m.engine.ContainerAttach(m.ctx, created.ID, client.ContainerAttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		m.removeHelper(created.ID)
		return fmt.Errorf("%w: attach: %w", ErrUnavailable, err)
	}
	current.conn = attached.HijackedResponse

	output, outputWriter := io.Pipe()
	go m.demultiplex(current, outputWriter)
	current.client = fileops.NewClient(output, attached.Conn)

	if _, err := m.engine.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		current.close()
		m.removeHelper(created.ID)
		return fmt.Errorf("%w: start: %w", ErrUnavailable, err)
	}
	if err := current.client.Init(ctx, mounts); err != nil {
		current.close()
		m.removeHelper(created.ID)
		m.logger.Warn("file helper did not start", "container_id", current.target, "error", err)
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	m.logger.Info("file helper started", "container_id", current.target, "helper_id", created.ID)

	return nil
}

// targetMounts lists the volumes and bind mounts --volumes-from shares.
func (m *Manager) targetMounts(ctx context.Context, target string) ([]fileops.Mount, error) {
	inspection, err := m.engine.ContainerInspect(ctx, target, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, containerio.ErrNotFound
		}
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	if inspection.Container.Config != nil && inspection.Container.Config.Labels[RoleLabel] == RoleHelper {
		return nil, ErrNoVolumes
	}

	var mounts []fileops.Mount
	for _, point := range inspection.Container.Mounts {
		if point.Type != mount.TypeVolume && point.Type != mount.TypeBind {
			continue
		}
		// A mount over the helper's binary would let the container run
		// its own program with the helper's privileges.
		if path.Clean(point.Destination) == helperBinary || path.Clean(point.Destination) == "/" {
			return nil, fmt.Errorf("%w: the container mounts %s, which the helper needs", ErrUnavailable, point.Destination)
		}
		mounts = append(mounts, fileops.Mount{Path: point.Destination, ReadOnly: !point.RW})
	}
	if len(mounts) == 0 {
		return nil, ErrNoVolumes
	}

	return mounts, nil
}

func helperOptions(image, target string) client.ContainerCreateOptions {
	pids := int64(helperPids)

	return client.ContainerCreateOptions{
		Config: &container.Config{
			Image:           image,
			Cmd:             []string{helperBinary, "files-helper"},
			User:            "0:0",
			WorkingDir:      "/",
			AttachStdin:     true,
			AttachStdout:    true,
			AttachStderr:    true,
			OpenStdin:       true,
			StdinOnce:       true,
			NetworkDisabled: true,
			Labels:          map[string]string{RoleLabel: RoleHelper, TargetLabel: target},
		},
		HostConfig: &container.HostConfig{
			VolumesFrom:    []string{target},
			NetworkMode:    "none",
			ReadonlyRootfs: true,
			AutoRemove:     true,
			// Root in the helper may read and change any file in the
			// volumes and keep its owner; nothing else.
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"},
			SecurityOpt: []string{"no-new-privileges"},
			LogConfig:   container.LogConfig{Type: "none"},
			Resources: container.Resources{
				Memory:    helperMemoryBytes,
				PidsLimit: &pids,
			},
		},
	}
}

// demultiplex splits the helper's attached output: stdout carries the
// protocol, stderr goes to the agent log.
func (m *Manager) demultiplex(current *helper, stdout *io.PipeWriter) {
	stderr := &logWriter{logger: m.logger, target: current.target}
	_, err := stdcopy.StdCopy(stdout, stderr, current.conn.Reader)
	stdout.CloseWithError(errors.Join(err, io.EOF))
}

func (m *Manager) removeHelper(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := m.engine.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}); err != nil && !errdefs.IsNotFound(err) {
		m.logger.Warn("remove file helper", "helper_id", id, "error", err)
	}
}

// stopped reports a helper that failed to start or has exited.
func (h *helper) stopped() bool {
	select {
	case <-h.ready:
	default:
		return false
	}
	if h.err != nil {
		return true
	}

	select {
	case <-h.client.Done():
		return true
	default:
		return false
	}
}

// close ends the connection; the helper sees its stdin close, exits, and
// Docker removes it.
func (h *helper) close() {
	if h.conn.Conn != nil {
		h.conn.Close()
	}
}

// logWriter logs helper stderr line by line.
type logWriter struct {
	logger  *slog.Logger
	target  string
	pending []byte
}

func (w *logWriter) Write(data []byte) (int, error) {
	w.pending = append(w.pending, data...)
	for {
		end := bytes.IndexByte(w.pending, '\n')
		if end < 0 {
			break
		}
		line := w.pending[:min(end, maxStderrLine)]
		w.logger.Warn("file helper", "container_id", w.target, "message", string(line))
		w.pending = w.pending[end+1:]
	}
	if len(w.pending) > maxStderrLine {
		w.pending = nil
	}

	return len(data), nil
}
