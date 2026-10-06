package direct

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
)

const (
	shutdownTimeout = 5 * time.Second
	// maxConnections bounds open TCP connections, including ones that are
	// still in the TLS handshake.
	maxConnections = 128
	// maxConnectionsPerAddress keeps one source address from taking every
	// slot. Devices behind one NAT share it, so it is not tiny.
	maxConnectionsPerAddress = 16
	// handshakeTimeout bounds the TLS handshake and the HTTP upgrade request.
	handshakeTimeout = 5 * time.Second
	// idleTimeout closes kept-alive connections that never upgraded.
	idleTimeout = 15 * time.Second
)

// Collectors provide system snapshots and metrics for device sessions.
type Collectors struct {
	Specifications func(context.Context) (specifications.Snapshot, error)
	Network        func(context.Context) (networkinfo.Snapshot, error)
	Metrics        session.MetricsSource
	Processes      func(pid int32, startedAt time.Time) (protocol.ProcessDetails, error)
}

func (c Collectors) session() session.Collectors {
	return session.Collectors{Specifications: c.Specifications, Network: c.Network, Metrics: c.Metrics, Processes: c.Processes}
}

// serialized runs each snapshot collector at most once at a time, so devices
// that open many sessions cannot pile up expensive collections.
func (c Collectors) serialized() Collectors {
	var specificationsMu, networkMu sync.Mutex

	collectSpecifications, collectNetwork := c.Specifications, c.Network
	c.Specifications = func(ctx context.Context) (specifications.Snapshot, error) {
		specificationsMu.Lock()
		defer specificationsMu.Unlock()

		return collectSpecifications(ctx)
	}
	c.Network = func(ctx context.Context) (networkinfo.Snapshot, error) {
		networkMu.Lock()
		defer networkMu.Unlock()

		return collectNetwork(ctx)
	}

	return c
}

// Options configures the direct server.
type Options struct {
	Version        string
	PortalEnrolled bool
	Collectors     Collectors
	// Workloads may be nil when the node has no workload runtime.
	Workloads session.WorkloadController
	// Containers may be nil when the node has no container runtime.
	Containers session.ContainerIO
	// Files may be nil when the node has no container runtime.
	Files  session.ContainerFiles
	Logger *slog.Logger
}

// localNode is the validated form of state.Node.
type localNode struct {
	id          string
	certificate tls.Certificate
	pin         string
	listenPort  int
	endpoints   []string
}

func parseNode(node *state.Node) (*localNode, error) {
	identity := certpin.Identity{PrivateKey: node.TLSPrivateKey, Certificate: node.TLSCertificate}
	certificate, err := identity.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("node TLS identity: %w", err)
	}
	if node.ListenPort < 1 || node.ListenPort > 65535 {
		return nil, errors.New("node listen port is out of range")
	}

	return &localNode{
		id:          node.NodeID,
		certificate: certificate,
		pin:         certpin.Of(certificate.Leaf),
		listenPort:  node.ListenPort,
		endpoints:   node.Endpoints,
	}, nil
}

// Run serves devices over TLS on the node's port and the CLI over the
// control socket until ctx is cancelled.
func Run(ctx context.Context, store *state.Store, node *state.Node, options Options) error {
	if options.Logger == nil {
		options.Logger = slog.New(slog.DiscardHandler)
	}
	if options.Collectors.Specifications == nil || options.Collectors.Network == nil {
		return errors.New("direct server collectors are required")
	}
	options.Collectors = options.Collectors.serialized()

	local, err := parseNode(node)
	if err != nil {
		return fmt.Errorf("load node identity: %w", err)
	}
	devices, err := loadRegistry(store)
	if err != nil {
		return err
	}

	pending := newPairings(local, devices, options.Logger)
	defer pending.closeAll()

	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", local.listenPort))
	if err != nil {
		return fmt.Errorf("listen on TCP port %d: %w", local.listenPort, err)
	}
	authorize := func(pin string) error {
		if _, paired := devices.byPin(pin); paired || pending.active() {
			return nil
		}

		return certpin.ErrPolicy
	}
	sessionListener := tls.NewListener(
		limitPerAddress(netutil.LimitListener(tcpListener, maxConnections), maxConnectionsPerAddress),
		certpin.ServerConfig(local.certificate, authorize),
	)

	controlListener, err := control.Listen(store.Dir())
	if err != nil {
		return errors.Join(err, sessionListener.Close())
	}

	service := newSessions(local, options, pending, devices)
	controller := &controlServer{pairings: pending, sessions: service, logger: options.Logger}

	if options.Workloads != nil {
		fanOutCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		go service.fanOut(fanOutCtx, options.Workloads.Results(local.id))
	}

	return serve(ctx, service, sessionListener, controller, controlListener, options.Logger, local)
}

func serve(ctx context.Context, service *sessions, sessionListener net.Listener, controller *controlServer,
	controlListener net.Listener, logger *slog.Logger, local *localNode,
) error {
	// Sessions get a context that is cancelled before shutdown, so they end at
	// once instead of outlasting the shutdown timeout.
	requestCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()

	server := &http.Server{
		Handler:           service.handler(),
		BaseContext:       func(net.Listener) context.Context { return requestCtx },
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	// Every real request is a WebSocket upgrade; anything else gets one answer.
	server.SetKeepAlivesEnabled(false)

	errs := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := server.Serve(sessionListener); !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("direct sessions stopped: %w", err)
		}
	})
	workers.Go(func() {
		if err := controller.serve(controlListener); err != nil {
			errs <- err
		}
	})

	logger.Info("direct access ready", "node_id", local.id, "tcp_port", local.listenPort, "node_pin", local.pin)

	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}

	cancelRequests()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	result = errors.Join(result, server.Shutdown(shutdownCtx))
	if err := controlListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		result = errors.Join(result, err)
	}
	controller.closeConnections()
	workers.Wait()

	return result
}
