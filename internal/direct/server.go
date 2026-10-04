package direct

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/control"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/session"
	"github.com/FroZor/loreva-agent/internal/specifications"
	"github.com/FroZor/loreva-agent/internal/state"
	"github.com/FroZor/loreva-agent/internal/tunnel"
)

const shutdownTimeout = 5 * time.Second

// Collectors provide system snapshots and metrics for device sessions.
type Collectors struct {
	Specifications func(context.Context) (specifications.Snapshot, error)
	Network        func(context.Context) (networkinfo.Snapshot, error)
	Metrics        func(context.Context) <-chan metrics.Sample
}

func (c Collectors) session() session.Collectors {
	return session.Collectors{Specifications: c.Specifications, Network: c.Network, Metrics: c.Metrics}
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
	Logger    *slog.Logger
}

// localNode is the validated form of state.Node.
type localNode struct {
	id         string
	publicKey  tunnel.Key
	privateKey tunnel.Key
	prefix     netip.Prefix
	address    netip.Addr
	listenPort int
	endpoints  []string
}

func parseNode(node *state.Node) (*localNode, error) {
	privateKey, err := tunnel.ParseKey(node.WireGuardPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("node private key: %w", err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}
	prefix, err := tunnel.ParsePrefix(node.TunnelPrefix)
	if err != nil {
		return nil, err
	}
	if node.ListenPort < 1 || node.ListenPort > 65535 {
		return nil, errors.New("node listen port is out of range")
	}

	return &localNode{
		id:         node.NodeID,
		publicKey:  publicKey,
		privateKey: privateKey,
		prefix:     prefix,
		address:    tunnel.NodeAddress(prefix),
		listenPort: node.ListenPort,
		endpoints:  node.Endpoints,
	}, nil
}

// Run serves paired devices over WireGuard and the CLI over the control
// socket until ctx is cancelled.
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

	peers := make([]tunnel.Peer, 0, len(devices.list()))
	for _, device := range devices.list() {
		peer, err := devicePeer(device)
		if err != nil {
			return err
		}

		peers = append(peers, peer)
	}

	tun, err := tunnel.Start(tunnel.Config{
		PrivateKey: local.privateKey,
		ListenPort: local.listenPort,
		Address:    local.address,
		Logger:     options.Logger,
	}, peers)
	if err != nil {
		return err
	}
	defer tun.Close()

	sessionListener, err := tun.ListenTCP(netip.AddrPortFrom(local.address, protocol.DirectSessionPort))
	if err != nil {
		return err
	}
	controlListener, err := control.Listen(store.Dir())
	if err != nil {
		return errors.Join(err, sessionListener.Close())
	}

	pending := newPairings(local, tun, devices, options.Logger)
	defer pending.closeAll()

	service := newSessions(local, options, pending, devices, tun)
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
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}

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

	logger.Info("direct access ready", "node_id", local.id, "udp_port", local.listenPort, "tunnel_address", local.address)

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
