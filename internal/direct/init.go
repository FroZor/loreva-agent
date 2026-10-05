// Package direct runs the standalone side of the agent: the local node
// identity, the TLS listener for devices, device pairing, device sessions,
// and the local control socket. It works without any portal or cloud
// service.
package direct

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/certpin"
	"github.com/FroZor/loreva-agent/internal/pairing"
	"github.com/FroZor/loreva-agent/internal/state"
)

const (
	minRandomPort  = 20000
	maxRandomPort  = 32000
	portAttempts   = 32
	maxEndpointArg = 16
)

// InitOptions configures a new local node identity.
type InitOptions struct {
	// ListenPort is the TCP port for devices. Zero picks a free random port
	// between 20000 and 32000.
	ListenPort int
	// Endpoints are public addresses advertised in invites before the
	// detected interface addresses, as IP or IP:port.
	Endpoints []string
}

// Init creates node.json in the store. It refuses to replace an existing
// node identity.
func Init(store *state.Store, options InitOptions) (*state.Node, error) {
	_, err := store.LoadNode()
	if err == nil {
		return nil, errors.New("this node is already initialized")
	}
	if !errors.Is(err, state.ErrNotFound) {
		return nil, fmt.Errorf("load node identity: %w", err)
	}

	port := options.ListenPort
	if port < 0 || port > 65535 {
		return nil, errors.New("listen port must be between 1 and 65535")
	}
	if port == 0 {
		if port, err = pickListenPort(); err != nil {
			return nil, err
		}
	}

	endpoints, err := normalizeEndpoints(options.Endpoints, port)
	if err != nil {
		return nil, err
	}

	nodeID, err := agentcrypto.NewUUID()
	if err != nil {
		return nil, err
	}
	identity, err := certpin.Generate()
	if err != nil {
		return nil, err
	}

	node := &state.Node{
		NodeID:         nodeID,
		TLSPrivateKey:  identity.PrivateKey,
		TLSCertificate: identity.Certificate,
		ListenPort:     port,
		Endpoints:      endpoints,
		CreatedAt:      time.Now().UTC(),
	}
	if err := store.SaveNode(node); err != nil {
		return nil, fmt.Errorf("save node identity: %w", err)
	}

	return node, nil
}

// pickListenPort returns a random TCP port in the configured range that is
// free right now, so init never takes a port another service already uses.
func pickListenPort() (int, error) {
	span := big.NewInt(maxRandomPort - minRandomPort + 1)

	for range portAttempts {
		offset, err := rand.Int(rand.Reader, span)
		if err != nil {
			return 0, fmt.Errorf("pick listen port: %w", err)
		}

		port := minRandomPort + int(offset.Int64())
		if tcpPortFree(port) {
			return port, nil
		}
	}

	return 0, errors.New("could not find a free TCP port between 20000 and 32000; use --port")
}

func tcpPortFree(port int) bool {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		return false
	}

	return listener.Close() == nil
}

func normalizeEndpoints(values []string, port int) ([]string, error) {
	if len(values) > maxEndpointArg {
		return nil, fmt.Errorf("at most %d endpoints are allowed", maxEndpointArg)
	}

	endpoints := make([]string, 0, len(values))
	for _, value := range values {
		endpoint, err := parseAdvertisedEndpoint(value, port)
		if err != nil {
			return nil, err
		}

		endpoints = append(endpoints, endpoint.String())
	}

	return endpoints, nil
}

// parseAdvertisedEndpoint accepts IP:port, or a bare IP that gets the node's
// listen port.
func parseAdvertisedEndpoint(value string, port int) (netip.AddrPort, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		value = netip.AddrPortFrom(address, uint16(port)).String()
	}

	return pairing.ParseEndpoint(value)
}
