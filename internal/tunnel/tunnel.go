package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// MTU is the inner tunnel MTU. 1280 is the IPv6 minimum, so inner packets are
// never fragmented by the netstack and fit typical outer paths.
const MTU = 1280

// Config describes the local end of a tunnel.
type Config struct {
	PrivateKey Key
	// ListenPort is the UDP port to bind. Zero lets the kernel pick one.
	ListenPort int
	// Address is this end's address inside the tunnel.
	Address netip.Addr
	Logger  *slog.Logger
}

// Peer is a remote WireGuard peer allowed to send from exactly one address.
type Peer struct {
	PublicKey    Key
	PresharedKey Key
	Address      netip.Addr
	// Endpoint is the peer's outer UDP address. Responders leave it unset and
	// learn it from authenticated packets.
	Endpoint netip.AddrPort
	// PersistentKeepalive is the keepalive interval in seconds; zero disables it.
	PersistentKeepalive int
}

// Tunnel is a running userspace WireGuard device with its own TCP/IP stack.
type Tunnel struct {
	device *device.Device
	net    *netstack.Net
}

// Start brings a tunnel up with the given peers.
func Start(config Config, peers []Peer) (*Tunnel, error) {
	if config.PrivateKey.IsZero() {
		return nil, errors.New("tunnel private key is required")
	}
	if !config.Address.Is6() || config.Address.Is4In6() {
		return nil, errors.New("tunnel address must be an IPv6 address")
	}
	if config.ListenPort < 0 || config.ListenPort > 65535 {
		return nil, errors.New("tunnel listen port is out of range")
	}

	tunDevice, network, err := netstack.CreateNetTUN([]netip.Addr{config.Address}, nil, MTU)
	if err != nil {
		return nil, fmt.Errorf("create userspace network stack: %w", err)
	}

	wireguard := device.NewDevice(tunDevice, conn.NewDefaultBind(), deviceLogger(config.Logger))
	tunnel := &Tunnel{device: wireguard, net: network}

	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", config.PrivateKey.hex(), config.ListenPort)
	for _, peer := range peers {
		if err := writePeer(&builder, peer); err != nil {
			wireguard.Close()
			return nil, err
		}
	}

	if err := wireguard.IpcSet(builder.String()); err != nil {
		wireguard.Close()
		return nil, fmt.Errorf("configure WireGuard device: %w", err)
	}
	if err := wireguard.Up(); err != nil {
		wireguard.Close()
		return nil, fmt.Errorf("start WireGuard device: %w", err)
	}

	return tunnel, nil
}

// AddPeer adds or replaces a peer.
func (t *Tunnel) AddPeer(peer Peer) error {
	var builder strings.Builder
	if err := writePeer(&builder, peer); err != nil {
		return err
	}

	if err := t.device.IpcSet(builder.String()); err != nil {
		return fmt.Errorf("add WireGuard peer: %w", err)
	}

	return nil
}

// RemovePeer removes a peer and drops its sessions.
func (t *Tunnel) RemovePeer(publicKey Key) error {
	if err := t.device.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", publicKey.hex())); err != nil {
		return fmt.Errorf("remove WireGuard peer: %w", err)
	}

	return nil
}

// ListenTCP listens on a TCP address inside the tunnel. The listener is not
// reachable from the host network.
func (t *Tunnel) ListenTCP(address netip.AddrPort) (net.Listener, error) {
	listener, err := t.net.ListenTCPAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("listen inside tunnel: %w", err)
	}

	return listener, nil
}

// DialContext opens a connection inside the tunnel.
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.net.DialContext(ctx, network, address)
}

// Close shuts the device down and releases its UDP socket.
func (t *Tunnel) Close() {
	t.device.Close()
}

func writePeer(builder *strings.Builder, peer Peer) error {
	if peer.PublicKey.IsZero() {
		return errors.New("WireGuard peer public key is required")
	}
	// wireguard-go silently runs a peer without a PSK with an all-zero PSK,
	// which would remove the post-quantum layer. Every peer must have one.
	if peer.PresharedKey.IsZero() {
		return errors.New("WireGuard peer preshared key is required")
	}
	if !peer.Address.Is6() || peer.Address.Is4In6() {
		return errors.New("WireGuard peer address must be an IPv6 address")
	}
	if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
		return errors.New("WireGuard keepalive interval is out of range")
	}

	fmt.Fprintf(builder, "public_key=%s\nreplace_allowed_ips=true\npreshared_key=%s\nallowed_ip=%s\n",
		peer.PublicKey.hex(), peer.PresharedKey.hex(), netip.PrefixFrom(peer.Address, 128))
	if peer.Endpoint.IsValid() {
		fmt.Fprintf(builder, "endpoint=%s\n", peer.Endpoint)
	}
	if peer.PersistentKeepalive > 0 {
		fmt.Fprintf(builder, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}

	return nil
}

func deviceLogger(logger *slog.Logger) *device.Logger {
	if logger == nil {
		return device.NewLogger(device.LogLevelSilent, "")
	}

	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug("wireguard", "message", fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			logger.Warn("wireguard", "message", fmt.Sprintf(format, args...))
		},
	}
}
