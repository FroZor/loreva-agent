package tunnel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
)

const prefixBits = 64

// NewPrefix returns a random unique local IPv6 /64 (RFC 4193): fd00::/8 with
// a random 40-bit global ID and subnet zero.
func NewPrefix() (netip.Prefix, error) {
	var address [16]byte
	address[0] = 0xfd
	if _, err := rand.Read(address[1:6]); err != nil {
		return netip.Prefix{}, fmt.Errorf("generate tunnel prefix: %w", err)
	}

	return netip.PrefixFrom(netip.AddrFrom16(address), prefixBits), nil
}

// ParsePrefix parses and validates a stored tunnel prefix.
func ParsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse tunnel prefix: %w", err)
	}
	if !prefix.Addr().Is6() || prefix.Bits() != prefixBits || prefix.Masked() != prefix ||
		prefix.Addr().As16()[0] != 0xfd {
		return netip.Prefix{}, errors.New("tunnel prefix must be a unique local IPv6 /64")
	}

	return prefix, nil
}

// NodeAddress returns the node's own address: the first address of prefix.
func NodeAddress(prefix netip.Prefix) netip.Addr {
	return prefix.Addr().Next()
}

// RandomAddress returns a random address in prefix other than the subnet
// router anycast and node addresses. Random 64-bit interface IDs keep peer
// addresses from being reused in practice.
func RandomAddress(prefix netip.Prefix) (netip.Addr, error) {
	address := prefix.Addr().As16()
	if _, err := rand.Read(address[8:]); err != nil {
		return netip.Addr{}, fmt.Errorf("generate tunnel address: %w", err)
	}

	random := netip.AddrFrom16(address)
	if random == prefix.Addr() || random == NodeAddress(prefix) {
		return netip.Addr{}, errors.New("generated a reserved tunnel address; retry")
	}

	return random, nil
}
