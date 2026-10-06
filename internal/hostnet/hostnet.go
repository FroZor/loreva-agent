// Package hostnet lists the host's network interfaces. When the agent runs in
// a container with its own network namespace, the standard library would
// describe the container's interfaces; this package then reads the host's
// view from the mounted /proc and /sys instead.
package hostnet

import (
	"net"
	"net/netip"
	"strconv"
)

// Interface is one network interface of the host.
type Interface struct {
	Index        int
	Name         string
	HardwareAddr net.HardwareAddr
	MTU          int
	Flags        net.Flags
	Addresses    []netip.Prefix
}

// ID is the stable identifier reports use for an interface.
func (i Interface) ID() string {
	return "network:" + strconv.Itoa(i.Index)
}

// standardInterfaces lists the interfaces of the agent's own namespace.
func standardInterfaces() ([]Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make([]Interface, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		item := Interface{
			Index:        networkInterface.Index,
			Name:         networkInterface.Name,
			HardwareAddr: networkInterface.HardwareAddr,
			MTU:          networkInterface.MTU,
			Flags:        networkInterface.Flags,
		}
		addresses, _ := networkInterface.Addrs()
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil {
				item.Addresses = append(item.Addresses, netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()))
			}
		}
		result = append(result, item)
	}

	return result, nil
}
