package direct

import (
	"net"
	"net/netip"
	"sync"
)

// perAddressListener closes connections from a source address that already
// holds max open connections, so one host cannot take every slot of the
// overall connection limit.
type perAddressListener struct {
	net.Listener
	max int

	mu   sync.Mutex
	open map[netip.Addr]int
}

func limitPerAddress(listener net.Listener, max int) net.Listener {
	return &perAddressListener{Listener: listener, max: max, open: make(map[netip.Addr]int)}
}

func (l *perAddressListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		address, ok := sourceAddress(conn)
		if !ok || !l.acquire(address) {
			_ = conn.Close()
			continue
		}

		return &trackedConn{Conn: conn, release: func() { l.release(address) }}, nil
	}
}

func (l *perAddressListener) acquire(address netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.open[address] >= l.max {
		return false
	}
	l.open[address]++

	return true
}

func (l *perAddressListener) release(address netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.open[address]--
	if l.open[address] <= 0 {
		delete(l.open, address)
	}
}

func sourceAddress(conn net.Conn) (netip.Addr, bool) {
	address, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}

	return address.Addr().Unmap(), true
}

// trackedConn releases its slot exactly once when closed.
type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)

	return err
}
