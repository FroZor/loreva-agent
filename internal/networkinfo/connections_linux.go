//go:build linux

package networkinfo

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

type procSocketTable struct {
	path       string
	family     uint32
	socketType uint32
	tcp        bool
}

func connectionStats(ctx context.Context, limit int) ([]gopsutilnet.ConnectionStat, error) {
	tables := []procSocketTable{
		{path: "/proc/net/tcp", family: syscall.AF_INET, socketType: syscall.SOCK_STREAM, tcp: true},
		{path: "/proc/net/tcp6", family: syscall.AF_INET6, socketType: syscall.SOCK_STREAM, tcp: true},
		{path: "/proc/net/udp", family: syscall.AF_INET, socketType: syscall.SOCK_DGRAM},
		{path: "/proc/net/udp6", family: syscall.AF_INET6, socketType: syscall.SOCK_DGRAM},
	}

	connections := make([]gopsutilnet.ConnectionStat, 0, limit)
	readTables := 0
	var lastErr error
	for _, table := range tables {
		remaining := limit - len(connections)
		if remaining == 0 {
			break
		}

		entries, err := readProcSocketTable(ctx, table, remaining)
		if err != nil {
			lastErr = err
			continue
		}

		readTables++
		connections = append(connections, entries...)
	}
	if readTables == 0 && lastErr != nil {
		return nil, lastErr
	}

	return connections, nil
}

func readProcSocketTable(
	ctx context.Context,
	table procSocketTable,
	limit int,
) (connections []gopsutilnet.ConnectionStat, resultErr error) {
	file, err := os.Open(table.path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close %s: %w", table.path, closeErr))
		}
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	if scanner.Scan() {
		// Skip the kernel table header.
	}

	connections = make([]gopsutilnet.ConnectionStat, 0, limit)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		connection, include := parseProcSocketLine(scanner.Text(), table)
		if !include {
			continue
		}

		connections = append(connections, connection)
		if len(connections) == limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", table.path, err)
	}

	return connections, nil
}

func parseProcSocketLine(line string, table procSocketTable) (gopsutilnet.ConnectionStat, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 || (table.tcp && fields[3] != "0A") {
		return gopsutilnet.ConnectionStat{}, false
	}

	localAddress, err := parseProcSocketAddress(fields[1], table.family)
	if err != nil || localAddress.Port == 0 {
		return gopsutilnet.ConnectionStat{}, false
	}
	remoteAddress, err := parseProcSocketAddress(fields[2], table.family)
	if err != nil {
		return gopsutilnet.ConnectionStat{}, false
	}
	if !table.tcp && remoteAddress.Port != 0 {
		return gopsutilnet.ConnectionStat{}, false
	}

	status := ""
	if table.tcp {
		status = "LISTEN"
	}

	return gopsutilnet.ConnectionStat{
		Family: table.family,
		Type:   table.socketType,
		Laddr:  localAddress,
		Raddr:  remoteAddress,
		Status: status,
	}, true
}

func parseProcSocketAddress(value string, family uint32) (gopsutilnet.Addr, error) {
	address, portText, found := strings.Cut(value, ":")
	if !found {
		return gopsutilnet.Addr{}, errors.New("socket address has no port")
	}

	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return gopsutilnet.Addr{}, err
	}

	decoded, err := hex.DecodeString(address)
	if err != nil {
		return gopsutilnet.Addr{}, err
	}

	var ip net.IP
	switch family {
	case syscall.AF_INET:
		if len(decoded) != net.IPv4len {
			return gopsutilnet.Addr{}, errors.New("invalid IPv4 socket address")
		}
		reverseBytes(decoded)
		ip = net.IP(decoded)
	case syscall.AF_INET6:
		if len(decoded) != net.IPv6len {
			return gopsutilnet.Addr{}, errors.New("invalid IPv6 socket address")
		}
		for index := 0; index < len(decoded); index += 4 {
			reverseBytes(decoded[index : index+4])
		}
		ip = net.IP(decoded)
	default:
		return gopsutilnet.Addr{}, errors.New("unsupported socket address family")
	}

	return gopsutilnet.Addr{IP: ip.String(), Port: uint32(port)}, nil
}

func reverseBytes(data []byte) {
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
}
