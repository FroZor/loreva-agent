//go:build linux

package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/hostfs"
)

const (
	// clockTicks is USER_HZ, which the kernel fixes at 100 for every
	// user-space ABI regardless of its internal tick rate.
	clockTicks = 100
	// maxCommandLine bounds one command line; longer ones are cut.
	maxCommandLine = 32 * 1024
	maxStatusFile  = 64 * 1024
)

var containerIDPattern = regexp.MustCompile(`(?:docker[-/]|/docker/|cri-containerd-|crio-|libpod-)([0-9a-f]{64})`)

// Scan reads every process. Processes that exit during the scan are skipped.
func Scan() ([]Process, error) {
	bootTime, err := BootTime()
	if err != nil {
		return nil, err
	}
	directory, err := os.Open(hostfs.Proc())
	if err != nil {
		return nil, err
	}
	defer directory.Close()

	pageSize := uint64(os.Getpagesize())
	var processes []Process
	for {
		names, err := directory.Readdirnames(512)
		for _, name := range names {
			pid, convErr := strconv.ParseInt(name, 10, 32)
			if convErr != nil || pid <= 0 {
				continue
			}
			data, readErr := os.ReadFile(hostfs.Proc(name, "stat"))
			if readErr != nil {
				continue
			}
			process, ok := parseStat(data, bootTime, pageSize)
			if ok && process.PID == int32(pid) {
				processes = append(processes, process)
			}
		}
		if errors.Is(err, io.EOF) {
			return processes, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// BootTime returns when the host booted, from the btime line of /proc/stat.
func BootTime() (time.Time, error) {
	data, err := os.ReadFile(hostfs.Proc("stat"))
	if err != nil {
		return time.Time{}, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if value, found := strings.CutPrefix(line, "btime "); found {
			seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(seconds, 0).UTC(), nil
		}
	}

	return time.Time{}, errors.New("btime is missing from /proc/stat")
}

// parseStat parses /proc/<pid>/stat. The command name is in parentheses and
// may itself contain spaces and parentheses, so fields are counted from the
// last closing parenthesis.
func parseStat(data []byte, bootTime time.Time, pageSize uint64) (Process, bool) {
	open := bytes.IndexByte(data, '(')
	closing := bytes.LastIndexByte(data, ')')
	if open < 0 || closing < open {
		return Process{}, false
	}
	pid, err := strconv.ParseInt(string(bytes.TrimSpace(data[:open])), 10, 32)
	if err != nil {
		return Process{}, false
	}
	// fields[0] is the state, which is field 3 in proc(5).
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) < 22 {
		return Process{}, false
	}
	field := func(number int) uint64 {
		value, _ := strconv.ParseUint(fields[number-3], 10, 64)
		return value
	}
	parent, _ := strconv.ParseInt(fields[1], 10, 32)
	rss, _ := strconv.ParseInt(fields[24-3], 10, 64)

	return Process{
		PID:        int32(pid),
		ParentPID:  int32(parent),
		Name:       string(data[open+1 : closing]),
		State:      normalizeState(fields[0]),
		StartedAt:  bootTime.Add(time.Duration(field(22)) * time.Second / clockTicks),
		CPUSeconds: float64(field(14)+field(15)) / clockTicks,
		Threads:    int32(field(20)),
		VMSBytes:   field(23),
		RSSBytes:   uint64(max(rss, 0)) * pageSize,
	}, true
}

func normalizeState(code string) string {
	switch code {
	case "R":
		return StateRunning
	case "D":
		return StateBlocked
	case "Z", "X", "x":
		return StateZombie
	case "T", "t":
		return StateStopped
	case "I":
		return StateIdle
	default:
		return StateSleeping
	}
}

// ReadIdentity reads the owner and container of one process. users maps
// UIDs to names and may be nil.
func ReadIdentity(pid int32, users map[uint32]string) Identity {
	name := strconv.Itoa(int(pid))
	var identity Identity

	if uid, ok := readUID(hostfs.Proc(name, "status")); ok {
		identity.UID = &uid
		identity.User = users[uid]
	}
	identity.ContainerID = readContainerID(hostfs.Proc(name, "cgroup"))

	return identity
}

// ReadUsage reads the I/O counters and open file count of one process.
func ReadUsage(pid int32) Usage {
	name := strconv.Itoa(int(pid))
	var usage Usage

	usage.ReadBytes, usage.WriteBytes = readIO(hostfs.Proc(name, "io"))
	if entries, err := os.ReadDir(hostfs.Proc(name, "fd")); err == nil {
		count := int32(len(entries))
		usage.FileDescriptors = &count
	}

	return usage
}

// Read reads one process's stat file.
func Read(pid int32) (Process, error) {
	bootTime, err := BootTime()
	if err != nil {
		return Process{}, err
	}
	data, err := os.ReadFile(hostfs.Proc(strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return Process{}, err
	}

	process, ok := parseStat(data, bootTime, uint64(os.Getpagesize()))
	if !ok || process.PID != pid {
		return Process{}, os.ErrNotExist
	}

	return process, nil
}

// CommandLine returns the arguments of one process, cut at 32 KiB; truncated
// reports the cut. It is empty for kernel threads and unreadable processes.
func CommandLine(pid int32) (arguments []string, truncated bool) {
	return readCommandLine(hostfs.Proc(strconv.Itoa(int(pid)), "cmdline"))
}

func readUID(path string) (uint32, bool) {
	data, err := readBounded(path, maxStatusFile)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if value, found := strings.CutPrefix(line, "Uid:"); found {
			fields := strings.Fields(value)
			if len(fields) == 0 {
				return 0, false
			}
			uid, err := strconv.ParseUint(fields[0], 10, 32)
			return uint32(uid), err == nil
		}
	}

	return 0, false
}

func readCommandLine(path string) ([]string, bool) {
	data, err := readBounded(path, maxCommandLine+1)
	if err != nil || len(data) == 0 {
		return []string{}, false
	}
	truncated := len(data) > maxCommandLine
	if truncated {
		data = data[:maxCommandLine]
	}

	arguments := strings.Split(strings.ToValidUTF8(string(bytes.TrimRight(data, "\x00")), "\uFFFD"), "\x00")

	return arguments, truncated
}

func readContainerID(path string) string {
	data, err := readBounded(path, maxStatusFile)
	if err != nil {
		return ""
	}
	if match := containerIDPattern.FindSubmatch(data); match != nil {
		return string(match[1])
	}

	return ""
}

func readIO(path string) (*uint64, *uint64) {
	data, err := readBounded(path, maxStatusFile)
	if err != nil {
		return nil, nil
	}
	var read, write *uint64
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "read_bytes":
			read = &number
		case "write_bytes":
			write = &number
		}
	}

	return read, write
}

// Users reads the host's /etc/passwd into a UID to name map.
func Users() map[uint32]string {
	users := make(map[uint32]string)
	data, err := readBounded(hostfs.Etc("passwd"), 4*1024*1024)
	if err != nil {
		return users
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		if _, exists := users[uint32(uid)]; !exists {
			users[uint32(uid)] = fields[0]
		}
	}

	return users
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(io.LimitReader(file, limit))
}

// SocketOwners maps socket inodes to the processes holding them, from the
// links in /proc/<pid>/fd. Complete is false when some processes' file
// tables could not be read, which needs root or CAP_SYS_PTRACE.
func SocketOwners() (owners map[uint64]int32, complete bool) {
	owners = make(map[uint64]int32)
	entries, err := os.ReadDir(hostfs.Proc())
	if err != nil {
		return owners, false
	}

	complete = true
	for _, entry := range entries {
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid <= 0 {
			continue
		}
		directory := hostfs.Proc(entry.Name(), "fd")
		descriptors, err := os.ReadDir(directory)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				complete = false
			}
			continue
		}
		for _, descriptor := range descriptors {
			target, err := os.Readlink(directory + "/" + descriptor.Name())
			if err != nil {
				continue
			}
			inode, found := strings.CutPrefix(target, "socket:[")
			if !found {
				continue
			}
			number, err := strconv.ParseUint(strings.TrimSuffix(inode, "]"), 10, 64)
			if err != nil {
				continue
			}
			if _, taken := owners[number]; !taken {
				owners[number] = int32(pid)
			}
		}
	}

	return owners, complete
}

// Name returns the command name of one process, or "" when it exited.
func Name(pid int32) string {
	data, err := readBounded(hostfs.Proc(strconv.Itoa(int(pid)), "comm"), 256)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}
