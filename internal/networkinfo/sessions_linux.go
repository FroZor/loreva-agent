//go:build linux

package networkinfo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxSessions    = 256
	maxSessionFile = 16 * 1024
	// utmpRecordSize is sizeof(struct utmp) in glibc on 64-bit Linux.
	utmpRecordSize  = 384
	utmpUserProcess = 7
	maxUtmpFile     = maxSessions * 16 * utmpRecordSize
)

// collectSessions lists logged-in users. systemd-logind keeps one file per
// session; systems without logind still write utmp, which who reads.
func collectSessions() ([]protocol.LoginSession, error) {
	sessions, err := logindSessions(hostfs.Run("systemd", "sessions"))
	if !errors.Is(err, fs.ErrNotExist) {
		return sessions, err
	}

	return utmpSessions(hostfs.Run("utmp"))
}

// logindSessions reads the session files of systemd-logind, the data
// loginctl shows. They are KEY=value lines.
func logindSessions(directory string) ([]protocol.LoginSession, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	sessions := make([]protocol.LoginSession, 0)
	for _, entry := range entries {
		if len(sessions) == maxSessions {
			break
		}
		if !entry.Type().IsRegular() || strings.HasSuffix(entry.Name(), ".ref") {
			continue
		}
		data, err := readNetworkFile(filepath.Join(directory, entry.Name()), maxSessionFile)
		if err != nil {
			continue
		}
		fields := keyValues(data)
		if fields["USER"] == "" || fields["CLASS"] != "user" && fields["CLASS"] != "" {
			continue
		}

		session := protocol.LoginSession{
			User:       sanitizeNetworkValue(fields["USER"], 64),
			TTY:        sanitizeNetworkValue(fields["TTY"], 64),
			RemoteHost: sanitizeNetworkValue(fields["REMOTE_HOST"], 255),
			Service:    sanitizeNetworkValue(fields["SERVICE"], 64),
			State:      sanitizeNetworkValue(fields["STATE"], 32),
		}
		if leader, err := strconv.ParseInt(fields["LEADER"], 10, 32); err == nil && leader > 0 {
			session.PID = int32(leader)
		}
		if micros, err := strconv.ParseInt(fields["REALTIME"], 10, 64); err == nil && micros > 0 {
			started := time.UnixMicro(micros).UTC()
			session.StartedAt = &started
		}
		sessions = append(sessions, session)
	}
	sortSessions(sessions)

	return sessions, nil
}

func keyValues(data []byte) map[string]string {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found && !strings.HasPrefix(key, "#") {
			fields[key] = value
		}
	}

	return fields
}

// utmpSessions reads USER_PROCESS records of the glibc utmp file.
func utmpSessions(path string) ([]protocol.LoginSession, error) {
	// utmp can hold many dead records; only its start is read.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxUtmpFile))
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	sessions := make([]protocol.LoginSession, 0)
	for offset := 0; offset+utmpRecordSize <= len(data) && len(sessions) < maxSessions; offset += utmpRecordSize {
		record := data[offset : offset+utmpRecordSize]
		if int16(binary.LittleEndian.Uint16(record[0:2])) != utmpUserProcess {
			continue
		}
		user := cString(record[44:76])
		if user == "" {
			continue
		}

		session := protocol.LoginSession{
			User:       sanitizeNetworkValue(user, 64),
			TTY:        sanitizeNetworkValue(cString(record[8:40]), 64),
			RemoteHost: sanitizeNetworkValue(cString(record[76:332]), 255),
			PID:        int32(binary.LittleEndian.Uint32(record[4:8])),
		}
		if seconds := int64(int32(binary.LittleEndian.Uint32(record[340:344]))); seconds > 0 {
			started := time.Unix(seconds, 0).UTC()
			session.StartedAt = &started
		}
		sessions = append(sessions, session)
	}
	sortSessions(sessions)

	return sessions, nil
}

func cString(value []byte) string {
	if end := bytes.IndexByte(value, 0); end >= 0 {
		value = value[:end]
	}

	return string(value)
}

func sortSessions(sessions []protocol.LoginSession) {
	slices.SortStableFunc(sessions, func(a, b protocol.LoginSession) int {
		switch {
		case a.StartedAt == nil || b.StartedAt == nil:
			return strings.Compare(a.User, b.User)
		default:
			return a.StartedAt.Compare(*b.StartedAt)
		}
	})
}
