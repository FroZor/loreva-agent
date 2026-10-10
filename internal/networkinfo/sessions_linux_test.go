//go:build linux

package networkinfo

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogindSessionsListUserLogins(t *testing.T) {
	directory := t.TempDir()
	files := map[string]string{
		"3": "# This is private data. Do not parse.\nUID=1000\nUSER=rick\nSTATE=active\nREMOTE=1\nCLASS=user\nSERVICE=sshd\n" +
			"LEADER=1234\nREMOTE_HOST=203.0.113.5\nTTY=pts/0\nREALTIME=1791230000000000\n",
		"3.ref": "",
		"c1":    "UID=120\nUSER=gdm\nCLASS=greeter\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := logindSessions(directory)
	if err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	session := sessions[0]
	if session.User != "rick" || session.RemoteHost != "203.0.113.5" || session.Service != "sshd" || session.PID != 1234 || session.TTY != "pts/0" {
		t.Fatalf("session = %+v", session)
	}
	if session.StartedAt == nil || !session.StartedAt.Equal(time.UnixMicro(1791230000000000)) {
		t.Fatalf("started at = %v", session.StartedAt)
	}
}

func TestUtmpSessionsReadUserProcesses(t *testing.T) {
	record := func(kind int16, pid int32, line, user, host string, seconds int32) []byte {
		data := make([]byte, utmpRecordSize)
		binary.LittleEndian.PutUint16(data[0:2], uint16(kind))
		binary.LittleEndian.PutUint32(data[4:8], uint32(pid))
		copy(data[8:40], line)
		copy(data[44:76], user)
		copy(data[76:332], host)
		binary.LittleEndian.PutUint32(data[340:344], uint32(seconds))
		return data
	}
	path := filepath.Join(t.TempDir(), "utmp")
	data := append(record(2, 0, "~", "reboot", "6.8.0", 1791220000), record(utmpUserProcess, 812, "pts/1", "admin", "198.51.100.9", 1791230000)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := utmpSessions(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(sessions) != 1 || sessions[0].User != "admin" || sessions[0].TTY != "pts/1" || sessions[0].RemoteHost != "198.51.100.9" || sessions[0].PID != 812 {
		t.Fatalf("sessions = %+v", sessions)
	}
	if sessions[0].StartedAt == nil || sessions[0].StartedAt.Unix() != 1791230000 {
		t.Fatalf("started at = %v", sessions[0].StartedAt)
	}
}
