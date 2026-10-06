//go:build linux

package networkinfo

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/procfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxConfigFile    = 256 * 1024
	maxConfigFiles   = 64
	maxSecurityItems = 128
)

// collectSecurity finds sshd settings, intrusion prevention, and mandatory
// access control. Running tools are found in the process table, so the
// check works the same on systemd and other init systems.
func collectSecurity(listeners []protocol.ListeningPort) (protocol.SecurityInformation, []protocol.CollectionIssue) {
	security := protocol.SecurityInformation{
		IntrusionPrevention:    []protocol.SecurityService{},
		MandatoryAccessControl: mandatoryAccessControl(),
	}
	var issues []protocol.CollectionIssue

	running := make(map[string]bool)
	if processes, err := procfs.Scan(); err == nil {
		for _, process := range processes {
			running[process.Name] = true
		}
	} else {
		issues = append(issues, networkIssue("security.processes", err))
	}

	ssh, err := sshConfiguration()
	if err != nil {
		issues = append(issues, networkIssue("security.ssh", err))
	}
	if ssh != nil || running["sshd"] {
		if ssh == nil {
			ssh = &protocol.SSHConfiguration{ConfiguredPorts: []uint16{}}
		}
		ssh.Running = running["sshd"]
		ssh.ListeningPorts = []uint16{}
		for _, listener := range listeners {
			if listener.ProcessName == "sshd" && listener.Protocol == "tcp" && !slices.Contains(ssh.ListeningPorts, listener.Port) {
				ssh.ListeningPorts = append(ssh.ListeningPorts, listener.Port)
			}
		}
		security.SSH = ssh
	}

	if service, found := fail2ban(running["fail2ban-server"]); found {
		security.IntrusionPrevention = append(security.IntrusionPrevention, service)
	}
	if service, found := crowdsec(running); found {
		security.IntrusionPrevention = append(security.IntrusionPrevention, service)
	}

	return security, issues
}

// sshConfiguration reads sshd_config and its includes. sshd keeps the first
// value it reads for each keyword; settings inside Match blocks apply only
// to some connections and are left out.
func sshConfiguration() (*protocol.SSHConfiguration, error) {
	values := make(map[string]string)
	ports := []uint16{}
	files := 0
	if err := readSSHConfig(hostfs.Etc("ssh/sshd_config"), values, &ports, &files); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		ports = append(ports, 22)
	}

	return &protocol.SSHConfiguration{
		ConfiguredPorts:        ports,
		PermitRootLogin:        values["permitrootlogin"],
		PasswordAuthentication: values["passwordauthentication"],
		PubkeyAuthentication:   values["pubkeyauthentication"],
	}, nil
}

func readSSHConfig(path string, values map[string]string, ports *[]uint16, files *int) error {
	*files++
	if *files > maxConfigFiles {
		return nil
	}
	data, err := readNetworkFile(path, maxConfigFile)
	if err != nil {
		return err
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(strings.ReplaceAll(line, "=", " "))
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		keyword := strings.ToLower(fields[0])
		switch keyword {
		case "match":
			return nil
		case "include":
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = "/etc/ssh/" + pattern
				}
				matches, _ := filepath.Glob(hostfs.Root(filepath.Clean(pattern)))
				slices.Sort(matches)
				for _, match := range matches {
					_ = readSSHConfig(match, values, ports, files)
				}
			}
		case "port":
			// Every Port line adds a port; ports are not first-wins.
			if port, err := strconv.ParseUint(fields[1], 10, 16); err == nil && port > 0 && !slices.Contains(*ports, uint16(port)) {
				*ports = append(*ports, uint16(port))
			}
		case "permitrootlogin", "passwordauthentication", "pubkeyauthentication":
			if _, set := values[keyword]; !set {
				values[keyword] = sanitizeNetworkValue(strings.ToLower(fields[1]), 32)
			}
		}
	}

	return nil
}

// fail2ban reports fail2ban when it is installed or running, with the jails
// its configuration enables. Files are read in fail2ban's order, so .local
// files and jail.d override jail.conf.
func fail2ban(running bool) (protocol.SecurityService, bool) {
	base := hostfs.Etc("fail2ban")
	var files []string
	for _, pattern := range []string{"jail.conf", "jail.d/*.conf", "jail.local", "jail.d/*.local"} {
		matches, _ := filepath.Glob(filepath.Join(base, pattern))
		slices.Sort(matches)
		files = append(files, matches...)
	}
	if len(files) == 0 && !running {
		return protocol.SecurityService{}, false
	}

	// Jails without their own enabled line inherit the one in [DEFAULT].
	enabled := make(map[string]*bool)
	defaultEnabled := false
	for _, path := range files[:min(len(files), maxConfigFiles)] {
		data, err := readNetworkFile(path, maxConfigFile)
		if err != nil {
			continue
		}
		section := ""
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(line[1 : len(line)-1])
				if _, known := enabled[section]; !known && jailSection(section) {
					enabled[section] = nil
				}
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "enabled") {
				continue
			}
			on := strings.EqualFold(strings.TrimSpace(value), "true")
			switch {
			case section == "DEFAULT":
				defaultEnabled = on
			case jailSection(section):
				enabled[section] = &on
			}
		}
	}

	var jails []string
	for jail, on := range enabled {
		if on != nil && *on || on == nil && defaultEnabled {
			jails = append(jails, sanitizeNetworkValue(jail, 64))
		}
	}
	slices.Sort(jails)

	return protocol.SecurityService{Name: "fail2ban", Status: runningStatus(running), Details: jails[:min(len(jails), maxSecurityItems)]}, true
}

func jailSection(section string) bool {
	switch section {
	case "", "DEFAULT", "INCLUDES", "Definition", "Init":
		return false
	default:
		return true
	}
}

// crowdsec reports the CrowdSec engine and the bouncers that enforce its
// decisions.
func crowdsec(running map[string]bool) (protocol.SecurityService, bool) {
	installed := fileExists(hostfs.Etc("crowdsec/config.yaml"))
	var bouncers []string
	for name := range running {
		// Process names are cut to 15 characters, so bouncers are matched
		// by prefix.
		if strings.HasPrefix(name, "crowdsec-") {
			bouncers = append(bouncers, name)
		}
	}
	if !installed && !running["crowdsec"] && len(bouncers) == 0 {
		return protocol.SecurityService{}, false
	}
	slices.Sort(bouncers)

	return protocol.SecurityService{Name: "crowdsec", Status: runningStatus(running["crowdsec"]), Details: bouncers}, true
}

// mandatoryAccessControl reports AppArmor and SELinux from their sysfs
// switches, which need no privileges.
func mandatoryAccessControl() []protocol.SecurityService {
	services := []protocol.SecurityService{}
	if value, err := readNetworkFile(hostfs.Sys("module/apparmor/parameters/enabled"), 16); err == nil {
		status := "disabled"
		if strings.TrimSpace(string(value)) == "Y" {
			status = "enabled"
		}
		services = append(services, protocol.SecurityService{Name: "apparmor", Status: status})
	}
	if value, err := readNetworkFile(hostfs.Sys("fs/selinux/enforce"), 16); err == nil {
		status := "permissive"
		if strings.TrimSpace(string(value)) == "1" {
			status = "enforcing"
		}
		services = append(services, protocol.SecurityService{Name: "selinux", Status: status})
	}

	return services
}

func runningStatus(running bool) string {
	if running {
		return "running"
	}

	return "stopped"
}
