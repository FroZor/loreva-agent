//go:build linux

package networkinfo

import (
	"encoding/hex"
	"encoding/xml"
	"path/filepath"
	"slices"
	"strings"

	"github.com/FroZor/loreva-agent/internal/hostfs"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	maxManagerFile  = 1024 * 1024
	maxManagerRules = 1024
	maxZoneFiles    = 128
)

// ufwConfiguration reads ufw's own files, the source of ufw status: the
// enabled flag, default policies, and the "### tuple ###" lines ufw writes
// for every user rule (ufw 0.36, backend_iptables.py _write_rules).
func ufwConfiguration() (*protocol.UFWConfiguration, error) {
	configuration, err := readNetworkFile(hostfs.Etc("ufw", "ufw.conf"), 64*1024)
	if err != nil {
		return nil, err
	}

	ufw := &protocol.UFWConfiguration{
		Enabled: strings.EqualFold(keyValues(configuration)["ENABLED"], "yes"),
		Rules:   []protocol.UFWRule{},
	}
	if defaults, err := readNetworkFile(hostfs.Etc("default", "ufw"), 64*1024); err == nil {
		policies := keyValues(defaults)
		ufw.DefaultIncoming = ufwPolicy(policies["DEFAULT_INPUT_POLICY"])
		ufw.DefaultOutgoing = ufwPolicy(policies["DEFAULT_OUTPUT_POLICY"])
		ufw.DefaultRouted = ufwPolicy(policies["DEFAULT_FORWARD_POLICY"])
	}

	var readErr error
	for _, file := range []struct{ name, family string }{{"user.rules", "ipv4"}, {"user6.rules", "ipv6"}} {
		data, err := readNetworkFile(hostfs.Etc("ufw", file.name), maxManagerFile)
		if err != nil {
			readErr = err
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if rule, ok := parseUFWTuple(line, file.family); ok && len(ufw.Rules) < maxManagerRules {
				ufw.Rules = append(ufw.Rules, rule)
			}
		}
	}

	return ufw, readErr
}

// ufwPolicy turns DROP into deny, as ufw status shows it.
func ufwPolicy(value string) string {
	switch strings.ToUpper(strings.Trim(value, `"`)) {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	case "REJECT":
		return "reject"
	default:
		return ""
	}
}

// parseUFWTuple reads "### tuple ### action proto dport dst sport src
// [dapp sapp] direction[_iface] [comment=hex]".
func parseUFWTuple(line, family string) (protocol.UFWRule, bool) {
	tuple, found := strings.CutPrefix(strings.TrimSpace(line), "### tuple ###")
	if !found {
		return protocol.UFWRule{}, false
	}
	comment := ""
	if before, encoded, found := strings.Cut(tuple, " comment="); found {
		tuple = before
		if decoded, err := hex.DecodeString(strings.TrimSpace(encoded)); err == nil {
			comment = string(decoded)
		}
	}
	fields := strings.Fields(tuple)
	if len(fields) != 7 && len(fields) != 9 {
		return protocol.UFWRule{}, false
	}

	rule := protocol.UFWRule{
		Family:      family,
		Protocol:    sanitizeNetworkValue(fields[1], 16),
		ToPort:      sanitizeNetworkValue(fields[2], 255),
		ToAddress:   sanitizeNetworkValue(fields[3], 255),
		FromPort:    sanitizeNetworkValue(fields[4], 255),
		FromAddress: sanitizeNetworkValue(fields[5], 255),
		Comment:     sanitizeNetworkValue(comment, 255),
	}
	action := fields[0]
	if route, found := strings.CutPrefix(action, "route:"); found {
		rule.Route, action = true, route
	}
	rule.Action, rule.Log, _ = strings.Cut(action, "_")
	rule.Action = sanitizeNetworkValue(rule.Action, 16)
	rule.Log = sanitizeNetworkValue(rule.Log, 16)
	if len(fields) == 9 {
		rule.ToApp = ufwApp(fields[6])
		rule.FromApp = ufwApp(fields[7])
	}

	// Direction is "in", "out", "in_eth0", "out_eth0", or
	// "in_eth0!out_eth1" for route rules.
	interfaces := fields[len(fields)-1]
	rule.Direction, _, _ = strings.Cut(interfaces, "_")
	for part := range strings.SplitSeq(interfaces, "!") {
		if name, found := strings.CutPrefix(part, "in_"); found {
			rule.InterfaceIn = sanitizeNetworkValue(name, 64)
		}
		if name, found := strings.CutPrefix(part, "out_"); found {
			rule.InterfaceOut = sanitizeNetworkValue(name, 64)
		}
	}
	rule.Direction = sanitizeNetworkValue(rule.Direction, 8)

	return rule, true
}

func ufwApp(value string) string {
	if value == "-" {
		return ""
	}

	return sanitizeNetworkValue(strings.ReplaceAll(value, "%20", " "), 255)
}

// firewalldZoneFile is the zone format of firewalld.zone(5).
type firewalldZoneFile struct {
	Target     string `xml:"target,attr"`
	Interfaces []struct {
		Name string `xml:"name,attr"`
	} `xml:"interface"`
	Sources []struct {
		Address string `xml:"address,attr"`
		MAC     string `xml:"mac,attr"`
		IPSet   string `xml:"ipset,attr"`
	} `xml:"source"`
	Services []struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
	Ports []struct {
		Port     string `xml:"port,attr"`
		Protocol string `xml:"protocol,attr"`
	} `xml:"port"`
	Masquerade *struct{} `xml:"masquerade"`
	Rules      []struct {
		Inner string `xml:",innerxml"`
	} `xml:"rule"`
}

// firewalldConfiguration reads the permanent zones: files in
// /etc/firewalld/zones replace the defaults of the same name.
func firewalldConfiguration() (*protocol.FirewalldConfiguration, error) {
	configuration, err := readNetworkFile(hostfs.Etc("firewalld", "firewalld.conf"), 64*1024)
	if err != nil {
		return nil, err
	}

	result := &protocol.FirewalldConfiguration{
		DefaultZone: sanitizeNetworkValue(keyValues(configuration)["DefaultZone"], 64),
		Zones:       []protocol.FirewalldZone{},
	}
	files := make(map[string]string)
	for _, directory := range []string{hostfs.Root("/usr/lib/firewalld/zones"), hostfs.Etc("firewalld", "zones")} {
		matches, _ := filepath.Glob(filepath.Join(directory, "*.xml"))
		for _, match := range matches[:min(len(matches), maxZoneFiles)] {
			files[strings.TrimSuffix(filepath.Base(match), ".xml")] = match
		}
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		zone, ok := readFirewalldZone(name, files[name])
		if ok && (name == result.DefaultZone || len(zone.Interfaces) > 0 || len(zone.Sources) > 0) {
			result.Zones = append(result.Zones, zone)
		}
	}

	return result, nil
}

func readFirewalldZone(name, path string) (protocol.FirewalldZone, bool) {
	data, err := readNetworkFile(path, maxManagerFile)
	if err != nil {
		return protocol.FirewalldZone{}, false
	}
	var file firewalldZoneFile
	if err := xml.Unmarshal(data, &file); err != nil {
		return protocol.FirewalldZone{}, false
	}

	zone := protocol.FirewalldZone{
		Name:       sanitizeNetworkValue(name, 64),
		Target:     sanitizeNetworkValue(file.Target, 32),
		Interfaces: []string{},
		Sources:    []string{},
		Services:   []string{},
		Ports:      []string{},
		Masquerade: file.Masquerade != nil,
		RichRules:  []string{},
	}
	if zone.Target == "" {
		zone.Target = "default"
	}
	for _, item := range file.Interfaces[:min(len(file.Interfaces), maxManagerRules)] {
		zone.Interfaces = append(zone.Interfaces, sanitizeNetworkValue(item.Name, 64))
	}
	for _, item := range file.Sources[:min(len(file.Sources), maxManagerRules)] {
		source := item.Address
		switch {
		case item.MAC != "":
			source = "mac:" + item.MAC
		case item.IPSet != "":
			source = "ipset:" + item.IPSet
		}
		zone.Sources = append(zone.Sources, sanitizeNetworkValue(source, 255))
	}
	for _, item := range file.Services[:min(len(file.Services), maxManagerRules)] {
		zone.Services = append(zone.Services, sanitizeNetworkValue(item.Name, 64))
	}
	for _, item := range file.Ports[:min(len(file.Ports), maxManagerRules)] {
		zone.Ports = append(zone.Ports, sanitizeNetworkValue(item.Port+"/"+item.Protocol, 64))
	}
	for _, item := range file.Rules[:min(len(file.Rules), maxManagerRules)] {
		zone.RichRules = append(zone.RichRules, sanitizeNetworkValue(strings.Join(strings.Fields(item.Inner), " "), 1024))
	}

	return zone, true
}
