//go:build linux

package networkinfo

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestUFWConfigurationReadsRuleTuples(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_ETC", root)
	writeFiles(t, root, map[string]string{
		"ufw/ufw.conf": "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n",
		"default/ufw":  "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n",
		"ufw/user.rules": "*filter\n### RULES ###\n\n" +
			"### tuple ### allow tcp 22 0.0.0.0/0 any 203.0.113.0/24 in comment=61646d696e\n" +
			"-A ufw-user-input -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT\n\n" +
			"### tuple ### limit_log any 80 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in_eth0\n" +
			"### tuple ### route:allow tcp 8080 10.0.0.5 any 0.0.0.0/0 in_eth0!out_docker0\n",
		"ufw/user6.rules": "### tuple ### deny udp 53 ::/0 any ::/0 out\n",
	})

	ufw, err := ufwConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	if !ufw.Enabled || ufw.DefaultIncoming != "deny" || ufw.DefaultOutgoing != "allow" || ufw.DefaultRouted != "deny" || len(ufw.Rules) != 4 {
		t.Fatalf("ufw = %+v", ufw)
	}
	ssh, web, route, dns := ufw.Rules[0], ufw.Rules[1], ufw.Rules[2], ufw.Rules[3]
	if ssh.Action != "allow" || ssh.ToPort != "22" || ssh.FromAddress != "203.0.113.0/24" || ssh.Comment != "admin" || ssh.Direction != "in" {
		t.Fatalf("ssh rule = %+v", ssh)
	}
	if web.Action != "limit" || web.Log != "log" || web.ToApp != "Nginx Full" || web.InterfaceIn != "eth0" {
		t.Fatalf("web rule = %+v", web)
	}
	if !route.Route || route.InterfaceIn != "eth0" || route.InterfaceOut != "docker0" || route.Direction != "in" {
		t.Fatalf("route rule = %+v", route)
	}
	if dns.Family != "ipv6" || dns.Direction != "out" || dns.Action != "deny" {
		t.Fatalf("dns rule = %+v", dns)
	}
}

func TestFirewalldConfigurationListsUsedZones(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_ETC", filepath.Join(root, "etc"))
	t.Setenv("HOST_ROOT", root)
	writeFiles(t, root, map[string]string{
		"etc/firewalld/firewalld.conf": "# firewalld config file\nDefaultZone=public\n",
		"usr/lib/firewalld/zones/public.xml": `<?xml version="1.0" encoding="utf-8"?>
<zone><short>Public</short><service name="ssh"/><service name="dhcpv6-client"/><forward/></zone>`,
		"usr/lib/firewalld/zones/trusted.xml": `<zone target="ACCEPT"><short>Trusted</short></zone>`,
		"etc/firewalld/zones/public.xml": `<zone><service name="ssh"/><port protocol="tcp" port="25565"/><masquerade/>
<rule family="ipv4"><source address="198.51.100.0/24"/><service name="http"/><accept/></rule></zone>`,
		"etc/firewalld/zones/internal.xml": `<zone><interface name="wg0"/><source address="10.8.0.0/24"/></zone>`,
	})

	firewalld, err := firewalldConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	if firewalld.DefaultZone != "public" || len(firewalld.Zones) != 2 {
		t.Fatalf("firewalld = %+v", firewalld)
	}
	internal, public := firewalld.Zones[0], firewalld.Zones[1]
	if internal.Name != "internal" || !slices.Equal(internal.Interfaces, []string{"wg0"}) || !slices.Equal(internal.Sources, []string{"10.8.0.0/24"}) {
		t.Fatalf("internal zone = %+v", internal)
	}
	if public.Target != "default" || !slices.Equal(public.Services, []string{"ssh"}) || !slices.Equal(public.Ports, []string{"25565/tcp"}) ||
		!public.Masquerade || len(public.RichRules) != 1 {
		t.Fatalf("public zone = %+v", public)
	}
}
