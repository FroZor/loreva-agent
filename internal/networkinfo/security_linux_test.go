//go:build linux

package networkinfo

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSHConfigurationFirstValueWinsAndIncludesAreRead(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_ROOT", root)
	t.Setenv("HOST_ETC", filepath.Join(root, "etc"))
	writeFiles(t, root, map[string]string{
		"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPort 2222\n" +
			"PasswordAuthentication yes\nPermitRootLogin yes\nMatch User backup\n  PasswordAuthentication no\n",
		"etc/ssh/sshd_config.d/50-cloud.conf": "PasswordAuthentication=no\n# PermitRootLogin no\n",
	})

	ssh, err := sshConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ssh.ConfiguredPorts, []uint16{22, 2222}) || ssh.PasswordAuthentication != "no" || ssh.PermitRootLogin != "yes" {
		t.Fatalf("ssh = %+v", ssh)
	}
}

func TestFail2banJailsInheritDefault(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOST_ETC", root)
	writeFiles(t, root, map[string]string{
		"fail2ban/jail.conf":                   "[DEFAULT]\nenabled = false\n[sshd]\nport = ssh\n[nginx-http-auth]\n[recidive]\n",
		"fail2ban/jail.d/defaults-debian.conf": "[sshd]\nenabled = true\n",
		"fail2ban/jail.local":                  "[recidive]\nenabled = true\n",
	})

	service, found := fail2ban(true)
	if !found || service.Status != "running" || !slices.Equal(service.Details, []string{"recidive", "sshd"}) {
		t.Fatalf("fail2ban = %+v, %v", service, found)
	}
}

func TestParseResolvConf(t *testing.T) {
	dns := parseResolvConf("# generated\nnameserver 127.0.0.53\nnameserver bad\nsearch old.example\nsearch example.com corp.example\noptions edns0\n")

	if !slices.Equal(dns.Nameservers, []string{"127.0.0.53"}) || !slices.Equal(dns.SearchDomains, []string{"example.com", "corp.example"}) {
		t.Fatalf("dns = %+v", dns)
	}
}
