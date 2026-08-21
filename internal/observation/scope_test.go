package observation

import "testing"

func TestIsContainer(t *testing.T) {
	for _, provider := range []string{"docker", "Podman", "containerd"} {
		if !isContainer(provider) {
			t.Fatalf("provider %q was not recognized as a container", provider)
		}
	}
	if isContainer("kvm") {
		t.Fatal("virtual machine provider was recognized as a container")
	}
}
