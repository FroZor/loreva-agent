//go:build !linux

package hostnet

// Interfaces lists the interfaces visible to the agent.
func Interfaces() ([]Interface, error) {
	return standardInterfaces()
}

// NetPath has no /proc/net to point at outside Linux.
func NetPath(string) string {
	return ""
}

// LinkState is not read outside Linux.
func LinkState(string) Link {
	return Link{}
}

// SameNamespace is always true outside Linux.
func SameNamespace() bool {
	return true
}
