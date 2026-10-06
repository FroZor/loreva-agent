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
