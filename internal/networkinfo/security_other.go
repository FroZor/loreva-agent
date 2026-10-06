//go:build !linux

package networkinfo

import "github.com/FroZor/loreva-agent/internal/protocol"

func collectSecurity([]protocol.ListeningPort) (protocol.SecurityInformation, []protocol.CollectionIssue) {
	return protocol.SecurityInformation{
		IntrusionPrevention:    []protocol.SecurityService{},
		MandatoryAccessControl: []protocol.SecurityService{},
		Sessions:               []protocol.LoginSession{},
	}, []protocol.CollectionIssue{{Component: "security", Code: "not_available"}}
}
