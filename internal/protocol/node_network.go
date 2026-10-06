package protocol

import "time"

const (
	NodeNetworkSchemaVersion = 1
	NodeNetworkReportType    = "node.network.report"
	NodeNetworkAcceptedType  = "node.network.accepted"
	NodeNetworkRejectedType  = "node.network.rejected"
	NodeNetworkRefreshType   = "node.network.refresh"
)

// NodeNetworkRefresh asks the node to collect its network report again. The
// node answers with a new node.network.report, or with error.
type NodeNetworkRefresh struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// NodeNetworkReport describes runtime network configuration and protection.
type NodeNetworkReport struct {
	Type             string      `json:"type"`
	SchemaVersion    int         `json:"schema_version"`
	RequestID        string      `json:"request_id"`
	ObservedAt       time.Time   `json:"observed_at"`
	ObservationScope string      `json:"observation_scope"`
	Network          NodeNetwork `json:"network"`
}

// NodeNetworkAccepted acknowledges a committed network snapshot.
type NodeNetworkAccepted struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
}

// NodeReportRejected rejects either node report and identifies its request.
type NodeReportRejected struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
}

// NodeNetwork contains interfaces, routing, listeners and firewall state.
type NodeNetwork struct {
	Interfaces       []NetworkInterfaceConfiguration `json:"interfaces"`
	Routes           []NetworkRoute                  `json:"routes"`
	ListeningPorts   []ListeningPort                 `json:"listening_ports"`
	Firewall         FirewallInformation             `json:"firewall"`
	PublicAddresses  []PublicAddress                 `json:"public_addresses"`
	DNS              *DNSConfiguration               `json:"dns,omitempty"`
	Security         SecurityInformation             `json:"security"`
	CollectionIssues []CollectionIssue               `json:"collection_issues,omitempty"`
}

// PublicAddress is an address under which the node is reachable from the
// internet. Source is interface, configured, cloud_metadata, or external;
// BehindNAT is set when the address is not on any interface of the node.
type PublicAddress struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	Source    string `json:"source"`
	BehindNAT bool   `json:"behind_nat"`
}

// DNSConfiguration is the resolver configuration of the host. When the
// host runs a local stub resolver, Upstream lists the servers it forwards
// to.
type DNSConfiguration struct {
	Nameservers   []string `json:"nameservers"`
	SearchDomains []string `json:"search_domains"`
	Resolver      string   `json:"resolver,omitempty"`
	Upstream      []string `json:"upstream,omitempty"`
}

// SecurityInformation describes host protection besides the firewall.
type SecurityInformation struct {
	SSH                    *SSHConfiguration `json:"ssh,omitempty"`
	IntrusionPrevention    []SecurityService `json:"intrusion_prevention"`
	MandatoryAccessControl []SecurityService `json:"mandatory_access_control"`
}

// SSHConfiguration is the effective sshd setting for logins, read from its
// configuration files. ListeningPorts are the ports sshd listens on now.
type SSHConfiguration struct {
	Running                bool     `json:"running"`
	ConfiguredPorts        []uint16 `json:"configured_ports"`
	ListeningPorts         []uint16 `json:"listening_ports"`
	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	PubkeyAuthentication   string   `json:"pubkey_authentication,omitempty"`
}

// SecurityService is one protection tool. Status is running, stopped,
// enabled, enforcing, permissive, or disabled; Details lists, for example,
// the enabled fail2ban jails.
type SecurityService struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Details []string `json:"details,omitempty"`
}

// NetworkInterfaceConfiguration describes configured addresses on an interface.
type NetworkInterfaceConfiguration struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	HardwareAddress string           `json:"hardware_address,omitempty"`
	MTU             int              `json:"mtu,omitempty"`
	Flags           []string         `json:"flags"`
	Addresses       []NetworkAddress `json:"addresses"`
	// OperState is the kernel's RFC 2863 state, such as up or down.
	OperState string `json:"oper_state,omitempty"`
	// SpeedBPS and Duplex describe the negotiated link, when it has one.
	SpeedBPS uint64 `json:"speed_bps,omitempty"`
	Duplex   string `json:"duplex,omitempty"`
}

// NetworkAddress is one normalized interface address.
type NetworkAddress struct {
	Family       string `json:"family"`
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
}

// NetworkRoute describes one normalized route without provider-specific flags.
type NetworkRoute struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	InterfaceID string `json:"interface_id,omitempty"`
	Metric      uint64 `json:"metric,omitempty"`
}

// ListeningPort describes a local listening socket and the process that owns it.
type ListeningPort struct {
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        uint16 `json:"port"`
	ProcessID   int32  `json:"process_id,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

// FirewallInformation describes observed managers and loss-aware normalized rules.
type FirewallInformation struct {
	Status    string             `json:"status"`
	Providers []FirewallProvider `json:"providers"`
	Rules     []FirewallRule     `json:"rules"`
	Truncated bool               `json:"truncated"`
}

// FirewallProvider identifies a firewall manager or kernel filtering backend.
type FirewallProvider struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Status  string `json:"status"`
	Backend string `json:"backend,omitempty"`
}

// FirewallRule is a loss-aware normalized view; empty fields are unknown when Partial is true.
type FirewallRule struct {
	ID               string      `json:"id"`
	Provider         string      `json:"provider"`
	Family           string      `json:"family"`
	Table            string      `json:"table,omitempty"`
	Chain            string      `json:"chain,omitempty"`
	Direction        string      `json:"direction"`
	Action           string      `json:"action"`
	Protocol         string      `json:"protocol"`
	SourceCIDRs      []string    `json:"source_cidrs"`
	DestinationCIDRs []string    `json:"destination_cidrs"`
	SourcePorts      []PortRange `json:"source_ports"`
	DestinationPorts []PortRange `json:"destination_ports"`
	Interfaces       []string    `json:"interfaces"`
	Enabled          bool        `json:"enabled"`
	Partial          bool        `json:"partial"`
}

// PortRange is one inclusive transport-port interval.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}
