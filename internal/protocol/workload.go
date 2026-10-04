package protocol

import (
	"encoding/json"
	"time"
)

// Workload protocol message and format identifiers.
const (
	PortalCommandType            = "portal.command"
	WorkloadPlanRequestType      = "workload.plan.request"
	WorkloadExecuteRequestType   = "workload.execute.request"
	WorkloadStopRequestType      = "workload.stop.request"
	WorkloadRestartRequestType   = "workload.restart.request"
	WorkloadDeleteRequestType    = "workload.delete.request"
	WorkloadPlanResultType       = "workload.plan.result"
	WorkloadOperationEventType   = "workload.operation.event"
	WorkloadOperationResultType  = "workload.operation.result"
	WorkloadSchemaVersion        = 1
	WorkloadFormatOCI            = "oci"
	WorkloadFormatCompose        = "compose"
	WorkloadFormatDockerfile     = "dockerfile"
	WorkloadFormatPterodactylEgg = "pterodactyl-egg"
	WorkloadDataPolicyPreserve   = "preserve"
)

// PortalCommand is the only workload command exposed directly on the WSS
// connection. SignedCommand is an ML-DSA Compact JWS whose payload is a
// WorkloadCommand.
type PortalCommand struct {
	Type          string `json:"type"`
	SignedCommand string `json:"signed_command"`
}

// WorkloadCommand is the common, signed command envelope. Payload is decoded
// strictly according to Type only after the signature and envelope have been
// validated.
type WorkloadCommand struct {
	Type          string          `json:"type"`
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	PortalID      string          `json:"portal_id"`
	NodeID        string          `json:"node_id"`
	WorkloadID    string          `json:"workload_id"`
	SessionNonce  string          `json:"session_nonce"`
	IssuedAt      time.Time       `json:"issued_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Payload       json.RawMessage `json:"payload"`
}

// ArtifactReference identifies an immutable artifact served by the enrolled
// portal over the agent's authenticated HTTPS channel.
type ArtifactReference struct {
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
}

// WorkloadPlanPayload contains exactly one format-specific input.
type WorkloadPlanPayload struct {
	Format     string                   `json:"format"`
	OCI        *OCIWorkloadInput        `json:"oci,omitempty"`
	Compose    *ComposeWorkloadInput    `json:"compose,omitempty"`
	Dockerfile *DockerfileWorkloadInput `json:"dockerfile,omitempty"`
	Egg        *PterodactylEggInput     `json:"pterodactyl_egg,omitempty"`
}

// OCIWorkloadInput describes one container created from a digest-pinned image.
type OCIWorkloadInput struct {
	Image       string            `json:"image"`
	Environment map[string]string `json:"environment,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Resources   WorkloadResources `json:"resources"`
	Ports       []WorkloadPort    `json:"ports,omitempty"`
	Mounts      []WorkloadMount   `json:"mounts,omitempty"`
}

// ComposeWorkloadInput points to a tar.gz artifact containing a Compose
// project. The portal supplies parameters separately from the artifact.
type ComposeWorkloadInput struct {
	Artifact    ArtifactReference `json:"artifact"`
	File        string            `json:"file"`
	Profiles    []string          `json:"profiles,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// DockerfileWorkloadInput builds a signed context and starts the resulting
// image with explicit resource and host-access constraints.
type DockerfileWorkloadInput struct {
	Artifact    ArtifactReference `json:"artifact"`
	File        string            `json:"file"`
	Target      string            `json:"target,omitempty"`
	BuildArgs   map[string]string `json:"build_args,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Resources   WorkloadResources `json:"resources"`
	Ports       []WorkloadPort    `json:"ports,omitempty"`
	Mounts      []WorkloadMount   `json:"mounts,omitempty"`
}

// PterodactylEggInput points to a PTDL_v2 Egg JSON document. Installer scripts
// are never approved implicitly by this structure.
type PterodactylEggInput struct {
	Artifact       ArtifactReference `json:"artifact"`
	DockerImage    string            `json:"docker_image"`
	InstallerImage string            `json:"installer_image,omitempty"`
	Variables      map[string]string `json:"variables,omitempty"`
	Agreements     []string          `json:"agreements,omitempty"`
	Resources      WorkloadResources `json:"resources"`
	Ports          []WorkloadPort    `json:"ports,omitempty"`
}

// WorkloadResources constrains runtime resource consumption.
type WorkloadResources struct {
	CPUMillicores int64 `json:"cpu_millicores"`
	MemoryBytes   int64 `json:"memory_bytes"`
	PIDsLimit     int64 `json:"pids_limit"`
}

// WorkloadPort publishes one TCP or UDP container port.
type WorkloadPort struct {
	HostIP        string `json:"host_ip"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// WorkloadMount defines storage made available to an OCI container. Managed
// volumes are the default; bind mounts require an explicit plan finding.
type WorkloadMount struct {
	Type     string `json:"type"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// WorkloadExecutePayload authorizes execution of an unchanged local plan.
type WorkloadExecutePayload struct {
	PlanDigest string   `json:"plan_digest"`
	Approvals  []string `json:"approvals"`
}

// WorkloadStopPayload controls graceful shutdown.
type WorkloadStopPayload struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

// WorkloadDeletePayload keeps persistent data unless the portal explicitly
// confirms a destructive plan.
type WorkloadDeletePayload struct {
	DataPolicy string `json:"data_policy"`
}

// WorkloadFinding is a deterministic policy result. FindingDigest is what an
// execute command approves, preventing approval from being applied to changed
// content.
type WorkloadFinding struct {
	Code             string `json:"code"`
	Severity         string `json:"severity"`
	Message          string `json:"message"`
	FindingDigest    string `json:"finding_digest"`
	RequiresApproval bool   `json:"requires_approval"`
}

// WorkloadPlanStep is a stable, human-readable deployment step.
type WorkloadPlanStep struct {
	Sequence int    `json:"sequence"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// WorkloadPlanResult reports the immutable plan stored by the agent.
type WorkloadPlanResult struct {
	Type          string                    `json:"type"`
	SchemaVersion int                       `json:"schema_version"`
	RequestID     string                    `json:"request_id"`
	PortalID      string                    `json:"portal_id"`
	NodeID        string                    `json:"node_id"`
	WorkloadID    string                    `json:"workload_id"`
	OccurredAt    time.Time                 `json:"occurred_at"`
	Payload       WorkloadPlanResultPayload `json:"payload"`
}

// WorkloadPlanResultPayload is the useful plan response data.
type WorkloadPlanResultPayload struct {
	State      string             `json:"state"`
	PlanDigest string             `json:"plan_digest,omitempty"`
	Steps      []WorkloadPlanStep `json:"steps"`
	Findings   []WorkloadFinding  `json:"findings"`
	Code       string             `json:"code,omitempty"`
	Message    string             `json:"message,omitempty"`
}

// WorkloadOperationEvent streams bounded progress for one requested action.
type WorkloadOperationEvent struct {
	Type          string                        `json:"type"`
	SchemaVersion int                           `json:"schema_version"`
	RequestID     string                        `json:"request_id"`
	PortalID      string                        `json:"portal_id"`
	NodeID        string                        `json:"node_id"`
	WorkloadID    string                        `json:"workload_id"`
	OccurredAt    time.Time                     `json:"occurred_at"`
	Payload       WorkloadOperationEventPayload `json:"payload"`
}

// WorkloadOperationEventPayload describes one state transition.
type WorkloadOperationEventPayload struct {
	Sequence int    `json:"sequence"`
	State    string `json:"state"`
	Step     string `json:"step"`
	Message  string `json:"message,omitempty"`
}

// WorkloadOperationResult terminates one requested action.
type WorkloadOperationResult struct {
	Type          string                         `json:"type"`
	SchemaVersion int                            `json:"schema_version"`
	RequestID     string                         `json:"request_id"`
	PortalID      string                         `json:"portal_id"`
	NodeID        string                         `json:"node_id"`
	WorkloadID    string                         `json:"workload_id"`
	OccurredAt    time.Time                      `json:"occurred_at"`
	Payload       WorkloadOperationResultPayload `json:"payload"`
}

// WorkloadOperationResultPayload is the final operation status.
type WorkloadOperationResultPayload struct {
	State   string `json:"state"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
