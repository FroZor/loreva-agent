// Package workload plans and executes container workloads requested by the
// portal or by paired devices.
package workload

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	commandNonceBytes  = 32
	commandMaxLifetime = time.Minute
	commandClockSkew   = 30 * time.Second
)

// VerifyCommand authenticates and validates a portal command against the
// current node and connection session.
func VerifyCommand(
	root *agentcrypto.JWK,
	signed string,
	portalID string,
	nodeID string,
	sessionNonce string,
	now time.Time,
) (protocol.WorkloadCommand, error) {
	var command protocol.WorkloadCommand
	if err := agentcrypto.VerifyCompactJWS(root, signed, &command); err != nil {
		return protocol.WorkloadCommand{}, fmt.Errorf("verify portal command: %w", err)
	}
	if err := validateCommand(command, portalID, nodeID, sessionNonce, now); err != nil {
		return protocol.WorkloadCommand{}, err
	}

	return command, nil
}

func validateCommand(
	command protocol.WorkloadCommand,
	portalID string,
	nodeID string,
	sessionNonce string,
	now time.Time,
) error {
	if command.SchemaVersion != protocol.WorkloadSchemaVersion {
		return errors.New("unsupported workload command schema_version")
	}
	if !supportedCommandType(command.Type) {
		return fmt.Errorf("unsupported workload command type %q", command.Type)
	}
	if !agentcrypto.ValidUUID(command.RequestID) || !agentcrypto.ValidUUID(command.WorkloadID) {
		return errors.New("workload command contains an invalid UUID")
	}
	if command.PortalID != portalID || command.NodeID != nodeID {
		return errors.New("workload command identity does not match the enrolled session")
	}
	if !validNonce(command.SessionNonce) || !constantTimeEqual(command.SessionNonce, sessionNonce) {
		return errors.New("workload command is not bound to the current session")
	}
	if command.IssuedAt.IsZero() || command.ExpiresAt.IsZero() {
		return errors.New("workload command has invalid timestamps")
	}
	if command.IssuedAt.After(now.Add(commandClockSkew)) {
		return errors.New("workload command issued_at is too far in the future")
	}
	if !command.ExpiresAt.After(now) {
		return errors.New("workload command expired")
	}
	if !command.ExpiresAt.After(command.IssuedAt) || command.ExpiresAt.Sub(command.IssuedAt) > commandMaxLifetime {
		return errors.New("workload command lifetime exceeds the protocol limit")
	}
	if len(command.Payload) == 0 || string(command.Payload) == "null" {
		return errors.New("workload command payload is required")
	}

	return nil
}

func supportedCommandType(value string) bool {
	switch value {
	case protocol.WorkloadPlanRequestType,
		protocol.WorkloadExecuteRequestType,
		protocol.WorkloadStopRequestType,
		protocol.WorkloadRestartRequestType,
		protocol.WorkloadDeleteRequestType:
		return true
	default:
		return false
	}
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)

	return err == nil && len(decoded) == commandNonceBytes && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// DeviceCommand turns a paired device's request into a command. Devices are
// authenticated by their TLS client certificates, so the request is not
// signed. Every device of a node shares one controller scope, the node ID,
// which keeps device-created workloads apart from portal-created ones.
func DeviceCommand(request protocol.DeviceWorkloadCommand, nodeID string, now time.Time) (protocol.WorkloadCommand, error) {
	if request.SchemaVersion != protocol.WorkloadSchemaVersion {
		return protocol.WorkloadCommand{}, errors.New("unsupported workload command schema_version")
	}
	if !supportedCommandType(request.Type) {
		return protocol.WorkloadCommand{}, fmt.Errorf("unsupported workload command type %q", request.Type)
	}
	if !agentcrypto.ValidUUID(request.RequestID) || !agentcrypto.ValidUUID(request.WorkloadID) {
		return protocol.WorkloadCommand{}, errors.New("workload command contains an invalid UUID")
	}
	if len(request.Payload) == 0 || string(request.Payload) == "null" {
		return protocol.WorkloadCommand{}, errors.New("workload command payload is required")
	}

	return protocol.WorkloadCommand{
		Type:          request.Type,
		SchemaVersion: request.SchemaVersion,
		RequestID:     request.RequestID,
		PortalID:      nodeID,
		NodeID:        nodeID,
		WorkloadID:    request.WorkloadID,
		IssuedAt:      now.UTC(),
		ExpiresAt:     now.UTC().Add(commandMaxLifetime),
		Payload:       request.Payload,
	}, nil
}
