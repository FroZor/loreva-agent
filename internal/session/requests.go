package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/metrics"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	// maxQueryRange bounds one metrics.query; the store keeps a week anyway.
	maxQueryRange     = 8 * 24 * time.Hour
	nodeRequestWrites = 10 * time.Second
	// maxRequestAnswer bounds one answer frame, like a node report.
	maxRequestAnswer = 512 * 1024
	// inventoryTimeout bounds a Docker call; measuring sizes can be slow.
	inventoryTimeout = time.Minute
	// maxInventoryCalls bounds the Docker calls one session runs at once.
	maxInventoryCalls = 4
)

// ContainerInventory lists the node's containers and describes one.
type ContainerInventory interface {
	List(ctx context.Context) (protocol.ContainersListResult, error)
	Inspect(ctx context.Context, containerID string, size bool) (protocol.ContainerDetails, error)
}

// handleRequest answers the node requests that every session serves the same
// way, whoever the peer is. It reports false for any other message type.
func (x *exchange) handleRequest(
	ctx context.Context,
	conn *websocket.Conn,
	messageType string,
	data []byte,
	reject rejectFunc,
) (bool, error) {
	switch messageType {
	case protocol.MetricsQueryType:
		return true, x.answerMetricsQuery(ctx, conn, data, reject)
	case protocol.NodeNetworkRefreshType:
		return true, x.refreshNetwork(ctx, data, reject)
	case protocol.NodeProcessInspectType:
		return true, x.inspectProcess(ctx, conn, data, reject)
	case protocol.ContainersListType:
		return true, x.listContainers(ctx, conn, data, reject)
	case protocol.ContainerInspectType:
		return true, x.inspectContainer(ctx, conn, data, reject)
	default:
		return false, nil
	}
}

func (x *exchange) answerMetricsQuery(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var query protocol.MetricsQuery
	if err := protocol.DecodeStrict(data, &query); err != nil || !agentcrypto.ValidUUID(query.RequestID) {
		return reject(ctx, "", "invalid_message", "metrics.query needs a UUID request_id, from, and to")
	}
	if query.To.Before(query.From) || query.To.Sub(query.From) > maxQueryRange {
		return reject(ctx, query.RequestID, "invalid_range", "to must not be before from, and the range must be at most 8 days")
	}
	if x.collectors.Metrics == nil {
		return reject(ctx, query.RequestID, "metrics_unavailable", "this node keeps no metrics")
	}

	result, err := queryResult(x.collectors.Metrics, query.RequestID, query.From, query.To)
	if err != nil {
		return fmt.Errorf("answer metrics query: %w", err)
	}

	writeCtx, cancel := context.WithTimeout(ctx, nodeRequestWrites)
	defer cancel()

	return wsframe.WriteJSON(writeCtx, conn, result)
}

// refreshNetwork collects the network report again. The answer is a new
// node.network.report, acknowledged like the first one.
func (x *exchange) refreshNetwork(ctx context.Context, data []byte, reject rejectFunc) error {
	var request protocol.NodeNetworkRefresh
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "node.network.refresh needs a UUID request_id")
	}
	if x.collectors.Network == nil {
		return reject(ctx, request.RequestID, "network_unavailable", "this node does not report its network")
	}

	x.reports.refreshNetwork(ctx)

	return nil
}

func (x *exchange) inspectProcess(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.NodeProcessInspect
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) || request.PID <= 0 {
		return reject(ctx, "", "invalid_message", "node.process.inspect needs a UUID request_id, pid, and started_at")
	}
	if x.collectors.Processes == nil {
		return reject(ctx, request.RequestID, "processes_unavailable", "this node does not report processes")
	}

	details, err := x.collectors.Processes(request.PID, request.StartedAt)
	if errors.Is(err, metrics.ErrProcessNotFound) {
		return reject(ctx, request.RequestID, "not_found", "no process with this pid and start time")
	}
	if err != nil {
		return reject(ctx, request.RequestID, "processes_unavailable", "the process table cannot be read")
	}

	writeCtx, cancel := context.WithTimeout(ctx, nodeRequestWrites)
	defer cancel()

	return wsframe.WriteJSON(writeCtx, conn, protocol.NodeProcessInspectResult{
		Type:      protocol.NodeProcessInspectResultType,
		RequestID: request.RequestID,
		Process:   details,
	})
}

func (x *exchange) listContainers(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.ContainersList
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "containers.list needs a UUID request_id")
	}
	if x.collectors.Inventory == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}

	return x.runInventory(ctx, conn, request.RequestID, reject, func(callCtx context.Context) (any, error) {
		result, err := x.collectors.Inventory.List(callCtx)
		result.Type = protocol.ContainersListResultType
		result.RequestID = request.RequestID

		return result, err
	})
}

func (x *exchange) inspectContainer(ctx context.Context, conn *websocket.Conn, data []byte, reject rejectFunc) error {
	var request protocol.ContainerInspect
	if err := protocol.DecodeStrict(data, &request); err != nil || !agentcrypto.ValidUUID(request.RequestID) {
		return reject(ctx, "", "invalid_message", "container.inspect needs a UUID request_id and container_id")
	}
	if x.collectors.Inventory == nil {
		return reject(ctx, request.RequestID, "containers_unavailable", "this node has no container runtime")
	}

	return x.runInventory(ctx, conn, request.RequestID, reject, func(callCtx context.Context) (any, error) {
		details, err := x.collectors.Inventory.Inspect(callCtx, request.ContainerID, request.Size)

		return protocol.ContainerInspectResult{
			Type:      protocol.ContainerInspectResultType,
			RequestID: request.RequestID,
			Container: details,
		}, err
	})
}

// runInventory answers a Docker call off the session loop, so a slow call
// does not hold back acknowledgements and other requests. Calls beyond
// maxInventoryCalls are refused with busy.
func (x *exchange) runInventory(
	ctx context.Context,
	conn *websocket.Conn,
	requestID string,
	reject rejectFunc,
	call func(context.Context) (any, error),
) error {
	select {
	case x.inventorySlots <- struct{}{}:
	default:
		return reject(ctx, requestID, "busy", "too many container requests are in progress")
	}

	go func() {
		defer func() { <-x.inventorySlots }()

		callCtx, cancel := context.WithTimeout(ctx, inventoryTimeout)
		answer, err := call(callCtx)
		cancel()
		if err != nil {
			code, message := containerErrorCode(err)
			_ = reject(ctx, requestID, code, message)
			return
		}

		// A failed write means the session is ending; its loop reports that.
		_ = x.writeAnswer(ctx, conn, requestID, answer, reject)
	}()

	return nil
}

// writeAnswer sends one answer frame, or too_large when it would exceed
// the frame bound.
func (x *exchange) writeAnswer(ctx context.Context, conn *websocket.Conn, requestID string, answer any, reject rejectFunc) error {
	payload, err := json.Marshal(answer)
	if err != nil {
		return fmt.Errorf("encode answer: %w", err)
	}
	if len(payload) > maxRequestAnswer {
		return reject(ctx, requestID, "too_large", "the answer exceeds 512 KiB")
	}

	writeCtx, cancel := context.WithTimeout(ctx, nodeRequestWrites)
	defer cancel()

	return conn.Write(writeCtx, websocket.MessageText, payload)
}
