package session

import (
	"context"
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
)

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
