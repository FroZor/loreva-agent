package session

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// exchange sends node reports, tracks their acknowledgements, and serves
// the metrics a peer watches.
// The portal session and direct device sessions run the same exchange; only
// the loop around it and the way the peer authenticated differ.
type exchange struct {
	collectors       Collectors
	reports          *nodeReporter
	reportReplyTimer *time.Timer
	reportRetryTimer *time.Timer
	metrics          *metricWatch
	// inventorySlots bounds the container inventory calls a session runs
	// at once.
	inventorySlots chan struct{}
}

// identityRejection means the peer no longer recognizes this node.
type identityRejection struct{ err error }

func (rejection *identityRejection) Error() string { return rejection.err.Error() }
func (rejection *identityRejection) Unwrap() error { return rejection.err }

// newExchange starts the exchange for one peer. reader names the peer in
// the metrics store's demand.
func newExchange(ctx context.Context, collectors Collectors, reports *nodeReportState, reader string) *exchange {
	return &exchange{
		collectors:       collectors,
		reports:          newNodeReporter(ctx, collectors, reports),
		reportReplyTimer: newStoppedTimer(),
		reportRetryTimer: newStoppedTimer(),
		metrics:          newMetricWatch(collectors.Metrics, reader),
		inventorySlots:   make(chan struct{}, maxInventoryCalls),
	}
}

func (x *exchange) stop() {
	x.reportReplyTimer.Stop()
	x.reportRetryTimer.Stop()
	x.metrics.stop()
}

func (x *exchange) reportCollected(ctx context.Context, conn *websocket.Conn, report collectedNodeReport) error {
	if err := x.reports.writeResult(ctx, conn, report); err != nil {
		return err
	}

	x.reportReplyTimer.Reset(nodeReportReplyTimeout)

	return nil
}

func (x *exchange) retryReport(ctx context.Context, conn *websocket.Conn) error {
	active := x.reports.state.active
	if active == nil {
		return errors.New("node report retry fired without an active report")
	}
	if err := x.reports.writeActive(ctx, conn, active.kind); err != nil {
		return err
	}

	x.reportReplyTimer.Reset(nodeReportReplyTimeout)

	return nil
}

func (x *exchange) scheduleNodeReportRetry(events Events, code string) {
	delay := x.reports.retryDelay()
	stopTimer(x.reportRetryTimer)
	x.reportRetryTimer.Reset(delay)

	notifyNodeReportRejection(events, NodeReportRejection{
		Type:      x.reports.activeType(),
		Code:      code,
		RetryIn:   delay,
		Retryable: true,
	})
}

// handleAcknowledgement processes a node report response. It reports
// false for any other message type. An *identityRejection error means the
// peer rejected the node itself.
func (x *exchange) handleAcknowledgement(
	ctx context.Context,
	conn *websocket.Conn,
	messageType string,
	data []byte,
	events Events,
) (bool, error) {
	switch messageType {
	case protocol.NodeSpecificationsAcceptedType,
		protocol.NodeSpecificationsRejectedType,
		protocol.NodeNetworkAcceptedType,
		protocol.NodeNetworkRejectedType:
		return true, x.handleReportResponse(ctx, data, events)
	default:
		return false, nil
	}
}

func (x *exchange) handleReportResponse(ctx context.Context, data []byte, events Events) error {
	reportType := x.reports.activeType()
	if err := x.reports.handleResponse(ctx, data); err != nil {
		if errors.Is(err, errDuplicateNodeReportAcknowledgement) {
			return nil
		}

		rejection, ok := errors.AsType[*nodeReportRejection](err)
		if !ok {
			return err
		}

		stopTimer(x.reportReplyTimer)
		stopTimer(x.reportRetryTimer)

		if identityNodeReportRejection(rejection.code) {
			return &identityRejection{err: rejection}
		}
		if !terminalNodeReportRejection(rejection.code) {
			x.scheduleNodeReportRetry(events, rejection.code)
			return nil
		}

		x.reports.skip(ctx)
		notifyNodeReportRejection(events, NodeReportRejection{
			Type: reportType,
			Code: rejection.code,
		})

		return nil
	}

	stopTimer(x.reportReplyTimer)
	stopTimer(x.reportRetryTimer)

	return nil
}

func notifyNodeReportRejection(events Events, rejection NodeReportRejection) {
	if events.ReportRejected != nil {
		events.ReportRejected(rejection)
	}
}
