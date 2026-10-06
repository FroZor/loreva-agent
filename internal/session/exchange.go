package session

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

// exchange sends node reports and metrics and tracks their acknowledgements.
// The portal session and direct device sessions run the same exchange; only
// the loop around it and the way the peer authenticated differ.
type exchange struct {
	collectors        Collectors
	reports           *nodeReporter
	reportReplyTimer  *time.Timer
	reportRetryTimer  *time.Timer
	metrics           *metricReporter
	metricsReplyTimer *time.Timer
	metricsRetryTimer *time.Timer
}

// identityRejection means the peer no longer recognizes this node.
type identityRejection struct{ err error }

func (rejection *identityRejection) Error() string { return rejection.err.Error() }
func (rejection *identityRejection) Unwrap() error { return rejection.err }

// newExchange starts the exchange for one peer. reader names the peer's
// cursor in the metrics store.
func newExchange(ctx context.Context, collectors Collectors, reports *nodeReportState, reader string) *exchange {
	return &exchange{
		collectors:        collectors,
		reports:           newNodeReporter(ctx, collectors, reports),
		reportReplyTimer:  newStoppedTimer(),
		reportRetryTimer:  newStoppedTimer(),
		metrics:           newMetricReporter(collectors.Metrics, reader),
		metricsReplyTimer: newStoppedTimer(),
		metricsRetryTimer: newStoppedTimer(),
	}
}

func (x *exchange) stop() {
	x.reportReplyTimer.Stop()
	x.reportRetryTimer.Stop()
	x.metricsReplyTimer.Stop()
	x.metricsRetryTimer.Stop()
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

// metricsStored sends newly stored metrics once the node reports are done.
func (x *exchange) metricsStored(ctx context.Context, conn *websocket.Conn) error {
	x.metrics.woke()
	if !x.reports.state.complete {
		return nil
	}

	sent, err := x.metrics.writeNext(ctx, conn)
	if err != nil {
		return err
	}
	if sent {
		x.metricsReplyTimer.Reset(metricsReplyTimeout)
	}

	return nil
}

func (x *exchange) retryMetrics(ctx context.Context, conn *websocket.Conn) error {
	if err := x.metrics.writeActive(ctx, conn); err != nil {
		return err
	}

	x.metricsReplyTimer.Reset(metricsReplyTimeout)

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

func (x *exchange) scheduleMetricsRetry(events Events, code string) {
	delay := x.metrics.retryDelay()
	stopTimer(x.metricsRetryTimer)
	x.metricsRetryTimer.Reset(delay)

	notifyNodeReportRejection(events, NodeReportRejection{
		Type:      x.metrics.activeType(),
		Code:      code,
		RetryIn:   delay,
		Retryable: true,
	})
}

// handleAcknowledgement processes a report or metrics response. It reports
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
		return true, x.handleReportResponse(ctx, conn, data, events)
	case protocol.MetricsAcceptedType, protocol.MetricsRejectedType:
		return true, x.handleMetricsResponse(ctx, conn, data, events)
	default:
		return false, nil
	}
}

func (x *exchange) handleReportResponse(ctx context.Context, conn *websocket.Conn, data []byte, events Events) error {
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

		return x.startMetricsAfterReports(ctx, conn)
	}

	stopTimer(x.reportReplyTimer)
	stopTimer(x.reportRetryTimer)

	return x.startMetricsAfterReports(ctx, conn)
}

func (x *exchange) startMetricsAfterReports(ctx context.Context, conn *websocket.Conn) error {
	if !x.reports.state.complete {
		return nil
	}

	sent, err := x.metrics.writeReady(ctx, conn)
	if err != nil {
		return err
	}
	if sent {
		x.metricsReplyTimer.Reset(metricsReplyTimeout)
	}

	return nil
}

func (x *exchange) handleMetricsResponse(ctx context.Context, conn *websocket.Conn, data []byte, events Events) error {
	if err := x.metrics.handleResponse(data); err != nil {
		if errors.Is(err, errDuplicateMetricsAcknowledgement) {
			return nil
		}

		rejection, ok := errors.AsType[*metricRejection](err)
		if !ok {
			return err
		}

		stopTimer(x.metricsReplyTimer)
		stopTimer(x.metricsRetryTimer)

		if identityNodeReportRejection(rejection.code) {
			return &identityRejection{err: rejection}
		}
		if !terminalNodeReportRejection(rejection.code) {
			x.scheduleMetricsRetry(events, rejection.code)
			return nil
		}

		metricType := x.metrics.activeType()
		x.metrics.discardActive()
		notifyNodeReportRejection(events, NodeReportRejection{
			Type: metricType,
			Code: rejection.code,
		})
	} else {
		stopTimer(x.metricsReplyTimer)
		stopTimer(x.metricsRetryTimer)
	}

	sent, err := x.metrics.writeNext(ctx, conn)
	if err != nil {
		return err
	}
	if sent {
		x.metricsReplyTimer.Reset(metricsReplyTimeout)
	}

	return nil
}

func notifyNodeReportRejection(events Events, rejection NodeReportRejection) {
	if events.ReportRejected != nil {
		events.ReportRejected(rejection)
	}
}
