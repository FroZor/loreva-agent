package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/workload"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

const (
	pingInterval         = 30 * time.Second
	pingJitter           = 5 * time.Second
	pongTimeout          = 10 * time.Second
	workloadWriteTimeout = 10 * time.Second
)

var (
	errReconnectRequested = errors.New("portal requested reconnect")
	errDrainRequested     = errors.New("portal requested drain")
)

type readResult struct {
	data []byte
	err  error
}

type liveState struct {
	renewal           *activeRenewal
	renewReplyTimer   *time.Timer
	sourceExpiryTimer *time.Timer
	reports           *nodeReporter
	reportReplyTimer  *time.Timer
	reportRetryTimer  *time.Timer
	metrics           *metricReporter
	metricsReplyTimer *time.Timer
	metricsRetryTimer *time.Timer
}

func (r *Runner) maintain(
	ctx context.Context,
	conn *websocket.Conn,
	sessionNonce string,
	endpoint string,
	events Events,
	heartbeatHealthy *bool,
) error {
	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()

	reads := startFrameReader(readCtx, conn)

	renewDelay, err := r.renewalDelay(time.Now())
	if err != nil {
		return &permanentError{Err: err}
	}

	renewTimer := time.NewTimer(renewDelay)
	defer renewTimer.Stop()

	pingTimer := time.NewTimer(nextPingDelay())
	defer pingTimer.Stop()

	renewReplyTimer := newStoppedTimer()
	defer renewReplyTimer.Stop()

	reportReplyTimer := newStoppedTimer()
	defer reportReplyTimer.Stop()

	reportRetryTimer := newStoppedTimer()
	defer reportRetryTimer.Stop()

	metricsReplyTimer := newStoppedTimer()
	defer metricsReplyTimer.Stop()

	metricsRetryTimer := newStoppedTimer()
	defer metricsRetryTimer.Stop()

	sourceExpiryTimer, sourceExpiry := r.newSourceExpiryTimer(endpoint)
	if sourceExpiryTimer != nil {
		defer sourceExpiryTimer.Stop()
	}

	metricReporter, err := newMetricReporter(readCtx, r.collectors.Metrics, &r.metrics)
	if err != nil {
		return &permanentError{Err: err}
	}

	live := liveState{
		renewReplyTimer:   renewReplyTimer,
		sourceExpiryTimer: sourceExpiryTimer,
		reports:           newNodeReporter(readCtx, r.collectors, &r.reports),
		reportReplyTimer:  reportReplyTimer,
		reportRetryTimer:  reportRetryTimer,
		metrics:           metricReporter,
		metricsReplyTimer: metricsReplyTimer,
		metricsRetryTimer: metricsRetryTimer,
	}
	var workloadResults <-chan any
	if r.workloads != nil {
		workloadResults = r.workloads.Results()
	}

	for {
		select {
		case <-ctx.Done():
			closeErr := conn.Close(websocket.StatusNormalClosure, "shutdown")
			return errors.Join(ctx.Err(), closeErr)
		case result := <-reads:
			if result.err != nil {
				return result.err
			}

			if err := r.handleWorkingMessage(readCtx, conn, sessionNonce, endpoint, result.data, &live, events); err != nil {
				return err
			}
		case response := <-workloadResults:
			writeCtx, cancel := context.WithTimeout(readCtx, workloadWriteTimeout)
			err := wsframe.WriteJSON(writeCtx, conn, response)
			cancel()
			if err != nil {
				return fmt.Errorf("write workload response: %w", err)
			}
		case report := <-live.reports.results:
			if err := live.reports.writeResult(readCtx, conn, report); err != nil {
				return err
			}

			reportReplyTimer.Reset(nodeReportReplyTimeout)
		case <-reportReplyTimer.C:
			r.scheduleNodeReportRetry(&live, events, "ack_timeout")
		case <-reportRetryTimer.C:
			active := live.reports.state.active
			if active == nil {
				return errors.New("node report retry fired without an active report")
			}
			if err := live.reports.writeActive(readCtx, conn, active.kind); err != nil {
				return err
			}

			reportReplyTimer.Reset(nodeReportReplyTimeout)
		case collection := <-live.metrics.results:
			if err := live.metrics.enqueue(collection); err != nil {
				continue
			}
			if !live.reports.state.complete {
				continue
			}

			sent, err := live.metrics.writeNext(readCtx, conn)
			if err != nil {
				return err
			}
			if sent {
				metricsReplyTimer.Reset(metricsReplyTimeout)
			}
		case <-metricsReplyTimer.C:
			r.scheduleMetricsRetry(&live, events, "ack_timeout")
		case <-metricsRetryTimer.C:
			if err := live.metrics.writeActive(readCtx, conn); err != nil {
				return err
			}

			metricsReplyTimer.Reset(metricsReplyTimeout)
		case <-renewTimer.C:
			if live.renewal != nil {
				return &permanentError{Err: errors.New("renewal timer fired while a request is pending")}
			}

			live.renewal, err = r.startRenewal(ctx, conn, sessionNonce)
			if err != nil {
				return err
			}

			renewReplyTimer.Reset(renewReplyTimeout)
		case <-renewReplyTimer.C:
			return errors.New("portal did not answer the renewal request before its proof expired")
		case <-sourceExpiry:
			closeErr := conn.Close(websocket.StatusNormalClosure, "source pool expired")
			return errors.Join(errReconnectRequested, closeErr)
		case <-pingTimer.C:
			if err := ping(ctx, conn); err != nil {
				return err
			}

			*heartbeatHealthy = true
			pingTimer.Reset(nextPingDelay())
		}
	}
}

func startFrameReader(ctx context.Context, conn *websocket.Conn) <-chan readResult {
	results := make(chan readResult, 1)

	go func() {
		for {
			messageType, data, err := conn.Read(ctx)
			if err != nil {
				sendReadResult(ctx, results, readResult{err: err})
				return
			}
			if messageType != websocket.MessageText {
				sendReadResult(ctx, results, readResult{err: errors.New("portal sent a non-text protocol message")})
				return
			}
			if !sendReadResult(ctx, results, readResult{data: data}) {
				return
			}
		}
	}()

	return results
}

func sendReadResult(ctx context.Context, results chan<- readResult, result readResult) bool {
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *Runner) handleWorkingMessage(
	ctx context.Context,
	conn *websocket.Conn,
	sessionNonce string,
	endpoint string,
	data []byte,
	live *liveState,
	events Events,
) error {
	messageType, err := protocol.MessageType(data)
	if err != nil {
		return r.endpointFailure(endpoint, errors.New("working message is not valid JSON"))
	}

	switch messageType {
	case protocol.PortalCommandType:
		return r.handlePortalCommand(ctx, conn, sessionNonce, endpoint, data)
	case protocol.NodeSpecificationsAcceptedType,
		protocol.NodeSpecificationsRejectedType,
		protocol.NodeNetworkAcceptedType,
		protocol.NodeNetworkRejectedType:
		reportType := live.reports.activeType()
		if err := live.reports.handleResponse(ctx, data); err != nil {
			if errors.Is(err, errDuplicateNodeReportAcknowledgement) {
				return nil
			}

			rejection, ok := errors.AsType[*nodeReportRejection](err)
			if !ok {
				return err
			}

			stopTimer(live.reportReplyTimer)
			stopTimer(live.reportRetryTimer)

			if identityNodeReportRejection(rejection.code) {
				return r.endpointFailure(endpoint, rejection)
			}
			if !terminalNodeReportRejection(rejection.code) {
				r.scheduleNodeReportRetry(live, events, rejection.code)
				return nil
			}

			live.reports.skip(ctx)
			notifyNodeReportRejection(events, NodeReportRejection{
				Type: reportType,
				Code: rejection.code,
			})
			if live.reports.state.complete {
				sent, err := live.metrics.writeReady(ctx, conn)
				if err != nil {
					return err
				}
				if sent {
					live.metricsReplyTimer.Reset(metricsReplyTimeout)
				}
			}

			return nil
		}

		stopTimer(live.reportReplyTimer)
		stopTimer(live.reportRetryTimer)

		if live.reports.state.complete {
			sent, err := live.metrics.writeReady(ctx, conn)
			if err != nil {
				return err
			}
			if sent {
				live.metricsReplyTimer.Reset(metricsReplyTimeout)
			}
		}

		return nil
	case protocol.MetricsAcceptedType, protocol.MetricsRejectedType:
		if err := live.metrics.handleResponse(data); err != nil {
			if errors.Is(err, errDuplicateMetricsAcknowledgement) {
				return nil
			}

			rejection, ok := errors.AsType[*metricRejection](err)
			if !ok {
				return err
			}

			stopTimer(live.metricsReplyTimer)
			stopTimer(live.metricsRetryTimer)

			if identityNodeReportRejection(rejection.code) {
				return r.endpointFailure(endpoint, rejection)
			}
			if !terminalNodeReportRejection(rejection.code) {
				r.scheduleMetricsRetry(live, events, rejection.code)
				return nil
			}

			metricType := live.metrics.activeType()
			live.metrics.discardActive()
			notifyNodeReportRejection(events, NodeReportRejection{
				Type: metricType,
				Code: rejection.code,
			})
		} else {
			stopTimer(live.metricsReplyTimer)
			stopTimer(live.metricsRetryTimer)
		}

		sent, err := live.metrics.writeNext(ctx, conn)
		if err != nil {
			return err
		}
		if sent {
			live.metricsReplyTimer.Reset(metricsReplyTimeout)
		}

		return nil
	case protocol.SourcesUpdateType:
		return r.handleSourcesUpdate(conn, endpoint, data, live.sourceExpiryTimer)
	case protocol.DrainType:
		return r.handleDrain(conn, endpoint, data)
	case protocol.RenewAcceptedType, protocol.RenewRejectedType:
		if live.renewal == nil {
			return r.endpointFailure(endpoint, errors.New("portal sent an unsolicited renewal result"))
		}

		stopTimer(live.renewReplyTimer)

		return r.handleRenewalResponse(conn, endpoint, live.renewal, data)
	default:
		return r.endpointFailure(endpoint, fmt.Errorf("unsupported working message type %q", messageType))
	}
}

func (r *Runner) handlePortalCommand(
	ctx context.Context,
	conn *websocket.Conn,
	sessionNonce string,
	endpoint string,
	data []byte,
) error {
	var envelope protocol.PortalCommand
	if err := protocol.DecodeStrict(data, &envelope); err != nil {
		return r.endpointFailure(endpoint, fmt.Errorf("decode portal.command message: %w", err))
	}
	if envelope.Type != protocol.PortalCommandType || envelope.SignedCommand == "" {
		return r.endpointFailure(endpoint, errors.New("invalid portal.command message"))
	}

	command, err := workload.VerifyCommand(
		&r.identity.PortalPQRoot,
		envelope.SignedCommand,
		r.identity.PortalID,
		r.identity.NodeID,
		sessionNonce,
		time.Now(),
	)
	if err != nil {
		return r.endpointFailure(endpoint, err)
	}
	if r.workloads == nil {
		return r.writeWorkloadUnavailable(ctx, conn, command, "workload_runtime_unavailable")
	}
	if err := r.workloads.Submit(command); err != nil {
		return r.writeWorkloadUnavailable(ctx, conn, command, "workload_queue_full")
	}

	return nil
}

func (r *Runner) writeWorkloadUnavailable(
	ctx context.Context,
	conn *websocket.Conn,
	command protocol.WorkloadCommand,
	code string,
) error {
	writeCtx, cancel := context.WithTimeout(ctx, workloadWriteTimeout)
	err := wsframe.WriteJSON(writeCtx, conn, protocol.WorkloadOperationResult{
		Type:          protocol.WorkloadOperationResultType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload: protocol.WorkloadOperationResultPayload{
			State: "rejected", Code: code,
		},
	})
	cancel()

	return err
}

func (r *Runner) scheduleNodeReportRetry(live *liveState, events Events, code string) {
	delay := live.reports.retryDelay()
	stopTimer(live.reportRetryTimer)
	live.reportRetryTimer.Reset(delay)

	notifyNodeReportRejection(events, NodeReportRejection{
		Type:      live.reports.activeType(),
		Code:      code,
		RetryIn:   delay,
		Retryable: true,
	})
}

func (r *Runner) scheduleMetricsRetry(live *liveState, events Events, code string) {
	delay := live.metrics.retryDelay()
	stopTimer(live.metricsRetryTimer)
	live.metricsRetryTimer.Reset(delay)

	notifyNodeReportRejection(events, NodeReportRejection{
		Type:      live.metrics.activeType(),
		Code:      code,
		RetryIn:   delay,
		Retryable: true,
	})
}

func notifyNodeReportRejection(events Events, rejection NodeReportRejection) {
	if events.ReportRejected != nil {
		events.ReportRejected(rejection)
	}
}

func (r *Runner) handleSourcesUpdate(conn *websocket.Conn, endpoint string, data []byte, expiryTimer *time.Timer) error {
	var update protocol.SourcesUpdate
	if err := protocol.DecodeStrict(data, &update); err != nil {
		return r.endpointFailure(endpoint, fmt.Errorf("decode sources.update message: %w", err))
	}
	if update.Type != protocol.SourcesUpdateType {
		return r.endpointFailure(endpoint, errors.New("invalid sources.update message"))
	}

	reconnect, err := r.applySourcesUpdate(endpoint, update.Sources)
	if err != nil {
		return r.endpointFailure(endpoint, err)
	}
	if reconnect {
		closeErr := conn.Close(websocket.StatusNormalClosure, "source pool updated")
		return errors.Join(errReconnectRequested, closeErr)
	}

	if expiryTimer != nil {
		resetTimerAt(expiryTimer, r.identity.Sources.ExpiresAt)
	}

	return nil
}

func (r *Runner) handleDrain(conn *websocket.Conn, endpoint string, data []byte) error {
	var drain protocol.Drain
	if err := protocol.DecodeStrict(data, &drain); err != nil {
		return r.endpointFailure(endpoint, fmt.Errorf("decode drain message: %w", err))
	}
	if drain.Type != protocol.DrainType || (drain.Deadline != nil && drain.Deadline.IsZero()) {
		return r.endpointFailure(endpoint, errors.New("invalid drain message"))
	}

	closeErr := conn.Close(websocket.StatusNormalClosure, "portal drain")

	return errors.Join(errDrainRequested, closeErr)
}

func (r *Runner) startRenewal(ctx context.Context, conn *websocket.Conn, sessionNonce string) (*activeRenewal, error) {
	pending, material, err := r.loadOrCreateRenewal()
	if err != nil {
		return nil, &permanentError{Err: err}
	}

	proof, err := agentcrypto.RenewalPoP(
		material,
		r.identity.PortalID,
		pending.JTI,
		sessionNonce,
		time.Now().Add(renewProofTTL),
	)
	if err != nil {
		return nil, &permanentError{Err: err}
	}

	writeCtx, cancel := context.WithTimeout(ctx, renewWriteTimeout)
	err = wsframe.WriteJSON(writeCtx, conn, protocol.RenewRequest{
		Type:  protocol.RenewRequestType,
		CSR:   pending.CSR,
		PQPoP: proof,
	})
	cancel()

	if err != nil {
		return nil, fmt.Errorf("write renewal request: %w", err)
	}

	return &activeRenewal{pending: pending, material: material}, nil
}

func (r *Runner) newSourceExpiryTimer(endpoint string) (*time.Timer, <-chan time.Time) {
	if endpoint == r.masterEndpoint {
		return nil, nil
	}

	timer := time.NewTimer(durationUntil(r.identity.Sources.ExpiresAt))

	return timer, timer.C
}

func newStoppedTimer() *time.Timer {
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)

	return timer
}

func resetTimerAt(timer *time.Timer, deadline time.Time) {
	stopTimer(timer)
	timer.Reset(durationUntil(deadline))
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func durationUntil(deadline time.Time) time.Duration {
	delay := time.Until(deadline)
	if delay < 0 {
		return 0
	}

	return delay
}

func ping(ctx context.Context, conn *websocket.Conn) error {
	pingCtx, cancel := context.WithTimeout(ctx, pongTimeout)
	err := conn.Ping(pingCtx)
	cancel()

	if err != nil {
		return fmt.Errorf("portal heartbeat failed: %w", err)
	}

	return nil
}

func nextPingDelay() time.Duration {
	return pingInterval - pingJitter + randomDuration(2*pingJitter+1)
}
