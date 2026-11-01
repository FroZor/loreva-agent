package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/nodeapi"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/workload"
	"github.com/FroZor/loreva-agent/internal/wsframe"
)

var (
	errReconnectRequested = errors.New("portal requested reconnect")
	errDrainRequested     = errors.New("portal requested drain")
)

type liveState struct {
	peer              *nodeapi.Peer
	renewal           *activeRenewal
	renewReplyTimer   *time.Timer
	sourceExpiryTimer *time.Timer
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

	reads := nodeapi.ReadFrames(readCtx, conn)

	renewDelay, err := r.renewalDelay(time.Now())
	if err != nil {
		return &permanentError{Err: err}
	}

	renewTimer := time.NewTimer(renewDelay)
	defer renewTimer.Stop()

	pingTimer := time.NewTimer(nodeapi.NextPingDelay())
	defer pingTimer.Stop()

	renewReplyTimer := nodeapi.NewStoppedTimer()
	defer renewReplyTimer.Stop()

	sourceExpiryTimer, sourceExpiry := r.newSourceExpiryTimer(endpoint)
	if sourceExpiryTimer != nil {
		defer sourceExpiryTimer.Stop()
	}

	logger := r.collectors.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	peer := nodeapi.NewPeer(readCtx, nodeapi.PeerConfig{
		Conn:       conn,
		Collectors: r.collectors,
		Reports:    &r.reports,
		Reader:     "portal:" + r.identity.PortalID,
		Reject:     nodeapi.Reject(conn),
		Events:     nodeapi.Events{ReportRejected: events.ReportRejected},
		Logger:     logger.With("portal_id", r.identity.PortalID),
	})
	defer peer.Close()

	live := liveState{
		peer:              peer,
		renewReplyTimer:   renewReplyTimer,
		sourceExpiryTimer: sourceExpiryTimer,
	}
	var workloadResults <-chan any
	if r.workloads != nil {
		workloadResults = r.workloads.Results(r.identity.PortalID)
	}

	for {
		select {
		case <-ctx.Done():
			closeErr := conn.Close(websocket.StatusNormalClosure, "shutdown")
			return errors.Join(ctx.Err(), closeErr)
		case frame := <-reads:
			if frame.Err != nil {
				return frame.Err
			}

			if frame.Binary {
				if err := peer.HandleBinary(readCtx, frame.Data); err != nil {
					return err
				}
				continue
			}
			if err := r.handleWorkingMessage(readCtx, conn, sessionNonce, endpoint, frame.Data, &live); err != nil {
				return err
			}
		case response := <-workloadResults:
			if err := nodeapi.WriteFrame(readCtx, conn, response); err != nil {
				return fmt.Errorf("write workload response: %w", err)
			}
		case id := <-peer.StreamFinished():
			peer.FinishStream(id)
		case report := <-peer.ReportCollected():
			if err := peer.SendReport(readCtx, report); err != nil {
				return err
			}
		case <-peer.ReportReplyTimeout():
			peer.ReportTimedOut()
		case <-peer.ReportRetry():
			if err := peer.RetryReport(readCtx); err != nil {
				return err
			}
		case <-peer.MetricsChanged():
			if err := peer.SendMetrics(readCtx); err != nil {
				return err
			}
		case <-peer.MetricsReplyTimeout():
			peer.MetricsTimedOut()
		case <-peer.MetricsRetry():
			if err := peer.RetryMetrics(readCtx); err != nil {
				return err
			}
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
			if err := nodeapi.Ping(ctx, conn); err != nil {
				return err
			}

			*heartbeatHealthy = true
			pingTimer.Reset(nodeapi.NextPingDelay())
		}
	}
}

func (r *Runner) handleWorkingMessage(
	ctx context.Context,
	conn *websocket.Conn,
	sessionNonce string,
	endpoint string,
	data []byte,
	live *liveState,
) error {
	messageType, err := protocol.MessageType(data)
	if err != nil {
		return r.endpointFailure(endpoint, errors.New("working message is not valid JSON"))
	}

	if handled, err := live.peer.HandleMessage(ctx, messageType, data); handled {
		return r.peerFailure(endpoint, err)
	}

	switch messageType {
	case protocol.PortalCommandType:
		return r.handlePortalCommand(ctx, conn, sessionNonce, endpoint, data)
	case protocol.SourcesUpdateType:
		return r.handleSourcesUpdate(conn, endpoint, data, live.sourceExpiryTimer)
	case protocol.DrainType:
		return r.handleDrain(conn, endpoint, data)
	case protocol.RenewAcceptedType, protocol.RenewRejectedType:
		if live.renewal == nil {
			return r.endpointFailure(endpoint, errors.New("portal sent an unsolicited renewal result"))
		}

		nodeapi.StopTimer(live.renewReplyTimer)

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
		return nodeapi.WriteWorkloadRejected(ctx, conn, command, "workload_runtime_unavailable")
	}
	if err := r.workloads.Submit(command, r.artifacts); err != nil {
		return nodeapi.WriteWorkloadRejected(ctx, conn, command, "workload_queue_full")
	}

	return nil
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

func resetTimerAt(timer *time.Timer, deadline time.Time) {
	nodeapi.StopTimer(timer)
	timer.Reset(durationUntil(deadline))
}

func durationUntil(deadline time.Time) time.Duration {
	delay := time.Until(deadline)
	if delay < 0 {
		return 0
	}

	return delay
}

// peerFailure ends the endpoint when the portal no longer recognizes the
// node; other errors from the shared protocol pass through unchanged.
func (r *Runner) peerFailure(endpoint string, err error) error {
	if rejection, ok := errors.AsType[*nodeapi.IdentityRejection](err); ok {
		return r.endpointFailure(endpoint, rejection.Err)
	}

	return err
}
