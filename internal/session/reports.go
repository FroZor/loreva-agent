package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/networkinfo"
	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/specifications"
)

const (
	maxNodeReportSize      = 512 * 1024
	nodeCollectionTimeout  = 30 * time.Second
	nodeReportWriteTimeout = 10 * time.Second
	nodeReportReplyTimeout = 30 * time.Second
)

type nodeReportKind uint8

const (
	nodeReportSpecifications nodeReportKind = iota + 1
	nodeReportNetwork
)

type collectedNodeReport struct {
	kind           nodeReportKind
	specifications specifications.Snapshot
	network        networkinfo.Snapshot
	retry          bool
	err            error
}

type activeNodeReport struct {
	kind      nodeReportKind
	requestID string
	payload   []byte
}

type nodeReportState struct {
	next                  nodeReportKind
	active                *activeNodeReport
	retryAttempt          int
	lastAcceptedKind      nodeReportKind
	lastAcceptedRequestID string
	lastAcceptedRevision  int64
	complete              bool
}

type nodeReporter struct {
	collectors Collectors
	results    chan collectedNodeReport
	state      *nodeReportState
}

type nodeReportRejection struct {
	code    string
	message string
}

var errDuplicateNodeReportAcknowledgement = errors.New("duplicate node report acknowledgement")

func (rejection *nodeReportRejection) Error() string {
	if rejection.message == "" {
		return "portal rejected node report: " + rejection.code
	}

	return "portal rejected node report: " + rejection.code + ": " + rejection.message
}

func newNodeReporter(ctx context.Context, collectors Collectors, state *nodeReportState) *nodeReporter {
	if state.complete {
		*state = nodeReportState{}
	}
	if state.next == 0 {
		state.next = nodeReportSpecifications
	}

	reporter := &nodeReporter{
		collectors: collectors,
		results:    make(chan collectedNodeReport, 1),
		state:      state,
	}
	reporter.startNext(ctx)

	return reporter
}

func (reporter *nodeReporter) startNext(ctx context.Context) {
	if reporter.state.active != nil {
		reporter.sendResult(ctx, collectedNodeReport{
			kind:  reporter.state.active.kind,
			retry: true,
		})
		return
	}

	for reporter.state.next <= nodeReportNetwork {
		kind := reporter.state.next

		switch kind {
		case nodeReportSpecifications:
			if reporter.collectors.Specifications == nil {
				reporter.state.next++
				continue
			}

			go reporter.collectSpecifications(ctx)
			return
		case nodeReportNetwork:
			if reporter.collectors.Network == nil {
				reporter.state.next++
				continue
			}

			go reporter.collectNetwork(ctx)
			return
		}
	}

	reporter.state.complete = true
}

func (reporter *nodeReporter) collectSpecifications(ctx context.Context) {
	collectionCtx, cancel := context.WithTimeout(ctx, nodeCollectionTimeout)
	snapshot, err := reporter.collectors.Specifications(collectionCtx)
	cancel()

	reporter.sendResult(ctx, collectedNodeReport{
		kind:           nodeReportSpecifications,
		specifications: snapshot,
		err:            err,
	})
}

func (reporter *nodeReporter) collectNetwork(ctx context.Context) {
	collectionCtx, cancel := context.WithTimeout(ctx, nodeCollectionTimeout)
	snapshot, err := reporter.collectors.Network(collectionCtx)
	cancel()

	reporter.sendResult(ctx, collectedNodeReport{
		kind:    nodeReportNetwork,
		network: snapshot,
		err:     err,
	})
}

func (reporter *nodeReporter) sendResult(ctx context.Context, result collectedNodeReport) {
	select {
	case reporter.results <- result:
	case <-ctx.Done():
	}
}

func (reporter *nodeReporter) writeResult(
	ctx context.Context,
	conn *websocket.Conn,
	result collectedNodeReport,
) error {
	if result.err != nil {
		return fmt.Errorf("collect node report: %w", result.err)
	}

	if result.retry {
		return reporter.writeActive(ctx, conn, result.kind)
	}
	if reporter.state.active != nil {
		return errors.New("node report collection completed while another report is pending")
	}

	requestID, err := agentcrypto.NewUUID()
	if err != nil {
		return fmt.Errorf("create node report request ID: %w", err)
	}

	var report any
	switch result.kind {
	case nodeReportSpecifications:
		report = protocol.NodeSpecificationsReport{
			Type:             protocol.NodeSpecificationsReportType,
			SchemaVersion:    protocol.NodeSpecificationsSchemaVersion,
			RequestID:        requestID,
			ObservedAt:       time.Now().UTC(),
			ObservationScope: result.specifications.ObservationScope,
			Specifications:   result.specifications.Specifications,
		}
	case nodeReportNetwork:
		report = protocol.NodeNetworkReport{
			Type:             protocol.NodeNetworkReportType,
			SchemaVersion:    protocol.NodeNetworkSchemaVersion,
			RequestID:        requestID,
			ObservedAt:       time.Now().UTC(),
			ObservationScope: result.network.ObservationScope,
			Network:          result.network.Network,
		}
	default:
		return errors.New("unknown node report kind")
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode node report: %w", err)
	}
	if len(payload) > maxNodeReportSize {
		return fmt.Errorf("node report exceeds %d bytes", maxNodeReportSize)
	}

	reporter.state.active = &activeNodeReport{
		kind:      result.kind,
		requestID: requestID,
		payload:   payload,
	}

	return reporter.writeActive(ctx, conn, result.kind)
}

func (reporter *nodeReporter) writeActive(
	ctx context.Context,
	conn *websocket.Conn,
	kind nodeReportKind,
) error {
	active := reporter.state.active
	if active == nil || active.kind != kind {
		return errors.New("invalid pending node report")
	}

	writeCtx, cancel := context.WithTimeout(ctx, nodeReportWriteTimeout)
	err := conn.Write(writeCtx, websocket.MessageText, active.payload)
	cancel()

	if err != nil {
		return fmt.Errorf("write node report: %w", err)
	}

	return nil
}

func (reporter *nodeReporter) handleResponse(ctx context.Context, data []byte) error {
	messageType, err := protocol.MessageType(data)
	if err != nil {
		return errors.New("node report result is not valid JSON")
	}
	if messageType == reporter.lastAcceptedType() {
		requestID, revision, err := decodeNodeReportAccepted(data, reporter.state.lastAcceptedKind)
		if err != nil {
			return err
		}
		if requestID != reporter.state.lastAcceptedRequestID || revision != reporter.state.lastAcceptedRevision {
			return errors.New("conflicting duplicate node report acknowledgement")
		}

		return errDuplicateNodeReportAcknowledgement
	}
	if reporter.state.active == nil {
		return errors.New("portal sent an unsolicited node report result")
	}

	expectedAccepted, expectedRejected := reporter.expectedResponseTypes()
	if messageType == expectedRejected {
		var rejected protocol.NodeReportRejected
		if err := protocol.DecodeStrict(data, &rejected); err != nil {
			return fmt.Errorf("decode node report rejection: %w", err)
		}
		if rejected.RequestID != reporter.state.active.requestID || rejected.Code == "" {
			return errors.New("invalid node report rejection")
		}

		return &nodeReportRejection{code: rejected.Code, message: rejected.Message}
	}
	if messageType != expectedAccepted {
		return fmt.Errorf("unexpected node report result type %q", messageType)
	}

	requestID, revision, err := decodeNodeReportAccepted(data, reporter.state.active.kind)
	if err != nil {
		return err
	}
	if requestID != reporter.state.active.requestID || revision <= 0 {
		return errors.New("invalid node report acknowledgement")
	}

	reporter.state.lastAcceptedKind = reporter.state.active.kind
	reporter.state.lastAcceptedRequestID = requestID
	reporter.state.lastAcceptedRevision = revision
	reporter.advance(ctx)

	return nil
}

func (reporter *nodeReporter) lastAcceptedType() string {
	switch reporter.state.lastAcceptedKind {
	case nodeReportSpecifications:
		return protocol.NodeSpecificationsAcceptedType
	case nodeReportNetwork:
		return protocol.NodeNetworkAcceptedType
	default:
		return ""
	}
}

func (reporter *nodeReporter) retryDelay() time.Duration {
	reporter.state.retryAttempt++

	return retryDelay(reporter.state.retryAttempt)
}

func (reporter *nodeReporter) skip(ctx context.Context) {
	reporter.advance(ctx)
}

func (reporter *nodeReporter) advance(ctx context.Context) {
	reporter.state.next = reporter.state.active.kind + 1
	reporter.state.active = nil
	reporter.state.retryAttempt = 0
	reporter.startNext(ctx)
}

func (reporter *nodeReporter) activeType() string {
	if reporter.state.active == nil {
		return ""
	}

	switch reporter.state.active.kind {
	case nodeReportSpecifications:
		return protocol.NodeSpecificationsReportType
	case nodeReportNetwork:
		return protocol.NodeNetworkReportType
	default:
		return ""
	}
}

func (reporter *nodeReporter) expectedResponseTypes() (string, string) {
	switch reporter.state.active.kind {
	case nodeReportSpecifications:
		return protocol.NodeSpecificationsAcceptedType, protocol.NodeSpecificationsRejectedType
	case nodeReportNetwork:
		return protocol.NodeNetworkAcceptedType, protocol.NodeNetworkRejectedType
	default:
		return "", ""
	}
}

func decodeNodeReportAccepted(data []byte, kind nodeReportKind) (string, int64, error) {
	switch kind {
	case nodeReportSpecifications:
		var accepted protocol.NodeSpecificationsAccepted
		if err := protocol.DecodeStrict(data, &accepted); err != nil {
			return "", 0, fmt.Errorf("decode specifications acknowledgement: %w", err)
		}

		return accepted.RequestID, accepted.Revision, nil
	case nodeReportNetwork:
		var accepted protocol.NodeNetworkAccepted
		if err := protocol.DecodeStrict(data, &accepted); err != nil {
			return "", 0, fmt.Errorf("decode network acknowledgement: %w", err)
		}

		return accepted.RequestID, accepted.Revision, nil
	default:
		return "", 0, errors.New("unknown node report kind")
	}
}

func terminalNodeReportRejection(code string) bool {
	switch code {
	case "internal_error", "temporarily_unavailable":
		return false
	default:
		return true
	}
}

func identityNodeReportRejection(code string) bool {
	switch code {
	case "node_not_registered", "node_revoked":
		return true
	default:
		return false
	}
}
