package nodeapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/coder/websocket"
)

// PeerConfig is what a Peer needs from the session that owns the connection.
type PeerConfig struct {
	Conn       *websocket.Conn
	Collectors Collectors
	// Reports carries report progress across connections to one peer;
	// nil starts afresh.
	Reports *ReportState
	// Reader names the peer's cursor in the metrics store.
	Reader string
	// Reject answers requests the node cannot accept.
	Reject RejectFunc
	Events Events
	// Logger receives the audit log of console commands; nil discards it.
	Logger *slog.Logger
}

// Peer serves the shared node protocol to one connected peer. Its methods
// must be called from the session loop that owns the connection; each wait
// channel below has a matching method that handles what it delivered.
type Peer struct {
	conn       *websocket.Conn
	exchange   *exchange
	containers *containerStreams
	reject     RejectFunc
	events     Events
}

// NewPeer starts collecting node reports for the peer. ctx bounds every
// goroutine the Peer starts; Close releases them.
func NewPeer(ctx context.Context, config PeerConfig) *Peer {
	if config.Reports == nil {
		config.Reports = &ReportState{}
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}

	return &Peer{
		conn:       config.Conn,
		exchange:   newExchange(ctx, config.Collectors, config.Reports, config.Reader),
		containers: newContainerStreams(ctx, config.Collectors.Containers, config.Collectors.Files, config.Conn, config.Logger),
		reject:     config.Reject,
		events:     config.Events,
	}
}

// Close stops the Peer's timers and container streams.
func (p *Peer) Close() {
	p.containers.close()
	p.exchange.stop()
}

// HandleMessage processes a JSON frame of the shared protocol: report and
// metrics acknowledgements, node requests, and container frames. It reports
// false for any other message type. An *IdentityRejection error means the
// peer rejected the node itself.
func (p *Peer) HandleMessage(ctx context.Context, messageType string, data []byte) (bool, error) {
	if handled, err := p.exchange.handleAcknowledgement(ctx, p.conn, messageType, data, p.events); handled {
		return true, err
	}
	if handled, err := p.exchange.handleRequest(ctx, p.conn, messageType, data, p.reject); handled {
		return true, err
	}

	return p.containers.handle(ctx, messageType, data, p.reject)
}

// HandleBinary processes a binary stream frame.
func (p *Peer) HandleBinary(ctx context.Context, data []byte) error {
	return p.containers.handleBinary(ctx, data, p.reject)
}

// StreamFinished delivers container streams that ended; pass each to FinishStream.
func (p *Peer) StreamFinished() <-chan uint32 { return p.containers.finished }

// FinishStream forgets a container stream that ended.
func (p *Peer) FinishStream(id uint32) { p.containers.streamFinished(id) }

// ReportCollected delivers collected node reports; pass each to SendReport.
func (p *Peer) ReportCollected() <-chan CollectedReport { return p.exchange.reports.results }

// SendReport writes a collected node report to the peer.
func (p *Peer) SendReport(ctx context.Context, report CollectedReport) error {
	return p.exchange.reportCollected(ctx, p.conn, report)
}

// ReportReplyTimeout fires when the peer did not acknowledge a node
// report in time; call ReportTimedOut.
func (p *Peer) ReportReplyTimeout() <-chan time.Time { return p.exchange.reportReplyTimer.C }

// ReportTimedOut schedules the unacknowledged node report again.
func (p *Peer) ReportTimedOut() { p.exchange.scheduleNodeReportRetry(p.events, "ack_timeout") }

// ReportRetry fires when a node report is due again; call RetryReport.
func (p *Peer) ReportRetry() <-chan time.Time { return p.exchange.reportRetryTimer.C }

// RetryReport resends the active node report.
func (p *Peer) RetryReport(ctx context.Context) error {
	return p.exchange.retryReport(ctx, p.conn)
}

// MetricsChanged fires when the metrics store has new samples; call
// SendMetrics. Read it anew on every wait: it changes after each fire.
func (p *Peer) MetricsChanged() <-chan struct{} { return p.exchange.metrics.wake }

// SendMetrics writes stored metrics the peer has not received yet.
func (p *Peer) SendMetrics(ctx context.Context) error {
	return p.exchange.metricsStored(ctx, p.conn)
}

// MetricsReplyTimeout fires when the peer did not acknowledge metrics in
// time; call MetricsTimedOut.
func (p *Peer) MetricsReplyTimeout() <-chan time.Time { return p.exchange.metricsReplyTimer.C }

// MetricsTimedOut schedules the unacknowledged metrics again.
func (p *Peer) MetricsTimedOut() { p.exchange.scheduleMetricsRetry(p.events, "ack_timeout") }

// MetricsRetry fires when metrics are due again; call RetryMetrics.
func (p *Peer) MetricsRetry() <-chan time.Time { return p.exchange.metricsRetryTimer.C }

// RetryMetrics resends the active metrics.
func (p *Peer) RetryMetrics(ctx context.Context) error {
	return p.exchange.retryMetrics(ctx, p.conn)
}
