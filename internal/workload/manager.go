package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	workloadQueueCapacity = 32
	// controllerQueueShare is how many queued commands one controller may
	// hold, so one controller cannot keep the queue full for the others.
	controllerQueueShare = workloadQueueCapacity / 2
	resultQueueCapacity  = workloadQueueCapacity * 2
	// maxArtifactCacheBytes is the artifact cache size beyond which uploads
	// from devices are refused.
	maxArtifactCacheBytes = 1 << 30
)

// ErrBusy indicates that the bounded workload command queue is full.
var ErrBusy = errors.New("workload command queue is full")

// Config supplies local state to a Manager.
type Config struct {
	StateDir string
}

// queuedCommand is an authenticated command and where its artifacts come from.
type queuedCommand struct {
	command protocol.WorkloadCommand
	source  ArtifactSource
}

// Manager serializes workload mutations from every controller (the portal
// and paired devices) without blocking any session heartbeat. Each command
// carries its controller in portal_id, and responses go back to that
// controller only.
type Manager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	commands   chan queuedCommand
	queuedMu   sync.Mutex
	queued     map[string]int
	resultsMu  sync.Mutex
	results    map[string]chan any
	plans      planStore
	builder    planBuilder
	runtime    *dockerRuntime
	runtimeErr error
	wait       sync.WaitGroup
}

// New creates and starts a workload manager. Docker unavailability is retained
// as a command result and does not prevent the node from connecting.
func New(ctx context.Context, config Config) (*Manager, error) {
	if config.StateDir == "" {
		return nil, errors.New("workload state directory is required")
	}
	stateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve workload state directory: %w", err)
	}

	managerCtx, cancel := context.WithCancel(ctx)
	root := filepath.Join(stateDir, "workloads")
	manager := &Manager{
		ctx:      managerCtx,
		cancel:   cancel,
		commands: make(chan queuedCommand, workloadQueueCapacity),
		queued:   make(map[string]int),
		results:  make(map[string]chan any),
		plans:    planStore{root: root},
		builder: planBuilder{
			stateRoot: stateDir,
			artifacts: artifactStore{root: filepath.Join(root, "artifacts"), uploadLimit: maxArtifactCacheBytes},
		},
	}
	manager.runtime, manager.runtimeErr = openDockerRuntime(managerCtx, root)

	manager.wait.Add(1)
	go manager.run()

	return manager, nil
}

// Submit queues an already authenticated command without blocking. source
// fetches artifacts that are not cached; it may be nil when the controller
// uploads artifacts before planning.
func (manager *Manager) Submit(command protocol.WorkloadCommand, source ArtifactSource) error {
	manager.queuedMu.Lock()
	defer manager.queuedMu.Unlock()

	if manager.queued[command.PortalID] >= controllerQueueShare {
		return ErrBusy
	}

	select {
	case manager.commands <- queuedCommand{command: command, source: source}:
		manager.queued[command.PortalID]++
		return nil
	default:
		return ErrBusy
	}
}

func (manager *Manager) dequeued(controller string) {
	manager.queuedMu.Lock()
	defer manager.queuedMu.Unlock()

	manager.queued[controller]--
	if manager.queued[controller] <= 0 {
		delete(manager.queued, controller)
	}
}

// Results returns the responses to commands whose portal_id is controller.
// One session reads them at a time. A response that finds the queue full is
// dropped rather than stalling other controllers: operation results are
// persisted, so repeating the request_id returns them again.
func (manager *Manager) Results(controller string) <-chan any {
	return manager.resultQueue(controller)
}

// StoreArtifact saves an uploaded artifact in the cache that plans read.
func (manager *Manager) StoreArtifact(reference protocol.ArtifactReference, data io.Reader) error {
	return manager.builder.artifacts.store(reference, data)
}

func (manager *Manager) resultQueue(controller string) chan any {
	manager.resultsMu.Lock()
	defer manager.resultsMu.Unlock()

	queue, found := manager.results[controller]
	if !found {
		queue = make(chan any, resultQueueCapacity)
		manager.results[controller] = queue
	}

	return queue
}

// Close stops pending work and releases Docker resources.
func (manager *Manager) Close() error {
	manager.cancel()
	manager.wait.Wait()

	return manager.runtime.close()
}

func (manager *Manager) run() {
	defer manager.wait.Done()

	for {
		select {
		case <-manager.ctx.Done():
			return
		case queued := <-manager.commands:
			manager.dequeued(queued.command.PortalID)
			manager.handle(queued.command, queued.source)
		}
	}
}

func (manager *Manager) handle(command protocol.WorkloadCommand, source ArtifactSource) {
	if command.Type == protocol.WorkloadPlanRequestType {
		manager.handlePlan(command, source)
		return
	}

	commandDigest, err := commandDigest(command)
	if err != nil {
		manager.emit(command.PortalID, operationResult(command, "rejected", "invalid_operation", err))
		return
	}
	if manager.replayOrReject(command, commandDigest) {
		return
	}

	if manager.runtime == nil {
		manager.finish(command, commandDigest, "failed", "runtime_unavailable", manager.runtimeErr)
		return
	}

	operation, plan, err := manager.validateOperation(command)
	if err != nil {
		manager.finish(command, commandDigest, "rejected", "invalid_operation", err)
		return
	}
	if err := manager.plans.startOperation(command.RequestID, commandDigest); err != nil {
		manager.finish(command, commandDigest, "failed", "state_persistence_failed", err)
		return
	}

	sequence := 0
	progress := func(step string) {
		sequence++
		manager.emit(command.PortalID, operationEvent(command, sequence, step))
	}
	progress(operation)

	switch operation {
	case "execute":
		err = manager.runtime.execute(manager.ctx, manager.plans, plan, progress)
	case "stop", "restart", "delete":
		err = manager.runtime.lifecycle(
			manager.ctx,
			manager.plans,
			command.PortalID,
			command.NodeID,
			command.WorkloadID,
			operation,
			operationTimeout(command),
		)
	default:
		err = errors.New("unsupported internal workload operation")
	}
	if err != nil {
		manager.finish(command, commandDigest, "unknown", "operation_outcome_unknown", err)
		return
	}

	manager.finish(command, commandDigest, "succeeded", "", nil)
}

func operationEvent(
	command protocol.WorkloadCommand,
	sequence int,
	step string,
) protocol.WorkloadOperationEvent {
	return protocol.WorkloadOperationEvent{
		Type:          protocol.WorkloadOperationEventType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload: protocol.WorkloadOperationEventPayload{
			Sequence: sequence,
			State:    "running",
			Step:     step,
		},
	}
}

func (manager *Manager) handlePlan(command protocol.WorkloadCommand, source ArtifactSource) {
	builder := manager.builder
	builder.artifacts.source = source

	plan, err := builder.build(manager.ctx, command)
	if err != nil {
		manager.emit(command.PortalID, planResult(command, "rejected", nil, "invalid_plan", err))
		return
	}
	if err := manager.plans.savePlan(plan); err != nil {
		manager.emit(command.PortalID, planResult(command, "failed", nil, "state_persistence_failed", err))
		return
	}

	manager.emit(command.PortalID, planResult(command, "ready", plan, "", nil))
}

func (manager *Manager) validateOperation(
	command protocol.WorkloadCommand,
) (string, *storedPlan, error) {
	switch command.Type {
	case protocol.WorkloadExecuteRequestType:
		var payload protocol.WorkloadExecutePayload
		if err := protocol.DecodeStrict(command.Payload, &payload); err != nil {
			return "", nil, err
		}
		plan, err := manager.plans.loadPlan(payload.PlanDigest)
		if err != nil {
			return "", nil, err
		}
		if plan.PortalID != command.PortalID || plan.NodeID != command.NodeID ||
			plan.WorkloadID != command.WorkloadID {
			return "", nil, errors.New("plan does not belong to the current portal, node, and workload")
		}
		if err := validateApprovals(plan.Findings, payload.Approvals); err != nil {
			return "", nil, err
		}

		return "execute", plan, nil
	case protocol.WorkloadStopRequestType, protocol.WorkloadRestartRequestType:
		var payload protocol.WorkloadStopPayload
		if err := protocol.DecodeStrict(command.Payload, &payload); err != nil {
			return "", nil, err
		}
		if payload.TimeoutSeconds < 1 || payload.TimeoutSeconds > 300 {
			return "", nil, errors.New("timeout_seconds must be between 1 and 300")
		}
		if command.Type == protocol.WorkloadStopRequestType {
			return "stop", nil, nil
		}

		return "restart", nil, nil
	case protocol.WorkloadDeleteRequestType:
		var payload protocol.WorkloadDeletePayload
		if err := protocol.DecodeStrict(command.Payload, &payload); err != nil {
			return "", nil, err
		}
		if payload.DataPolicy != protocol.WorkloadDataPolicyPreserve {
			return "", nil, errors.New("destructive data deletion requires a separate approved contract")
		}

		return "delete", nil, nil
	default:
		return "", nil, errors.New("unsupported workload operation")
	}
}

func (manager *Manager) replayOrReject(command protocol.WorkloadCommand, commandDigest string) bool {
	result, err := manager.plans.loadResult(command.RequestID)
	if err == nil {
		if result.CommandDigest == commandDigest {
			manager.emit(command.PortalID, result.Result)
		} else {
			manager.emit(command.PortalID, operationResult(command, "rejected", "request_conflict", errors.New("request_id was already used")))
		}
		return true
	}
	if !errors.Is(err, os.ErrNotExist) {
		manager.emit(command.PortalID, operationResult(command, "unknown", "state_read_failed", err))
		return true
	}

	started, err := manager.plans.loadStarted(command.RequestID)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		manager.emit(command.PortalID, operationResult(command, "unknown", "state_read_failed", err))
		return true
	}
	if started.CommandDigest != commandDigest {
		manager.emit(command.PortalID, operationResult(command, "rejected", "request_conflict", errors.New("request_id was already used")))
	} else {
		manager.emit(command.PortalID, operationResult(
			command,
			"unknown",
			"operation_outcome_unknown",
			errors.New("the agent restarted after beginning this operation; inspect runtime state before retrying"),
		))
	}

	return true
}

func (manager *Manager) finish(
	command protocol.WorkloadCommand,
	commandDigest string,
	state string,
	code string,
	err error,
) {
	result := operationResult(command, state, code, err)
	if saveErr := manager.plans.saveResult(commandDigest, result); saveErr != nil {
		result = operationResult(command, "unknown", "result_persistence_failed", saveErr)
	}

	manager.emit(command.PortalID, result)
}

func (manager *Manager) emit(controller string, message any) {
	select {
	case manager.resultQueue(controller) <- message:
	default:
	}
}

func planResult(
	command protocol.WorkloadCommand,
	state string,
	plan *storedPlan,
	code string,
	err error,
) protocol.WorkloadPlanResult {
	payload := protocol.WorkloadPlanResultPayload{
		State:    state,
		Steps:    []protocol.WorkloadPlanStep{},
		Findings: []protocol.WorkloadFinding{},
		Code:     code,
	}
	if plan != nil {
		payload.PlanDigest = plan.PlanDigest
		payload.Steps = plan.Steps
		payload.Findings = plan.Findings
	}
	if err != nil {
		payload.Message = boundedError(err)
	}

	return protocol.WorkloadPlanResult{
		Type:          protocol.WorkloadPlanResultType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload:       payload,
	}
}

func operationResult(
	command protocol.WorkloadCommand,
	state string,
	code string,
	err error,
) protocol.WorkloadOperationResult {
	payload := protocol.WorkloadOperationResultPayload{State: state, Code: code}
	if err != nil {
		payload.Message = boundedError(err)
	}

	return protocol.WorkloadOperationResult{
		Type:          protocol.WorkloadOperationResultType,
		SchemaVersion: protocol.WorkloadSchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		OccurredAt:    time.Now().UTC(),
		Payload:       payload,
	}
}

func validateApprovals(findings []protocol.WorkloadFinding, approvals []string) error {
	expected := make(map[string]struct{})
	for _, finding := range findings {
		if finding.RequiresApproval {
			expected[finding.FindingDigest] = struct{}{}
		}
	}
	actual := make(map[string]struct{}, len(approvals))
	for _, approval := range approvals {
		if _, duplicate := actual[approval]; duplicate {
			return errors.New("approvals contain a duplicate finding digest")
		}
		if _, known := expected[approval]; !known {
			return errors.New("approval does not match a finding in the stored plan")
		}
		actual[approval] = struct{}{}
	}
	if len(actual) != len(expected) {
		return errors.New("not all required plan findings were approved")
	}

	return nil
}

func operationTimeout(command protocol.WorkloadCommand) int {
	if command.Type == protocol.WorkloadDeleteRequestType {
		return 30
	}

	var payload protocol.WorkloadStopPayload
	if err := json.Unmarshal(command.Payload, &payload); err != nil {
		return 30
	}

	return payload.TimeoutSeconds
}

func commandDigest(command protocol.WorkloadCommand) (string, error) {
	semantic := struct {
		Type          string          `json:"type"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		PortalID      string          `json:"portal_id"`
		NodeID        string          `json:"node_id"`
		WorkloadID    string          `json:"workload_id"`
		Payload       json.RawMessage `json:"payload"`
	}{
		Type:          command.Type,
		SchemaVersion: command.SchemaVersion,
		RequestID:     command.RequestID,
		PortalID:      command.PortalID,
		NodeID:        command.NodeID,
		WorkloadID:    command.WorkloadID,
		Payload:       command.Payload,
	}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return "", fmt.Errorf("encode semantic workload command: %w", err)
	}
	hash := sha256.Sum256(encoded)

	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}

	message := strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || character >= 0x20 {
			return character
		}
		return -1
	}, err.Error())
	message = strings.TrimSpace(message)
	if len(message) > 2048 {
		message = message[:2048]
	}

	return message
}
