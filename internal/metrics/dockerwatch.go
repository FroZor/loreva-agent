package metrics

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

const (
	// listRefreshInterval bounds how long a container list is reused while
	// the event stream runs; events change it in between.
	listRefreshInterval = 5 * time.Minute
	maxPendingEvents    = 256
	eventRetryMin       = 5 * time.Second
	eventRetryMax       = time.Minute
)

// ContainerEvent is a lifecycle change Docker reported for a container.
type ContainerEvent struct {
	At          time.Time
	ContainerID string
	Name        string
	Labels      map[string]string
	// Action is start, restart, die, oom, or health_status.
	Action string
	// ExitCode is set for die.
	ExitCode string
	// Health is healthy or unhealthy for health_status.
	Health string
}

// dockerWatch follows Docker's event stream, so the container list is read
// again only when a container starts, stops, or changes, instead of on
// every sample. Listing is the most expensive Docker call: dockerd spends
// several milliseconds of CPU per container on it.
type dockerWatch struct {
	mu sync.Mutex
	// running is true while the event stream is connected.
	running bool
	stale   bool
	// changed holds containers whose cached inspection is out of date.
	changed map[string]struct{}
	pending []ContainerEvent
}

func newDockerWatch() *dockerWatch {
	return &dockerWatch{stale: true, changed: make(map[string]struct{})}
}

// run follows the event stream until ctx ends, reconnecting with a backoff.
func (watch *dockerWatch) run(ctx context.Context, docker *client.Client) {
	delay := eventRetryMin
	for ctx.Err() == nil {
		connected := watch.follow(ctx, docker)
		if connected {
			delay = eventRetryMin
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, eventRetryMax)
	}
}

// follow reads one connection of the event stream. It reports whether any
// message arrived, so a stream that keeps failing backs off.
func (watch *dockerWatch) follow(ctx context.Context, docker *client.Client) bool {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := docker.Events(streamCtx, client.EventsListOptions{
		Filters: make(client.Filters).Add("type", string(events.ContainerEventType)),
	})

	watch.mu.Lock()
	watch.running = true
	// Events may have been missed while disconnected.
	watch.stale = true
	watch.mu.Unlock()

	defer func() {
		watch.mu.Lock()
		watch.running = false
		watch.stale = true
		watch.mu.Unlock()
	}()

	received := false
	for {
		select {
		case <-streamCtx.Done():
			return received
		case <-result.Err:
			return received
		case message, ok := <-result.Messages:
			if !ok {
				return received
			}
			received = true
			watch.handle(message)
		}
	}
}

func (watch *dockerWatch) handle(message events.Message) {
	action := string(message.Action)
	health := ""
	if name, status, found := strings.Cut(action, ":"); found && name == "health_status" {
		action = name
		health = strings.TrimSpace(status)
	}

	watch.mu.Lock()
	defer watch.mu.Unlock()

	switch action {
	case "start", "restart", "die", "destroy", "rename", "pause", "unpause", "update":
		watch.stale = true
		watch.changed[message.Actor.ID] = struct{}{}
	}

	switch action {
	case "start", "restart", "die", "oom", "health_status":
	default:
		return
	}
	if len(watch.pending) >= maxPendingEvents {
		return
	}

	at := time.Unix(0, message.TimeNano).UTC()
	if message.TimeNano == 0 {
		at = time.Unix(message.Time, 0).UTC()
	}
	attributes := message.Actor.Attributes
	watch.pending = append(watch.pending, ContainerEvent{
		At:          at,
		ContainerID: sanitize(message.Actor.ID, 128),
		Name:        sanitize(attributes["name"], 256),
		Labels:      composeLabels(attributes),
		Action:      action,
		ExitCode:    sanitize(attributes["exitCode"], 16),
		Health:      sanitize(health, 32),
	})
}

// needsList reports whether the container list must be read again, and
// marks it fresh.
func (watch *dockerWatch) needsList(now, listedAt time.Time) bool {
	watch.mu.Lock()
	defer watch.mu.Unlock()

	if !watch.running || watch.stale || now.Sub(listedAt) >= listRefreshInterval {
		watch.stale = false
		return true
	}

	return false
}

// takeChanged returns and forgets the containers whose inspection is stale.
func (watch *dockerWatch) takeChanged() map[string]struct{} {
	watch.mu.Lock()
	defer watch.mu.Unlock()

	changed := watch.changed
	watch.changed = make(map[string]struct{})

	return changed
}

// takeEvents returns and forgets the events seen since the last call.
func (watch *dockerWatch) takeEvents() []ContainerEvent {
	watch.mu.Lock()
	defer watch.mu.Unlock()

	pending := watch.pending
	watch.pending = nil

	return pending
}

// composeLabels keeps the labels that identify a compose service.
func composeLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, 3)
	for _, key := range []string{composeProject, composeService, composeNumber} {
		if value := labels[key]; value != "" {
			result[key] = sanitize(value, 128)
		}
	}

	return result
}

const (
	composeProject = "com.docker.compose.project"
	composeService = "com.docker.compose.service"
	composeNumber  = "com.docker.compose.container-number"
)

// ContainerKey is a container's stable identity: compose:<project>/<service>/<n>
// for a compose service, otherwise name:<name>. A recreated container keeps
// it, so its history continues.
func ContainerKey(name string, labels map[string]string) string {
	project, service := labels[composeProject], labels[composeService]
	if project != "" && service != "" {
		number := labels[composeNumber]
		if number == "" {
			number = "1"
		}

		return "compose:" + project + "/" + service + "/" + number
	}

	return "name:" + strings.TrimPrefix(name, "/")
}
