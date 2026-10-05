package metrics

import (
	"context"
	"sync"
	"time"
)

// Sample is one collected interval, or the error that replaced it.
type Sample struct {
	Snapshot Snapshot
	Err      error
}

// Stream shares one collector between subscribers. A Collector measures
// rates against its previous call, so independent callers would shorten
// each other's intervals; Stream collects once per interval and hands every
// subscriber the same sample.
type Stream struct {
	collect  func(context.Context) (Snapshot, error)
	interval time.Duration
	timeout  time.Duration

	mu          sync.Mutex
	subscribers map[chan Sample]struct{}
}

// NewStream creates a stream. Run must be called for samples to flow.
func NewStream(collect func(context.Context) (Snapshot, error), interval, timeout time.Duration) *Stream {
	return &Stream{
		collect:     collect,
		interval:    interval,
		timeout:     timeout,
		subscribers: make(map[chan Sample]struct{}),
	}
}

// Run collects once per interval until ctx is cancelled. While nobody is
// subscribed it still collects, so the first sample after an idle period
// covers one interval instead of the whole idle time.
func (s *Stream) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		collectCtx, cancel := context.WithTimeout(ctx, s.timeout)
		snapshot, err := s.collect(collectCtx)
		cancel()

		s.publish(Sample{Snapshot: snapshot, Err: err})
	}
}

// Subscribe returns samples until ctx is cancelled. A slow subscriber skips
// samples instead of delaying the others: the channel keeps only the newest.
func (s *Stream) Subscribe(ctx context.Context) <-chan Sample {
	samples := make(chan Sample, 1)

	s.mu.Lock()
	s.subscribers[samples] = struct{}{}
	s.mu.Unlock()

	go func() {
		<-ctx.Done()

		s.mu.Lock()
		delete(s.subscribers, samples)
		s.mu.Unlock()
	}()

	return samples
}

func (s *Stream) publish(sample Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for subscriber := range s.subscribers {
		select {
		case <-subscriber:
		default:
		}

		subscriber <- sample
	}
}
