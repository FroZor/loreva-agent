package metrics

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamSharesEachSampleBetweenSubscribers(t *testing.T) {
	var calls atomic.Int64
	stream := NewStream(func(context.Context) (Snapshot, error) {
		return Snapshot{Interval: time.Duration(calls.Add(1))}, nil
	}, 10*time.Millisecond, time.Second)

	first := stream.Subscribe(t.Context())
	second := stream.Subscribe(t.Context())

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		stream.Run(ctx)
		close(done)
	}()

	if sample := receiveSample(t, first); sample.Err != nil || sample.Snapshot.Interval < 1 {
		t.Fatalf("first subscriber sample = %+v", sample)
	}
	if sample := receiveSample(t, second); sample.Err != nil || sample.Snapshot.Interval < 1 {
		t.Fatalf("second subscriber sample = %+v", sample)
	}

	cancel()
	<-done

	// One collection per tick, however many subscribers there are.
	ticks := calls.Load()
	stream.publish(Sample{Snapshot: Snapshot{Interval: -1}})
	if a, b := receiveSample(t, first), receiveSample(t, second); a.Snapshot.Interval != -1 || b.Snapshot.Interval != -1 {
		t.Fatalf("subscribers got %+v and %+v, want the same published sample", a, b)
	}
	if calls.Load() != ticks {
		t.Fatal("publishing collected again")
	}
}

func TestStreamKeepsOnlyTheNewestSampleForSlowSubscribers(t *testing.T) {
	stream := NewStream(nil, time.Hour, time.Second)
	samples := stream.Subscribe(t.Context())

	stream.publish(Sample{Snapshot: Snapshot{Interval: 1}})
	stream.publish(Sample{Snapshot: Snapshot{Interval: 2}})

	if sample := receiveSample(t, samples); sample.Snapshot.Interval != 2 {
		t.Fatalf("sample = %+v, want the newest", sample)
	}
}

func TestStreamForgetsCancelledSubscribers(t *testing.T) {
	stream := NewStream(nil, time.Hour, time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	stream.Subscribe(ctx)
	cancel()

	deadline := time.Now().Add(time.Second)
	for {
		stream.mu.Lock()
		remaining := len(stream.subscribers)
		stream.mu.Unlock()

		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled subscriber was not removed")
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func receiveSample(t *testing.T, samples <-chan Sample) Sample {
	t.Helper()

	select {
	case sample := <-samples:
		return sample
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a sample")
		return Sample{}
	}
}
