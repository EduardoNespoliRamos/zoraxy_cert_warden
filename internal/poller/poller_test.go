package poller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollerDoesNotOverlapAndStops(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	p := New(time.Millisecond, func(ctx context.Context) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-ctx.Done():
		case <-release:
		}
	})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("poller did not invoke callback")
	}
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("poller did not cancel the active callback")
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent callbacks = %d, want 1", maximum.Load())
	}
}

func TestStopBeforeStart(t *testing.T) {
	p := New(time.Second, func(context.Context) {})
	p.Stop()
}
