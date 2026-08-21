// Package poller provides a cancellable, non-overlapping periodic worker.
package poller

import (
	"context"
	"sync"
	"time"
)

type Poller struct {
	interval time.Duration
	callback func(context.Context)
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
}

func New(interval time.Duration, callback func(context.Context)) *Poller {
	return &Poller{interval: interval, callback: callback, done: make(chan struct{})}
}

func (p *Poller) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go func() {
		defer close(p.done)
		timer := time.NewTimer(p.interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				p.callback(ctx)
				timer.Reset(p.interval)
			}
		}
	}()
	return nil
}

func (p *Poller) Stop() {
	p.once.Do(func() {
		if p.cancel != nil {
			p.cancel()
			<-p.done
		}
	})
}
