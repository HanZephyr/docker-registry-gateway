// Package gateway owns the runtime boundary between a stable downstream HTTP
// server and replaceable Provider-routing configuration.
package gateway

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/hjx/docker-registry-gateway/internal/registry"
)

// Switcher delegates each new Registry request to the currently active
// backend. Replacing it never mutates the backend captured by an in-flight
// Blob reader, which makes configuration reload safe for active pulls.
type Switcher struct {
	mu        sync.RWMutex
	backend   registry.Backend
	accepting bool
	active    atomic.Int64
	queued    atomic.Int64
	pullSlots chan struct{}
	maxQueued int
	stopping  chan struct{}
	stopOnce  sync.Once
}

// Options constrains inbound blob streams. Zero values keep the constructor
// backwards compatible for embedded use; production configuration validates
// positive limits before constructing the runtime.
type Options struct {
	MaxConcurrentPulls int
	MaxQueuedPulls     int
}

// New creates a Switcher accepting requests through initial.
func New(initial registry.Backend, options ...Options) *Switcher {
	var configured Options
	if len(options) > 0 {
		configured = options[0]
	}
	switcher := &Switcher{
		backend:   initial,
		accepting: true,
		maxQueued: configured.MaxQueuedPulls,
		stopping:  make(chan struct{}),
	}
	if configured.MaxConcurrentPulls > 0 {
		switcher.pullSlots = make(chan struct{}, configured.MaxConcurrentPulls)
	}
	return switcher
}

// Replace atomically makes backend visible to requests that begin afterwards.
func (switcher *Switcher) Replace(backend registry.Backend) {
	switcher.mu.Lock()
	defer switcher.mu.Unlock()
	switcher.backend = backend
}

// StopAccepting rejects new content requests while already-open blob readers
// are allowed to drain.
func (switcher *Switcher) StopAccepting() {
	switcher.mu.Lock()
	switcher.accepting = false
	switcher.mu.Unlock()
	switcher.stopOnce.Do(func() { close(switcher.stopping) })
}

// ActivePulls reports blob streams currently owned by downstream requests.
func (switcher *Switcher) ActivePulls() int {
	return int(switcher.active.Load())
}

// QueuedPulls reports requests waiting for the configured pull-stream cap.
func (switcher *Switcher) QueuedPulls() int {
	return int(switcher.queued.Load())
}

func (switcher *Switcher) Manifest(ctx context.Context, repository, reference string, accepts []string) (registry.Manifest, error) {
	backend, accepting := switcher.snapshot()
	if !accepting || backend == nil {
		return registry.Manifest{}, registry.ErrUnavailable
	}
	return backend.Manifest(ctx, repository, reference, accepts)
}

func (switcher *Switcher) Blob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	backend, accepting := switcher.snapshot()
	if !accepting || backend == nil {
		return registry.Blob{}, registry.ErrUnavailable
	}
	if err := switcher.acquirePull(ctx); err != nil {
		return registry.Blob{}, err
	}
	if _, accepting = switcher.snapshot(); !accepting {
		switcher.releasePull()
		return registry.Blob{}, registry.ErrUnavailable
	}
	blob, err := backend.Blob(ctx, repository, digest, rangeHeader)
	if err != nil || blob.Reader == nil {
		switcher.releasePull()
		return blob, err
	}
	switcher.active.Add(1)
	blob.Reader = &trackedReadCloser{ReadCloser: blob.Reader, done: func() {
		switcher.active.Add(-1)
		switcher.releasePull()
	}}
	return blob, nil
}

func (switcher *Switcher) acquirePull(ctx context.Context) error {
	if switcher.pullSlots == nil {
		return nil
	}
	select {
	case switcher.pullSlots <- struct{}{}:
		return nil
	default:
	}
	if switcher.maxQueued <= 0 || int(switcher.queued.Add(1)) > switcher.maxQueued {
		if switcher.maxQueued > 0 {
			switcher.queued.Add(-1)
		}
		return registry.ErrUnavailable
	}
	defer switcher.queued.Add(-1)
	select {
	case switcher.pullSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-switcher.stopping:
		return registry.ErrUnavailable
	}
}

func (switcher *Switcher) releasePull() {
	if switcher.pullSlots != nil {
		<-switcher.pullSlots
	}
}

func (switcher *Switcher) snapshot() (registry.Backend, bool) {
	switcher.mu.RLock()
	defer switcher.mu.RUnlock()
	return switcher.backend, switcher.accepting
}

type trackedReadCloser struct {
	io.ReadCloser
	done func()
	once sync.Once
}

func (reader *trackedReadCloser) Close() error {
	err := reader.ReadCloser.Close()
	reader.once.Do(reader.done)
	return err
}
