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
}

// New creates a Switcher accepting requests through initial.
func New(initial registry.Backend) *Switcher {
	return &Switcher{backend: initial, accepting: true}
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
	defer switcher.mu.Unlock()
	switcher.accepting = false
}

// ActivePulls reports blob streams currently owned by downstream requests.
func (switcher *Switcher) ActivePulls() int {
	return int(switcher.active.Load())
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
	blob, err := backend.Blob(ctx, repository, digest, rangeHeader)
	if err != nil || blob.Reader == nil {
		return blob, err
	}
	switcher.active.Add(1)
	blob.Reader = &trackedReadCloser{ReadCloser: blob.Reader, done: func() { switcher.active.Add(-1) }}
	return blob, nil
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
