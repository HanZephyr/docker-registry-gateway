package gateway_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/gateway"
	"github.com/hjx/docker-registry-gateway/internal/registry"
)

func TestSwitcherReplacesOnlyNewRequestsAndTracksActiveBlobStreams(t *testing.T) {
	t.Parallel()

	first := fakeBackend{manifest: registry.Manifest{Digest: "sha256:first"}, blob: []byte("first")}
	second := fakeBackend{manifest: registry.Manifest{Digest: "sha256:second"}, blob: []byte("second")}
	switcher := gateway.New(first)

	switcher.Replace(second)
	manifest, err := switcher.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil || manifest.Digest != "sha256:second" {
		t.Fatalf("post-reload manifest = %#v, %v; want second backend", manifest, err)
	}
	blob, err := switcher.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	if got := switcher.ActivePulls(); got != 1 {
		t.Errorf("active pulls = %d, want 1", got)
	}
	if _, err := io.ReadAll(blob.Reader); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if err := blob.Reader.Close(); err != nil {
		t.Fatalf("close blob: %v", err)
	}
	if got := switcher.ActivePulls(); got != 0 {
		t.Errorf("active pulls after close = %d, want 0", got)
	}

	switcher.StopAccepting()
	if _, err := switcher.Manifest(context.Background(), "library/nginx", "latest", nil); err != registry.ErrUnavailable {
		t.Errorf("manifest after stop error = %v, want ErrUnavailable", err)
	}
}

func TestSwitcherLimitsAndQueuesBlobPulls(t *testing.T) {
	t.Parallel()

	switcher := gateway.New(fakeBackend{blob: []byte("x")}, gateway.Options{MaxConcurrentPulls: 1, MaxQueuedPulls: 1})
	first, err := switcher.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("first Blob() error = %v", err)
	}
	defer first.Reader.Close()

	secondDone := make(chan error, 1)
	go func() {
		second, pullErr := switcher.Blob(context.Background(), "library/nginx", "sha256:blob", "")
		if pullErr == nil {
			pullErr = second.Reader.Close()
		}
		secondDone <- pullErr
	}()
	deadline := time.Now().Add(time.Second)
	for switcher.QueuedPulls() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("second pull did not enter the configured queue")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := switcher.Blob(context.Background(), "library/nginx", "sha256:blob", ""); err != registry.ErrUnavailable {
		t.Errorf("third Blob() error = %v, want ErrUnavailable because queue is full", err)
	}
	if err := first.Reader.Close(); err != nil {
		t.Fatalf("close first reader: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("queued Blob() error = %v", err)
	}
}

func TestLimitRequestsRejectsExcessInFlightWork(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	limited := gateway.LimitRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}), 1)
	firstDone := make(chan struct{})
	go func() {
		limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://gateway/v2/", nil))
		close(firstDone)
	}()
	<-started
	second := httptest.NewRecorder()
	limited.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://gateway/v2/", nil))
	if got, want := second.Code, http.StatusServiceUnavailable; got != want {
		t.Errorf("over-capacity status = %d, want %d", got, want)
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
}

type fakeBackend struct {
	manifest registry.Manifest
	blob     []byte
}

func (backend fakeBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	return backend.manifest, nil
}

func (backend fakeBackend) Blob(context.Context, string, string, string) (registry.Blob, error) {
	return registry.Blob{Digest: "sha256:blob", Size: int64(len(backend.blob)), Start: 0, End: int64(len(backend.blob)) - 1, Reader: io.NopCloser(bytes.NewReader(backend.blob))}, nil
}
