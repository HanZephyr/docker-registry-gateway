package gateway_test

import (
	"bytes"
	"context"
	"io"
	"testing"

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
