package router_test

import (
	"context"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestRangeUnsupportedProviderIsWithheldUntilProbeSuccess(t *testing.T) {
	t.Parallel()

	health := router.NewHealth()
	health.RecordRangeUnsupported("pull")
	gateway := router.New([]router.Source{{Name: "pull", PullProvider: true, Backend: functionBackend{}}}, router.Options{Health: health})
	if _, err := gateway.Blob(context.Background(), "library/busybox", "sha256:blob", ""); err != registry.ErrUnavailable {
		t.Fatalf("Blob() error = %v, want unavailable while Range support is absent", err)
	}
	health.RecordProbeSuccess("pull")
	if _, err := gateway.Blob(context.Background(), "library/busybox", "sha256:blob", ""); err == registry.ErrUnavailable {
		t.Fatal("Blob() remained unavailable after a successful Range admission probe")
	}
}
