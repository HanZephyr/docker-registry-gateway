package router_test

import (
	"context"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestHealthRestorePreservesThroughputButResetsFailures(t *testing.T) {
	t.Parallel()

	original := router.NewHealth()
	original.RecordSuccess("provider", 4<<20, time.Second)
	original.RecordFailure("provider")

	restored := router.NewHealth()
	restored.Restore(original.Snapshot())
	snapshot := restored.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot entries = %d, want 1", len(snapshot))
	}
	if snapshot[0].ThroughputBytesPerSecond <= 0 {
		t.Error("restored throughput must remain available")
	}
	if snapshot[0].Failures != 0 {
		t.Errorf("restored failures = %d, want 0", snapshot[0].Failures)
	}
}

func TestHealthProbeSuccessRestoresAuthenticationAndIntegrityStates(t *testing.T) {
	t.Parallel()

	health := router.NewHealth()
	health.RecordAuthenticationFailure("provider")
	health.RecordIntegrityViolation("provider")
	health.RecordProbeSuccess("provider")

	snapshots := health.Snapshot()
	if len(snapshots) != 1 {
		t.Fatalf("snapshot count = %d, want 1", len(snapshots))
	}
	if snapshots[0].AuthenticationInvalid || snapshots[0].IntegrityInvalid {
		t.Errorf("probe-recovered snapshot = %#v, want no persistent exclusion", snapshots[0])
	}
}

func TestHealthRecordsTypedProviderFailures(t *testing.T) {
	t.Parallel()

	health := router.NewHealth()
	health.RecordProviderFailure("rate", registry.NewFailure(registry.FailureRateLimited, time.Minute, nil))
	health.RecordProviderFailure("auth", registry.NewFailure(registry.FailureAuthentication, 0, nil))
	health.RecordProviderFailure("integrity", registry.NewFailure(registry.FailureIntegrity, 0, nil))

	states := map[string]router.HealthSnapshot{}
	for _, snapshot := range health.Snapshot() {
		states[snapshot.Provider] = snapshot
	}
	if states["rate"].RateLimitedUntil.Before(time.Now()) {
		t.Errorf("rate snapshot = %#v, want active cooldown", states["rate"])
	}
	if !states["auth"].AuthenticationInvalid {
		t.Errorf("auth snapshot = %#v, want authentication exclusion", states["auth"])
	}
	if !states["integrity"].IntegrityInvalid {
		t.Errorf("integrity snapshot = %#v, want integrity exclusion", states["integrity"])
	}
}

func TestHealthPrefersProviderWithLowerRecentFirstByteLatency(t *testing.T) {
	t.Parallel()

	health := router.NewHealth()
	health.RecordFirstByte("slow", 400*time.Millisecond)
	health.RecordFirstByte("fast", 20*time.Millisecond)
	var attempts []string
	backend := func(name string) functionBackend {
		return functionBackend{blob: func(context.Context, string, string, string) (registry.Blob, error) {
			attempts = append(attempts, name)
			return registry.Blob{Digest: "sha256:blob", Size: 1, Start: 0, End: 0, Reader: ioNopCloser("x")}, nil
		}}
	}
	gateway := router.New([]router.Source{
		{Name: "slow", PullProvider: true, Backend: backend("slow")},
		{Name: "fast", PullProvider: true, Backend: backend("fast")},
	}, router.Options{Health: health})
	if _, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", ""); err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	if len(attempts) != 1 || attempts[0] != "fast" {
		t.Errorf("attempts = %v, want fast Provider first", attempts)
	}
}
