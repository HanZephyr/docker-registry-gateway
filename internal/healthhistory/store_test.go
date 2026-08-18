package healthhistory

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestStoreRoundTripDropsFailureCounters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	store := Open(filepath.Join(t.TempDir(), "provider-health.json"), func() time.Time { return now })
	if err := store.Save([]router.HealthSnapshot{{
		Provider:                 "provider",
		ThroughputBytesPerSecond: 1234,
		Failures:                 3,
		LastSuccess:              now.Add(-time.Minute),
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	snapshots, err := store.Load(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %#v, want one entry", snapshots)
	}
	if snapshots[0].Failures != 0 {
		t.Errorf("persisted failures = %d, want 0", snapshots[0].Failures)
	}
}

func TestStorePrunesExpiredHistory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	store := Open(filepath.Join(t.TempDir(), "provider-health.json"), func() time.Time { return now })
	if err := store.Save([]router.HealthSnapshot{{
		Provider:                 "expired",
		ThroughputBytesPerSecond: 1,
		LastSuccess:              now.Add(-8 * 24 * time.Hour),
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	snapshots, err := store.Load(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(snapshots) != 0 {
		t.Errorf("snapshots = %#v, want expired history removed", snapshots)
	}
}
