package router_test

import (
	"testing"
	"time"

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
