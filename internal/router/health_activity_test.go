package router_test

import (
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestHealthRecordsOnlyRealPullActivity(t *testing.T) {
	t.Parallel()

	health := router.NewHealth()
	if health.HasRecentPullActivity(time.Minute) {
		t.Fatal("empty health tracker reported recent pull activity")
	}
	health.RecordPullActivity()
	if !health.HasRecentPullActivity(time.Minute) {
		t.Fatal("real pull activity was not retained for probe scheduling")
	}
}
