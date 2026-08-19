package cli

import (
	"io"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/eventlog"
)

func TestServiceLoggerWritesLifecycleRecordsToUnifiedHistory(t *testing.T) {
	log := eventlog.New(t.TempDir(), time.Now)
	logger := newServiceLogger(log, io.Discard)
	logger.log("info", "gateway_ready", "Gateway 已就绪")

	events, err := log.Read(10)
	if err != nil {
		t.Fatalf("read unified logs: %v", err)
	}
	if len(events) != 1 || events[0].Code != "gateway_ready" || events[0].Message != "Gateway 已就绪" {
		t.Fatalf("events = %#v, want one gateway lifecycle record", events)
	}
}
