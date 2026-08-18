package eventlog

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLogReadsNewestBoundedEvents(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	log := New(filepath.Join(t.TempDir(), "data"), func() time.Time { return now })
	if err := log.Write(Event{Level: "info", Code: "first", Message: "one"}); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := log.Write(Event{Level: "warning", Code: "second", Message: "two"}); err != nil {
		t.Fatalf("write second: %v", err)
	}
	events, err := log.Read(1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 || events[0].Code != "second" {
		t.Errorf("events = %#v, want newest second", events)
	}
}
