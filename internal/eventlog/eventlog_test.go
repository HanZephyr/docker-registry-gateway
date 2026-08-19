package eventlog

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
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
	if err := log.Write(Event{Level: "warning", Code: "second", Repository: "library/nginx", Reference: "latest", Digest: "sha256:stable", Message: "two"}); err != nil {
		t.Fatalf("write second: %v", err)
	}
	events, err := log.Read(1)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 || events[0].Code != "second" {
		t.Errorf("events = %#v, want newest second", events)
	}
	if got, want := events[0].Repository, "library/nginx"; got != want {
		t.Errorf("repository = %q, want %q", got, want)
	}
}

func TestLogHonorsConfiguredSizeLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	log := New(filepath.Join(t.TempDir(), "data"), func() time.Time { return now }, Options{MaxBytes: 1})
	if err := log.Write(Event{Level: "info", Code: "first", Message: "the first event"}); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := log.Write(Event{Level: "info", Code: "second", Message: "the second event"}); err != nil {
		t.Fatalf("write second: %v", err)
	}

	events, err := log.Read(10)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 || events[0].Code != "second" {
		t.Errorf("events = %#v, want only newest event after size cleanup", events)
	}
}

func TestLogFollowStreamsEventsAcrossDailyRotation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	today := time.Date(2026, time.August, 19, 23, 59, 0, 0, time.UTC)
	initial := New(dataDir, func() time.Time { return today })
	if err := initial.Write(Event{Level: "info", Code: "gateway_started", Message: "Gateway started"}); err != nil {
		t.Fatalf("write initial event: %v", err)
	}

	context, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var observed []Event
	done := make(chan error, 1)
	go func() {
		done <- initial.Follow(context, 10, func(event Event) {
			mu.Lock()
			defer mu.Unlock()
			observed = append(observed, event)
		})
	}()
	waitForEvent(t, &mu, &observed, "gateway_started")

	tomorrow := New(dataDir, func() time.Time { return today.AddDate(0, 0, 1) })
	if err := tomorrow.Write(Event{Level: "info", Code: "blob_source_selected", Message: "Provider selected"}); err != nil {
		t.Fatalf("write next-day event: %v", err)
	}
	waitForEvent(t, &mu, &observed, "blob_source_selected")
	for index := 0; index < 128; index++ {
		if err := tomorrow.Write(Event{Level: "info", Code: fmt.Sprintf("batch_%03d", index), Message: "batch event"}); err != nil {
			t.Fatalf("write batch event %d: %v", index, err)
		}
	}
	waitForEvent(t, &mu, &observed, "batch_127")
	time.Sleep(followInterval * 2)
	duplicate := Event{Time: today.AddDate(0, 0, 1), Level: "info", Code: "duplicate", Message: "same event is still a distinct log entry"}
	if err := tomorrow.Write(duplicate); err != nil {
		t.Fatalf("write first duplicate: %v", err)
	}
	if err := tomorrow.Write(duplicate); err != nil {
		t.Fatalf("write second duplicate: %v", err)
	}
	waitForEventCount(t, &mu, &observed, "duplicate", 2)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follow did not stop after context cancellation")
	}
}

func waitForEventCount(t *testing.T, mu *sync.Mutex, observed *[]Event, code string, wanted int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := 0
		for _, event := range *observed {
			if event.Code == code {
				count++
			}
		}
		mu.Unlock()
		if count >= wanted {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events %q", wanted, code)
}

func waitForEvent(t *testing.T, mu *sync.Mutex, observed *[]Event, code string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		found := false
		for _, event := range *observed {
			if event.Code == code {
				found = true
				break
			}
		}
		mu.Unlock()
		if found {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event %q", code)
}
