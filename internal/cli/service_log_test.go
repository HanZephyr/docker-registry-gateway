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

func TestHTTPServiceErrorWriterRecordsSafeCategoryWithoutRawRequest(t *testing.T) {
	log := eventlog.New(t.TempDir(), time.Now)
	writer := httpServiceErrorWriter{logger: newServiceLogger(log, io.Discard)}
	if _, err := writer.Write([]byte("http: panic serving 127.0.0.1: token=secret")); err != nil {
		t.Fatalf("write HTTP server error: %v", err)
	}

	events, err := log.Read(10)
	if err != nil {
		t.Fatalf("read unified logs: %v", err)
	}
	if len(events) != 1 || events[0].Code != "http_server_error" {
		t.Fatalf("events = %#v, want one safe HTTP server error category", events)
	}
	if events[0].Message == "" || events[0].Message == "http: panic serving 127.0.0.1: token=secret" {
		t.Errorf("HTTP server event message = %q, want safe summary", events[0].Message)
	}
}
