package router_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/lease"
	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestManifestChoosesMajorityDigestAcrossResolvers(t *testing.T) {
	t.Parallel()
	majority := registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:majority", Content: []byte("majority")}
	var events []router.Event
	gateway := router.New([]router.Source{
		{Name: "one", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: majority}},
		{Name: "two", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: registry.Manifest{MediaType: majority.MediaType, Digest: "sha256:other", Content: []byte("other")}}},
		{Name: "three", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: majority}},
	}, router.Options{TieBreaker: "rendezvous_hash", Salt: []byte("test-salt"), Observer: router.ObserverFunc(func(event router.Event) {
		events = append(events, event)
	})})

	manifest, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if got, want := manifest.Digest, majority.Digest; got != want {
		t.Errorf("digest = %q, want majority %q", got, want)
	}
	if !strings.Contains(manifest.Notice, "resolver conflict") {
		t.Errorf("manifest notice = %q, want conflict notice", manifest.Notice)
	}
	if !containsEventCode(events, "resolver_conflict") || !containsEvent(events, "resolution_selected", "sha256:majority") {
		t.Errorf("events = %#v, want conflict and selected-digest events", events)
	}
}

func containsEventCode(events []router.Event, code string) bool {
	for _, event := range events {
		if event.Code == code {
			return true
		}
	}
	return false
}

func containsEvent(events []router.Event, code, digest string) bool {
	for _, event := range events {
		if event.Code == code && event.Digest == digest {
			return true
		}
	}
	return false
}

func TestManifestUsesLowestConfiguredResolverPriority(t *testing.T) {
	t.Parallel()
	preferredPriority := 10
	fallbackPriority := 20
	gateway := router.New([]router.Source{
		{Name: "fallback", Resolver: true, PullProvider: true, Priority: &fallbackPriority, Backend: fakeBackend{manifest: registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:fallback", Content: []byte("fallback")}}},
		{Name: "preferred", Resolver: true, PullProvider: true, Priority: &preferredPriority, Backend: fakeBackend{manifest: registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:preferred", Content: []byte("preferred")}}},
	}, router.Options{ConflictStrategy: "provider_priority"})

	manifest, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if got, want := manifest.Digest, "sha256:preferred"; got != want {
		t.Errorf("digest = %q, want the lowest-priority-number resolver result %q", got, want)
	}
}

func TestManifestLeaseKeepsTagOnTheSelectedDigest(t *testing.T) {
	t.Parallel()

	store, err := lease.Open("", time.Now())
	if err != nil {
		t.Fatalf("lease.Open() error = %v", err)
	}
	resolverCalls := 0
	resolvedDigest := "sha256:first"
	resolver := functionBackend{manifest: func(context.Context, string, string, []string) (registry.Manifest, error) {
		resolverCalls++
		return registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: resolvedDigest, Content: []byte(resolvedDigest)}, nil
	}}
	pull := functionBackend{manifest: func(_ context.Context, _ string, reference string, _ []string) (registry.Manifest, error) {
		return registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: reference, Content: []byte(reference)}, nil
	}}
	gateway := router.New([]router.Source{
		{Name: "resolver", Resolver: true, Backend: resolver},
		{Name: "pull", PullProvider: true, Backend: pull},
	}, router.Options{DecisionLease: time.Minute, LeaseStore: store})

	first, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil || first.Digest != "sha256:first" {
		t.Fatalf("first Manifest() = %#v, %v; want first digest", first, err)
	}
	resolvedDigest = "sha256:second"
	second, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil || second.Digest != "sha256:first" {
		t.Fatalf("leased Manifest() = %#v, %v; want first digest", second, err)
	}
	if resolverCalls != 1 {
		t.Errorf("resolver calls = %d, want 1 because the second request uses the lease", resolverCalls)
	}
}

func TestBlobFallsBackToNextPullProvider(t *testing.T) {
	t.Parallel()
	var events []router.Event
	gateway := router.New([]router.Source{
		{Name: "missing", PullProvider: true, Backend: fakeBackend{blobErr: registry.ErrNotFound}},
		{Name: "available", PullProvider: true, Backend: fakeBackend{blob: registry.Blob{Digest: "sha256:blob", Size: 1, Start: 0, End: 0, Reader: ioNopCloser("x")}}},
	}, router.Options{Observer: router.ObserverFunc(func(event router.Event) { events = append(events, event) })})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	if got, want := blob.Digest, "sha256:blob"; got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
	if !containsEventCode(events, "provider_content_not_found") || !containsEvent(events, "blob_source_selected", "sha256:blob") {
		t.Errorf("events = %#v, want missing-provider and selected-source diagnostics", events)
	}
}

func TestBlobPrefersProviderWithBetterRecentThroughput(t *testing.T) {
	t.Parallel()

	tracker := router.NewHealth()
	tracker.RecordSuccess("slow", 1<<20, time.Second)
	tracker.RecordSuccess("fast", 10<<20, time.Second)
	var attempts []string
	backend := func(name string) functionBackend {
		return functionBackend{blob: func(context.Context, string, string, string) (registry.Blob, error) {
			attempts = append(attempts, name)
			return registry.Blob{Digest: "sha256:blob", Size: 1, Start: 0, End: 0, Reader: io.NopCloser(strings.NewReader("x"))}, nil
		}}
	}
	gateway := router.New([]router.Source{
		{Name: "slow", PullProvider: true, Backend: backend("slow")},
		{Name: "fast", PullProvider: true, Backend: backend("fast")},
	}, router.Options{Health: tracker})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	if _, err := io.ReadAll(blob.Reader); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if got, want := strings.Join(attempts, ","), "fast"; got != want {
		t.Errorf("Provider attempts = %q, want %q", got, want)
	}
}

func TestBlobAvoidsRecentlyFailingProvider(t *testing.T) {
	t.Parallel()

	tracker := router.NewHealth()
	tracker.RecordFailure("unreliable")
	var attempts []string
	backend := func(name string) functionBackend {
		return functionBackend{blob: func(context.Context, string, string, string) (registry.Blob, error) {
			attempts = append(attempts, name)
			return registry.Blob{Digest: "sha256:blob", Size: 1, Start: 0, End: 0, Reader: io.NopCloser(strings.NewReader("x"))}, nil
		}}
	}
	gateway := router.New([]router.Source{
		{Name: "unreliable", PullProvider: true, Backend: backend("unreliable")},
		{Name: "stable", PullProvider: true, Backend: backend("stable")},
	}, router.Options{Health: tracker})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	if _, err := io.ReadAll(blob.Reader); err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if got, want := strings.Join(attempts, ","), "stable"; got != want {
		t.Errorf("Provider attempts = %q, want %q", got, want)
	}
}

func TestBlobDownloadsLargeFullRangeInTemporarySegments(t *testing.T) {
	t.Parallel()

	contents := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	temporaryDir := filepath.Join(t.TempDir(), "segments")
	backend := &rangeBackend{contents: contents}
	gateway := router.New([]router.Source{{Name: "range", PullProvider: true, Backend: backend}}, router.Options{
		MaxSegmentsPerBlob: 3,
		MinSegmentSize:     64 << 10,
		TemporaryDir:       temporaryDir,
		TempBudget:         router.NewTempBudget(int64(len(contents)) * 2),
	})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	got, err := io.ReadAll(blob.Reader)
	if err != nil {
		t.Fatalf("read segmented blob: %v", err)
	}
	if err := blob.Reader.Close(); err != nil {
		t.Fatalf("close segmented blob: %v", err)
	}
	if !bytes.Equal(got, contents) {
		t.Fatal("segmented blob contents do not match the source")
	}
	if entries, err := os.ReadDir(temporaryDir); err != nil {
		t.Fatalf("read temporary directory: %v", err)
	} else if len(entries) != 0 {
		t.Errorf("temporary segment entries = %d, want cleanup after read", len(entries))
	}
	if calls := backend.rangeCalls(); len(calls) < 3 || calls[0] != "bytes=0-0" {
		t.Errorf("range calls = %#v, want metadata probe and multiple segments", calls)
	}
}

func TestBlobAbortsWhenSegmentOverlapDisagrees(t *testing.T) {
	t.Parallel()

	contents := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	backend := &rangeBackend{contents: contents, corruptNonZeroRange: true}
	gateway := router.New([]router.Source{{Name: "range", PullProvider: true, Backend: backend}}, router.Options{
		MaxSegmentsPerBlob: 3,
		MinSegmentSize:     64 << 10,
		TemporaryDir:       filepath.Join(t.TempDir(), "segments"),
		TempBudget:         router.NewTempBudget(int64(len(contents)) * 2),
	})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	if _, err := io.ReadAll(blob.Reader); err == nil {
		t.Fatal("read segmented blob error = nil, want overlap verification failure")
	}
	for _, call := range backend.rangeCalls() {
		if call == "" {
			t.Errorf("range calls = %#v, must not silently switch to a potentially different full stream", backend.rangeCalls())
			break
		}
	}
}

func TestBlobStreamsFirstCompletedSegmentBeforeLaterSegmentsFinish(t *testing.T) {
	t.Parallel()

	contents := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	blockLaterSegments := make(chan struct{})
	backend := &rangeBackend{contents: contents, blockNonFirstRange: blockLaterSegments}
	gateway := router.New([]router.Source{{Name: "range", PullProvider: true, Backend: backend}}, router.Options{
		MaxSegmentsPerBlob: 3,
		MinSegmentSize:     64 << 10,
		TemporaryDir:       filepath.Join(t.TempDir(), "segments"),
		TempBudget:         router.NewTempBudget(int64(len(contents)) * 2),
	})
	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()

	firstRead := make(chan error, 1)
	buffer := make([]byte, 1024)
	go func() {
		count, readErr := blob.Reader.Read(buffer)
		if count == 0 && readErr == nil {
			readErr = errors.New("first segment produced no bytes")
		}
		firstRead <- readErr
	}()
	select {
	case readErr := <-firstRead:
		if readErr != nil {
			t.Fatalf("first segment read: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("first segment waited for later segments before yielding bytes")
	}
	close(blockLaterSegments)
}

func TestBlobResumesFromNextRangeProviderAfterInterruptedRead(t *testing.T) {
	t.Parallel()

	const blobDigest = "sha256:blob"
	primary := functionBackend{blob: func(_ context.Context, _ string, _ string, rangeHeader string) (registry.Blob, error) {
		if rangeHeader != "" {
			return registry.Blob{}, errors.New("primary must only serve the initial request")
		}
		return registry.Blob{
			Digest: blobDigest,
			Size:   10,
			Start:  0,
			End:    9,
			Reader: &failingReadCloser{remaining: "0123", err: io.ErrUnexpectedEOF},
		}, nil
	}}
	fallback := functionBackend{blob: func(_ context.Context, _ string, _ string, rangeHeader string) (registry.Blob, error) {
		if got, want := rangeHeader, "bytes=4-9"; got != want {
			return registry.Blob{}, errors.New("fallback received an unexpected resume range")
		}
		return registry.Blob{
			Digest: blobDigest,
			Size:   10,
			Start:  4,
			End:    9,
			Reader: io.NopCloser(strings.NewReader("456789")),
		}, nil
	}}
	gateway := router.New([]router.Source{
		{Name: "primary", PullProvider: true, Backend: primary},
		{Name: "fallback", PullProvider: true, Backend: fallback},
	}, router.Options{})

	blob, err := gateway.Blob(context.Background(), "library/nginx", blobDigest, "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	contents, err := io.ReadAll(blob.Reader)
	if err != nil {
		t.Fatalf("read resumed blob: %v", err)
	}
	if got, want := string(contents), "0123456789"; got != want {
		t.Errorf("resumed blob = %q, want %q", got, want)
	}
}

func TestBlobSwitchesAwayFromStalledProviderAndResumesAtExactOffset(t *testing.T) {
	contents := []byte("fast")
	stalled := functionBackend{blob: func(ctx context.Context, _ string, digest, _ string) (registry.Blob, error) {
		return registry.Blob{Digest: digest, Size: int64(len(contents)), Start: 0, End: int64(len(contents) - 1), Reader: &contextBlockingReadCloser{ctx: ctx}}, nil
	}}
	var fallbackRange string
	fallback := functionBackend{blob: func(_ context.Context, _ string, digest, rangeHeader string) (registry.Blob, error) {
		fallbackRange = rangeHeader
		return registry.Blob{Digest: digest, Size: int64(len(contents)), Start: 0, End: int64(len(contents) - 1), Reader: io.NopCloser(bytes.NewReader(contents))}, nil
	}}
	var events []router.Event
	gateway := router.New([]router.Source{
		{Name: "stalled", PullProvider: true, Backend: stalled},
		{Name: "fallback", PullProvider: true, Backend: fallback},
	}, router.Options{StallTimeout: 10 * time.Millisecond, Observer: router.ObserverFunc(func(event router.Event) { events = append(events, event) })})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	got, err := io.ReadAll(blob.Reader)
	if err != nil {
		t.Fatalf("read stalled blob fallback: %v", err)
	}
	if got, want := string(got), string(contents); got != want {
		t.Errorf("blob = %q, want %q", got, want)
	}
	if got, want := fallbackRange, "bytes=0-3"; got != want {
		t.Errorf("fallback range = %q, want %q", got, want)
	}
	if !containsEventCode(events, "blob_source_switched") {
		t.Errorf("events = %#v, want a stalled-source switch event", events)
	}
}

func TestBlobSwitchesToMateriallyFasterKnownProvider(t *testing.T) {
	contents := bytes.Repeat([]byte("x"), 2<<20)
	tracker := router.NewHealth()
	slow := functionBackend{blob: func(_ context.Context, _ string, digest, _ string) (registry.Blob, error) {
		return registry.Blob{Digest: digest, Size: int64(len(contents)), Start: 0, End: int64(len(contents) - 1), Reader: &pacedReadCloser{contents: contents, chunk: 64 << 10, delay: 50 * time.Millisecond}}, nil
	}}
	var fallbackRange string
	fast := functionBackend{blob: func(_ context.Context, _ string, digest, rangeHeader string) (registry.Blob, error) {
		fallbackRange = rangeHeader
		start, end, err := parseTestRange(rangeHeader, int64(len(contents)))
		if err != nil {
			return registry.Blob{}, err
		}
		return registry.Blob{Digest: digest, Size: int64(len(contents)), Start: start, End: end, Reader: io.NopCloser(bytes.NewReader(contents[start : end+1]))}, nil
	}}
	var events []router.Event
	gateway := router.New([]router.Source{
		{Name: "slow", PullProvider: true, Backend: slow},
		{Name: "fast", PullProvider: true, Backend: fast},
	}, router.Options{Health: tracker, Observer: router.ObserverFunc(func(event router.Event) { events = append(events, event) })})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	tracker.RecordSuccess("fast", 100<<20, time.Second)
	got, err := io.ReadAll(blob.Reader)
	if err != nil {
		t.Fatalf("read speed-switched blob: %v", err)
	}
	if !bytes.Equal(got, contents) {
		t.Errorf("downloaded contents differ after speed switch")
	}
	if fallbackRange == "" || fallbackRange == "bytes=0-2097151" {
		t.Errorf("fallback range = %q, want a non-zero exact resume range", fallbackRange)
	}
	if !containsEventCode(events, "blob_source_switched") {
		t.Errorf("events = %#v, want speed-based switch event", events)
	}
}

func TestBlobRestartsAndSkipsWhenNoRangeFallbackFitsBudget(t *testing.T) {
	t.Parallel()

	const blobDigest = "sha256:blob"
	primary := functionBackend{blob: func(_ context.Context, _ string, _ string, rangeHeader string) (registry.Blob, error) {
		if rangeHeader != "" {
			return registry.Blob{}, errors.New("primary must only serve the initial request")
		}
		return registry.Blob{Digest: blobDigest, Size: 10, Start: 0, End: 9, Reader: &failingReadCloser{remaining: "0123", err: io.ErrUnexpectedEOF}}, nil
	}}
	noRangeFallback := functionBackend{blob: func(_ context.Context, _ string, _ string, rangeHeader string) (registry.Blob, error) {
		if rangeHeader != "" {
			return registry.Blob{}, registry.ErrUnavailable
		}
		return registry.Blob{Digest: blobDigest, Size: 10, Start: 0, End: 9, Reader: io.NopCloser(strings.NewReader("0123456789"))}, nil
	}}
	gateway := router.New([]router.Source{
		{Name: "primary", PullProvider: true, Backend: primary},
		{Name: "no-range", PullProvider: true, Backend: noRangeFallback},
	}, router.Options{MaxNoRangeRestartDiscard: 4})

	blob, err := gateway.Blob(context.Background(), "library/nginx", blobDigest, "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	contents, err := io.ReadAll(blob.Reader)
	if err != nil {
		t.Fatalf("read restarted blob: %v", err)
	}
	if got, want := string(contents), "0123456789"; got != want {
		t.Errorf("restarted blob = %q, want %q", got, want)
	}
}

func TestBlobAvoidsRateLimitedProviderAndReturnsRetryHintWhenNoAlternative(t *testing.T) {
	var calls int
	rateLimited := functionBackend{blob: func(context.Context, string, string, string) (registry.Blob, error) {
		calls++
		return registry.Blob{}, registry.NewFailure(registry.FailureRateLimited, time.Minute, nil)
	}}
	gateway := router.New([]router.Source{{Name: "rate-limited", PullProvider: true, Backend: rateLimited}}, router.Options{})

	for attempt := 0; attempt < 2; attempt++ {
		_, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
		if !registry.IsFailureKind(err, registry.FailureRateLimited) {
			t.Fatalf("Blob() attempt %d error = %v, want rate-limited failure", attempt+1, err)
		}
	}
	if got, want := calls, 1; got != want {
		t.Errorf("rate-limited Provider calls = %d, want %d after its cooldown begins", got, want)
	}
}

func TestBlobIsolatesIntegrityViolatingProviderButUsesHealthyFallback(t *testing.T) {
	contents := []byte("healthy")
	var badCalls, goodCalls int
	bad := functionBackend{blob: func(context.Context, string, string, string) (registry.Blob, error) {
		badCalls++
		return registry.Blob{}, registry.NewFailure(registry.FailureIntegrity, 0, nil)
	}}
	good := functionBackend{blob: func(_ context.Context, _ string, expected string, _ string) (registry.Blob, error) {
		goodCalls++
		return registry.Blob{Digest: expected, Size: int64(len(contents)), Start: 0, End: int64(len(contents) - 1), Reader: io.NopCloser(bytes.NewReader(contents))}, nil
	}}
	gateway := router.New([]router.Source{
		{Name: "bad", PullProvider: true, Backend: bad},
		{Name: "good", PullProvider: true, Backend: good},
	}, router.Options{})

	for attempt := 0; attempt < 2; attempt++ {
		blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
		if err != nil {
			t.Fatalf("Blob() attempt %d error = %v", attempt+1, err)
		}
		if err := blob.Reader.Close(); err != nil {
			t.Fatalf("close Blob() attempt %d: %v", attempt+1, err)
		}
	}
	if got, want := badCalls, 1; got != want {
		t.Errorf("integrity-violating Provider calls = %d, want %d", got, want)
	}
	if got, want := goodCalls, 2; got != want {
		t.Errorf("healthy fallback calls = %d, want %d", got, want)
	}
}

type fakeBackend struct {
	manifest registry.Manifest
	blob     registry.Blob
	blobErr  error
}

type functionBackend struct {
	manifest func(context.Context, string, string, []string) (registry.Manifest, error)
	blob     func(context.Context, string, string, string) (registry.Blob, error)
}

func (backend functionBackend) Manifest(ctx context.Context, repository, reference string, accepts []string) (registry.Manifest, error) {
	if backend.manifest == nil {
		return registry.Manifest{}, registry.ErrNotFound
	}
	return backend.manifest(ctx, repository, reference, accepts)
}

func (backend functionBackend) Blob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	if backend.blob == nil {
		return registry.Blob{}, registry.ErrNotFound
	}
	return backend.blob(ctx, repository, digest, rangeHeader)
}

func (backend fakeBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	if backend.manifest.Digest == "" {
		return registry.Manifest{}, registry.ErrNotFound
	}
	return backend.manifest, nil
}

func (backend fakeBackend) Blob(context.Context, string, string, string) (registry.Blob, error) {
	if backend.blobErr != nil {
		return registry.Blob{}, backend.blobErr
	}
	return backend.blob, nil
}

type stringReadCloser struct{ content string }

func ioNopCloser(content string) *stringReadCloser { return &stringReadCloser{content: content} }

func (reader *stringReadCloser) Read(buffer []byte) (int, error) {
	if reader.content == "" {
		return 0, io.EOF
	}
	count := copy(buffer, reader.content)
	reader.content = reader.content[count:]
	return count, nil
}

func (*stringReadCloser) Close() error { return nil }

type failingReadCloser struct {
	remaining string
	err       error
}

func (reader *failingReadCloser) Read(buffer []byte) (int, error) {
	if reader.remaining != "" {
		count := copy(buffer, reader.remaining)
		reader.remaining = reader.remaining[count:]
		return count, nil
	}
	return 0, reader.err
}

func (*failingReadCloser) Close() error { return nil }

type contextBlockingReadCloser struct{ ctx context.Context }

func (reader *contextBlockingReadCloser) Read([]byte) (int, error) {
	<-reader.ctx.Done()
	return 0, reader.ctx.Err()
}

func (*contextBlockingReadCloser) Close() error { return nil }

type pacedReadCloser struct {
	contents []byte
	chunk    int
	delay    time.Duration
}

func (reader *pacedReadCloser) Read(buffer []byte) (int, error) {
	if len(reader.contents) == 0 {
		return 0, io.EOF
	}
	time.Sleep(reader.delay)
	count := len(buffer)
	if count > reader.chunk {
		count = reader.chunk
	}
	if count > len(reader.contents) {
		count = len(reader.contents)
	}
	copy(buffer[:count], reader.contents[:count])
	reader.contents = reader.contents[count:]
	return count, nil
}

func (*pacedReadCloser) Close() error { return nil }

type rangeBackend struct {
	mu                  sync.Mutex
	contents            []byte
	calls               []string
	corruptNonZeroRange bool
	blockNonFirstRange  <-chan struct{}
}

func (*rangeBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	return registry.Manifest{}, registry.ErrNotFound
}

func (backend *rangeBackend) Blob(ctx context.Context, _ string, digest, rangeHeader string) (registry.Blob, error) {
	backend.mu.Lock()
	backend.calls = append(backend.calls, rangeHeader)
	backend.mu.Unlock()
	start, end, err := parseTestRange(rangeHeader, int64(len(backend.contents)))
	if err != nil {
		return registry.Blob{}, err
	}
	if backend.blockNonFirstRange != nil && rangeHeader != "" && start > 0 {
		select {
		case <-backend.blockNonFirstRange:
		case <-ctx.Done():
			return registry.Blob{}, ctx.Err()
		}
	}
	responseContents := append([]byte(nil), backend.contents[start:end+1]...)
	if backend.corruptNonZeroRange && rangeHeader != "" && start > 0 && len(responseContents) > 0 {
		responseContents[0] ^= 0xff
	}
	return registry.Blob{
		Digest: digest,
		Size:   int64(len(backend.contents)),
		Start:  start,
		End:    end,
		Reader: io.NopCloser(bytes.NewReader(responseContents)),
	}, nil
}

func (backend *rangeBackend) rangeCalls() []string {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]string(nil), backend.calls...)
}

func parseTestRange(header string, size int64) (int64, int64, error) {
	if header == "" {
		return 0, size - 1, nil
	}
	value := strings.TrimPrefix(header, "bytes=")
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid test range")
	}
	start, startErr := strconv.ParseInt(parts[0], 10, 64)
	end, endErr := strconv.ParseInt(parts[1], 10, 64)
	if startErr != nil || endErr != nil || start < 0 || end < start || end >= size {
		return 0, 0, errors.New("invalid test range")
	}
	return start, end, nil
}
