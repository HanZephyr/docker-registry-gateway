package registry_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/routeguard"
	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestHandlerServesV2ManifestAndRangedBlob(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	blob := []byte("0123456789")
	backend := fakeBackend{
		manifest: registry.Manifest{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    digest(manifest),
			Content:   manifest,
		},
		blob:       blob,
		blobDigest: digest(blob),
	}
	handler := registry.NewHandler(backend)

	t.Run("v2 ping", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if got, want := response.Code, http.StatusOK; got != want {
			t.Fatalf("status = %d, want %d", got, want)
		}
		if got, want := response.Header().Get("Docker-Distribution-API-Version"), "registry/2.0"; got != want {
			t.Errorf("Docker-Distribution-API-Version = %q, want %q", got, want)
		}
	})

	t.Run("manifest get", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/manifests/latest", nil)
		request.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if got, want := response.Code, http.StatusOK; got != want {
			t.Fatalf("status = %d, want %d; body = %s", got, want, response.Body.String())
		}
		if got, want := response.Header().Get("Docker-Content-Digest"), digest(manifest); got != want {
			t.Errorf("Docker-Content-Digest = %q, want %q", got, want)
		}
		if got, want := response.Body.String(), string(manifest); got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})

	t.Run("blob range", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/blobs/"+digest(blob), nil)
		request.Header.Set("Range", "bytes=2-5")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if got, want := response.Code, http.StatusPartialContent; got != want {
			t.Fatalf("status = %d, want %d; body = %s", got, want, response.Body.String())
		}
		if got, want := response.Header().Get("Content-Range"), "bytes 2-5/10"; got != want {
			t.Errorf("Content-Range = %q, want %q", got, want)
		}
		if got, want := response.Body.String(), "2345"; got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})

	t.Run("manifest head", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodHead, "https://drg.localhost:5443/v2/library/nginx/manifests/latest", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if got, want := response.Code, http.StatusOK; got != want {
			t.Fatalf("status = %d, want %d", got, want)
		}
		if got := response.Body.Len(); got != 0 {
			t.Errorf("HEAD body length = %d, want 0", got)
		}
	})
}

func TestHandlerAbortsFullBlobResponseWhenDigestDoesNotMatch(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		blob:       []byte("corrupted bytes"),
		blobDigest: digest([]byte("expected bytes")),
	}
	handler := registry.NewHandler(backend)
	request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/blobs/"+backend.blobDigest, nil)
	response := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("panic = %v, want http.ErrAbortHandler", recovered)
		}
	}()
	handler.ServeHTTP(response, request)
}

func TestHandlerUsesMetadataProbeForUnrangedBlobHead(t *testing.T) {
	t.Parallel()

	blob := bytes.Repeat([]byte("x"), 128)
	backend := &rangeRecordingBackend{blob: blob, blobDigest: digest(blob)}
	handler := registry.NewHandler(backend)
	request := httptest.NewRequest(http.MethodHead, "https://drg.localhost:5443/v2/library/nginx/blobs/"+backend.blobDigest, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := response.Header().Get("Content-Length"), "128"; got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
	if got := response.Header().Get("Content-Range"); got != "" {
		t.Errorf("Content-Range = %q, want no downstream range response", got)
	}
	if got := response.Body.Len(); got != 0 {
		t.Errorf("HEAD body length = %d, want 0", got)
	}
	if got, want := backend.rangeCalls(), []string{"bytes=0-0"}; !slices.Equal(got, want) {
		t.Errorf("backend ranges = %q, want %q", got, want)
	}
}

func TestHandlerHeadDoesNotStartSegmentedDownload(t *testing.T) {
	t.Parallel()

	blob := bytes.Repeat([]byte("x"), 256<<10)
	backend := &rangeRecordingBackend{blob: blob, blobDigest: digest(blob)}
	var events []router.Event
	var eventsMu sync.Mutex
	routed := router.New([]router.Source{{Name: "range", PullProvider: true, Backend: backend}}, router.Options{
		MaxSegmentsPerBlob: 3,
		MinSegmentSize:     64 << 10,
		TemporaryDir:       filepath.Join(t.TempDir(), "segments"),
		TempBudget:         router.NewTempBudget(int64(len(blob)) * 2),
		Observer: router.ObserverFunc(func(event router.Event) {
			eventsMu.Lock()
			defer eventsMu.Unlock()
			events = append(events, event)
		}),
	})
	handler := registry.NewHandler(routed)
	request := httptest.NewRequest(http.MethodHead, "https://drg.localhost:5443/v2/library/nginx/blobs/"+backend.blobDigest, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if containsRouterEvent(events, "segmented_download_started") {
		t.Errorf("events = %#v, want no segmented download for HEAD", events)
	}
}

func TestHandlerRejectsGatewayRouteThatReturnsToThisInstance(t *testing.T) {
	backend := &countingBackend{}
	var events []registry.HandlerEvent
	handler := registry.NewHandlerWithOptions(backend, registry.HandlerOptions{
		RouteGuard: routeguard.New("gateway-a", 3),
		OnEvent: func(event registry.HandlerEvent) {
			events = append(events, event)
		},
	})
	request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/manifests/latest", nil)
	request.Header.Set(routeguard.InstanceHeader, "gateway-a")
	request.Header.Set(routeguard.HopHeader, "1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d; body = %s", got, want, response.Body.String())
	}
	if backend.calls != 0 {
		t.Errorf("backend calls = %d, want no routing after loop rejection", backend.calls)
	}
	if len(events) != 1 || events[0].Code != "routing_loop_detected" {
		t.Errorf("events = %#v, want routing-loop event", events)
	}
}

func TestHandlerReturnsProviderRateLimitToDockerWithRetryHint(t *testing.T) {
	handler := registry.NewHandler(errorBackend{err: registry.NewFailure(registry.FailureRateLimited, 15*time.Second, nil)})
	request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/manifests/latest", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusTooManyRequests; got != want {
		t.Fatalf("status = %d, want %d; body = %s", got, want, response.Body.String())
	}
	if got, want := response.Header().Get("Retry-After"), "15"; got != want {
		t.Errorf("Retry-After = %q, want %q", got, want)
	}
}

func TestHandlerEmitsBestEffortRoutingNoticeAsWarning(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	handler := registry.NewHandler(fakeBackend{manifest: registry.Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    digest(manifest),
		Content:   manifest,
		Notice:    "DRG resolver conflict selected sha256:stable",
	}})
	request := httptest.NewRequest(http.MethodGet, "https://drg.localhost:5443/v2/library/nginx/manifests/latest", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Header().Get("Warning"), `299 drg "DRG resolver conflict selected sha256:stable"`; got != want {
		t.Errorf("Warning = %q, want %q", got, want)
	}
}

type fakeBackend struct {
	manifest   registry.Manifest
	blob       []byte
	blobDigest string
}

type countingBackend struct{ calls int }

func (backend *countingBackend) Manifest(_ context.Context, _, _ string, _ []string) (registry.Manifest, error) {
	backend.calls++
	return registry.Manifest{}, registry.ErrUnavailable
}

func (backend *countingBackend) Blob(_ context.Context, _, _, _ string) (registry.Blob, error) {
	backend.calls++
	return registry.Blob{}, registry.ErrUnavailable
}

type errorBackend struct{ err error }

type rangeRecordingBackend struct {
	blob       []byte
	blobDigest string
	mu         sync.Mutex
	calls      []string
}

func (backend *rangeRecordingBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	return registry.Manifest{}, registry.ErrNotFound
}

func (backend *rangeRecordingBackend) Blob(_ context.Context, repository, requestedDigest, rangeHeader string) (registry.Blob, error) {
	if repository != "library/nginx" || requestedDigest != backend.blobDigest {
		return registry.Blob{}, registry.ErrNotFound
	}
	backend.mu.Lock()
	backend.calls = append(backend.calls, rangeHeader)
	backend.mu.Unlock()
	end := int64(len(backend.blob) - 1)
	if rangeHeader != "" {
		var start int64
		if _, err := fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= int64(len(backend.blob)) {
			return registry.Blob{}, registry.ErrNotFound
		}
		return registry.Blob{
			Digest: backend.blobDigest,
			Size:   int64(len(backend.blob)),
			Start:  start,
			End:    end,
			Reader: io.NopCloser(bytes.NewReader(backend.blob[start : end+1])),
		}, nil
	}
	return registry.Blob{
		Digest: backend.blobDigest,
		Size:   int64(len(backend.blob)),
		Start:  0,
		End:    end,
		Reader: io.NopCloser(bytes.NewReader(backend.blob[:end+1])),
	}, nil
}

func (backend *rangeRecordingBackend) rangeCalls() []string {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]string(nil), backend.calls...)
}

func containsRouterEvent(events []router.Event, code string) bool {
	for _, event := range events {
		if event.Code == code {
			return true
		}
	}
	return false
}

func (backend errorBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	return registry.Manifest{}, backend.err
}

func (backend errorBackend) Blob(context.Context, string, string, string) (registry.Blob, error) {
	return registry.Blob{}, backend.err
}

func (backend fakeBackend) Manifest(_ context.Context, repository, reference string, _ []string) (registry.Manifest, error) {
	if repository != "library/nginx" || reference != "latest" {
		return registry.Manifest{}, registry.ErrNotFound
	}
	return backend.manifest, nil
}

func (backend fakeBackend) Blob(_ context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	if repository != "library/nginx" || digest != backend.blobDigest {
		return registry.Blob{}, registry.ErrNotFound
	}
	start, end := int64(0), int64(len(backend.blob)-1)
	if rangeHeader != "" {
		if rangeHeader != "bytes=2-5" {
			return registry.Blob{}, registry.ErrNotFound
		}
		start, end = 2, 5
	}
	return registry.Blob{
		Digest: backend.blobDigest,
		Size:   int64(len(backend.blob)),
		Start:  start,
		End:    end,
		Reader: io.NopCloser(bytes.NewReader(backend.blob[start : end+1])),
	}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", sum)
}
