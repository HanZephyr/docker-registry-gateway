package router_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/router"
)

func TestManifestChoosesMajorityDigestAcrossResolvers(t *testing.T) {
	t.Parallel()
	majority := registry.Manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:majority", Content: []byte("majority")}
	gateway := router.New([]router.Source{
		{Name: "one", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: majority}},
		{Name: "two", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: registry.Manifest{MediaType: majority.MediaType, Digest: "sha256:other", Content: []byte("other")}}},
		{Name: "three", Resolver: true, PullProvider: true, Backend: fakeBackend{manifest: majority}},
	}, router.Options{TieBreaker: "rendezvous_hash", Salt: []byte("test-salt")})

	manifest, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if got, want := manifest.Digest, majority.Digest; got != want {
		t.Errorf("digest = %q, want majority %q", got, want)
	}
}

func TestManifestUsesLowestConfiguredResolverPriority(t *testing.T) {
	t.Parallel()
	preferredPriority := 10
	fallbackPriority := 20
	gateway := router.New([]router.Source{
		{Name: "fallback", Resolver: true, Priority: &fallbackPriority, Backend: fakeBackend{manifest: registry.Manifest{Digest: "sha256:fallback", Content: []byte("fallback")}}},
		{Name: "preferred", Resolver: true, Priority: &preferredPriority, Backend: fakeBackend{manifest: registry.Manifest{Digest: "sha256:preferred", Content: []byte("preferred")}}},
	}, router.Options{ConflictStrategy: "provider_priority"})

	manifest, err := gateway.Manifest(context.Background(), "library/nginx", "latest", nil)
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if got, want := manifest.Digest, "sha256:preferred"; got != want {
		t.Errorf("digest = %q, want the lowest-priority-number resolver result %q", got, want)
	}
}

func TestBlobFallsBackToNextPullProvider(t *testing.T) {
	t.Parallel()
	gateway := router.New([]router.Source{
		{Name: "missing", PullProvider: true, Backend: fakeBackend{blobErr: registry.ErrNotFound}},
		{Name: "available", PullProvider: true, Backend: fakeBackend{blob: registry.Blob{Digest: "sha256:blob", Size: 1, Start: 0, End: 0, Reader: ioNopCloser("x")}}},
	}, router.Options{})

	blob, err := gateway.Blob(context.Background(), "library/nginx", "sha256:blob", "")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer blob.Reader.Close()
	if got, want := blob.Digest, "sha256:blob"; got != want {
		t.Errorf("digest = %q, want %q", got, want)
	}
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

type fakeBackend struct {
	manifest registry.Manifest
	blob     registry.Blob
	blobErr  error
}

type functionBackend struct {
	blob func(context.Context, string, string, string) (registry.Blob, error)
}

func (backend functionBackend) Manifest(context.Context, string, string, []string) (registry.Manifest, error) {
	return registry.Manifest{}, registry.ErrNotFound
}

func (backend functionBackend) Blob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
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
