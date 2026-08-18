package registry_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/registry"
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

type fakeBackend struct {
	manifest   registry.Manifest
	blob       []byte
	blobDigest string
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
