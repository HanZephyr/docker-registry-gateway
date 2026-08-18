package provider_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/provider"
)

func TestClientUsesBearerChallengeAndStreamsBlobRange(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{"schemaVersion":2}`)
	blob := []byte("0123456789")
	var tokenRequests int
	authServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		tokenRequests++
		username, password, ok := request.BasicAuth()
		if !ok || username != "robot" || password != "provider-pat" {
			t.Errorf("token credentials = (%q, %q, %t), want (robot, provider-pat, true)", username, password, ok)
		}
		if got, want := request.URL.Query().Get("scope"), "repository:library/nginx:pull"; got != want {
			t.Errorf("token scope = %q, want %q", got, want)
		}
		_ = json.NewEncoder(response).Encode(map[string]string{"token": "provider-token"})
	}))
	defer authServer.Close()

	registryServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("Accept-Encoding"), "identity"; got != want {
			t.Errorf("Accept-Encoding = %q, want %q", got, want)
		}
		if request.Header.Get("Authorization") != "Bearer provider-token" {
			response.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service=%q`, authServer.URL, "test-registry"))
			response.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch request.URL.Path {
		case "/v2/library/nginx/manifests/latest":
			response.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			response.Header().Set("Docker-Content-Digest", digest(manifest))
			_, _ = response.Write(manifest)
		case "/v2/library/nginx/blobs/" + digest(blob):
			if got, want := request.Header.Get("Range"), "bytes=2-5"; got != want {
				t.Errorf("Range = %q, want %q", got, want)
			}
			response.Header().Set("Content-Range", "bytes 2-5/10")
			response.Header().Set("Content-Length", "4")
			response.WriteHeader(http.StatusPartialContent)
			_, _ = response.Write(blob[2:6])
		default:
			http.NotFound(response, request)
		}
	}))
	defer registryServer.Close()

	client, err := provider.New(provider.Options{URL: registryServer.URL, Username: "robot", Password: "provider-pat"})
	if err != nil {
		t.Fatalf("provider.New() error = %v", err)
	}
	resolvedManifest, err := client.Manifest(context.Background(), "library/nginx", "latest", []string{"application/vnd.oci.image.manifest.v1+json"})
	if err != nil {
		t.Fatalf("Manifest() error = %v", err)
	}
	if got, want := string(resolvedManifest.Content), string(manifest); got != want {
		t.Errorf("manifest = %q, want %q", got, want)
	}

	resolvedBlob, err := client.Blob(context.Background(), "library/nginx", digest(blob), "bytes=2-5")
	if err != nil {
		t.Fatalf("Blob() error = %v", err)
	}
	defer resolvedBlob.Reader.Close()
	contents, err := io.ReadAll(resolvedBlob.Reader)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if got, want := string(contents), "2345"; got != want {
		t.Errorf("blob = %q, want %q", got, want)
	}
	if resolvedBlob.Start != 2 || resolvedBlob.End != 5 || resolvedBlob.Size != 10 {
		t.Errorf("blob range = %d-%d/%d, want 2-5/10", resolvedBlob.Start, resolvedBlob.End, resolvedBlob.Size)
	}
	if tokenRequests != 1 {
		t.Errorf("token request count = %d, want 1 (cached across manifest and blob)", tokenRequests)
	}
}

func TestClientRejectsManifestWithMismatchedContentDigest(t *testing.T) {
	t.Parallel()

	manifest := []byte(`{"schemaVersion":2}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		response.Header().Set("Docker-Content-Digest", digest([]byte("different manifest")))
		_, _ = response.Write(manifest)
	}))
	defer server.Close()

	client, err := provider.New(provider.Options{URL: server.URL})
	if err != nil {
		t.Fatalf("provider.New() error = %v", err)
	}
	if _, err := client.Manifest(context.Background(), "library/nginx", "latest", nil); err == nil {
		t.Fatal("Manifest() error = nil, want mismatched content digest rejection")
	}
}

func TestClientRejectsBlobThatDeclaresDifferentDigest(t *testing.T) {
	t.Parallel()

	contents := []byte("expected blob")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Docker-Content-Digest", digest([]byte("another blob")))
		response.Header().Set("Content-Length", fmt.Sprint(len(contents)))
		_, _ = response.Write(contents)
	}))
	defer server.Close()

	client, err := provider.New(provider.Options{URL: server.URL})
	if err != nil {
		t.Fatalf("provider.New() error = %v", err)
	}
	if _, err := client.Blob(context.Background(), "library/nginx", digest(contents), ""); err == nil {
		t.Fatal("Blob() error = nil, want response digest disagreement rejection")
	}
}

func TestClientProbeVerifiesV2ManifestAndBlobRange(t *testing.T) {
	t.Parallel()

	config := []byte("config bytes")
	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"` + digest(config) + `"}}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/":
			response.WriteHeader(http.StatusOK)
		case "/v2/library/busybox/manifests/latest":
			response.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			response.Header().Set("Docker-Content-Digest", digest(manifest))
			_, _ = response.Write(manifest)
		case "/v2/library/busybox/blobs/" + digest(config):
			if got, want := request.Header.Get("Range"), "bytes=0-0"; got != want {
				t.Errorf("probe Range = %q, want %q", got, want)
			}
			response.Header().Set("Docker-Content-Digest", digest(config))
			response.Header().Set("Content-Range", "bytes 0-0/12")
			response.Header().Set("Content-Length", "1")
			response.WriteHeader(http.StatusPartialContent)
			_, _ = response.Write(config[:1])
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := provider.New(provider.Options{URL: server.URL})
	if err != nil {
		t.Fatalf("provider.New() error = %v", err)
	}
	result, err := client.Probe(context.Background(), "library/busybox:latest")
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if !result.RangeSupported || result.ManifestDigest != digest(manifest) || result.BlobDigest != digest(config) {
		t.Errorf("probe result = %#v, want a successful Range-capable admission", result)
	}
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("sha256:%x", sum)
}
