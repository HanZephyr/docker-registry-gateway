// Package registry exposes the deliberately small Registry V2 pull surface
// implemented by DRG.
package registry

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/hjx/docker-registry-gateway/internal/routeguard"
)

var (
	// ErrNotFound means the requested repository content does not exist.
	ErrNotFound = errors.New("registry content not found")
	// ErrUnavailable means content may exist but cannot be obtained now.
	ErrUnavailable = errors.New("registry content temporarily unavailable")
)

// Backend obtains already-selected immutable Registry content. It is the seam
// between downstream HTTP handling and Provider routing.
type Backend interface {
	Manifest(context.Context, string, string, []string) (Manifest, error)
	Blob(context.Context, string, string, string) (Blob, error)
}

// Manifest is immutable manifest or index bytes selected by the routing layer.
type Manifest struct {
	MediaType string
	Digest    string
	Content   []byte
}

// Blob is immutable config or layer bytes selected by the routing layer.
type Blob struct {
	Digest string
	Size   int64
	Start  int64
	End    int64
	Reader io.ReadCloser
}

// NewHandler creates the HTTP pull API backed by the supplied routing layer.
func NewHandler(backend Backend) http.Handler {
	return handler{backend: backend}
}

// HandlerOptions configures optional protections around the intentionally
// small downstream Registry pull surface.
type HandlerOptions struct {
	RouteGuard routeguard.Guard
}

// NewHandlerWithOptions creates the HTTP pull API with Gateway-to-Gateway
// routing protection enabled when RouteGuard has an instance identity.
func NewHandlerWithOptions(backend Backend, options HandlerOptions) http.Handler {
	return handler{backend: backend, routeGuard: options.RouteGuard}
}

type handler struct {
	backend    Backend
	routeGuard routeguard.Guard
}

func (value handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	context, err := value.routeGuard.Inbound(request.Context(), request.Header)
	if err != nil {
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "gateway routing loop detected")
		return
	}
	request = request.WithContext(context)
	if request.URL.Path == "/v2" || request.URL.Path == "/v2/" {
		value.servePing(response, request)
		return
	}
	if !strings.HasPrefix(request.URL.Path, "/v2/") {
		writeOCIError(response, http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
		return
	}

	remainder := strings.TrimPrefix(request.URL.Path, "/v2/")
	if index := strings.LastIndex(remainder, "/manifests/"); index > 0 {
		value.serveManifest(response, request, remainder[:index], remainder[index+len("/manifests/"):])
		return
	}
	if index := strings.LastIndex(remainder, "/blobs/"); index > 0 {
		value.serveBlob(response, request, remainder[:index], remainder[index+len("/blobs/"):])
		return
	}
	writeOCIError(response, http.StatusNotFound, "NOT_FOUND", "unknown pull endpoint")
}

func (value handler) servePing(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(response)
		return
	}
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	response.WriteHeader(http.StatusOK)
}

func (value handler) serveManifest(response http.ResponseWriter, request *http.Request, repository, reference string) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(response)
		return
	}
	if repository == "" || reference == "" {
		writeOCIError(response, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest reference is required")
		return
	}

	manifest, err := value.backend.Manifest(request.Context(), repository, reference, acceptableMediaTypes(request.Header.Values("Accept")))
	if err != nil {
		writeBackendError(response, err, "MANIFEST_UNKNOWN")
		return
	}
	if manifest.MediaType == "" || manifest.Digest == "" {
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "routing layer returned incomplete manifest metadata")
		return
	}
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	response.Header().Set("Content-Type", manifest.MediaType)
	response.Header().Set("Docker-Content-Digest", manifest.Digest)
	response.Header().Set("Content-Length", strconv.Itoa(len(manifest.Content)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = response.Write(manifest.Content)
	}
}

func (value handler) serveBlob(response http.ResponseWriter, request *http.Request, repository, digest string) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(response)
		return
	}
	if repository == "" || digest == "" {
		writeOCIError(response, http.StatusNotFound, "BLOB_UNKNOWN", "blob digest is required")
		return
	}

	blob, err := value.backend.Blob(request.Context(), repository, digest, request.Header.Get("Range"))
	if err != nil {
		writeBackendError(response, err, "BLOB_UNKNOWN")
		return
	}
	if blob.Digest == "" || blob.Reader == nil {
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "routing layer returned incomplete blob metadata")
		return
	}
	defer blob.Reader.Close()
	if err := validateBlobRange(blob); err != nil {
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "routing layer returned an invalid blob range")
		return
	}
	contentLength := blob.End - blob.Start + 1
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Docker-Content-Digest", blob.Digest)
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	if request.Header.Get("Range") != "" {
		response.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", blob.Start, blob.End, blob.Size))
		response.WriteHeader(http.StatusPartialContent)
	} else {
		response.WriteHeader(http.StatusOK)
	}
	if request.Method == http.MethodGet {
		if err := streamBlob(response, blob.Reader, blob.Digest, blob.Start == 0 && blob.End == blob.Size-1, contentLength); err != nil {
			// A Registry error body cannot be written after bytes have begun to
			// stream. Abort the response so Docker treats the layer as failed and
			// retries rather than accepting a completed corrupt response.
			panic(http.ErrAbortHandler)
		}
	}
}

func streamBlob(destination io.Writer, source io.Reader, expectedDigest string, verifyDigest bool, length int64) error {
	if !verifyDigest {
		count, err := io.Copy(destination, io.LimitReader(source, length))
		if err != nil {
			return err
		}
		if count != length {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	hasher, algorithm, expectedValue, err := digestHasher(expectedDigest)
	if err != nil {
		return err
	}
	count, err := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(source, length))
	if err != nil {
		return err
	}
	if count != length {
		return io.ErrUnexpectedEOF
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actual, expectedValue) {
		return fmt.Errorf("%s digest mismatch", algorithm)
	}
	return nil
}

func digestHasher(expected string) (hash.Hash, string, string, error) {
	algorithm, value, found := strings.Cut(strings.ToLower(strings.TrimSpace(expected)), ":")
	if !found || value == "" {
		return nil, "", "", errors.New("invalid blob digest")
	}
	switch algorithm {
	case "sha256":
		return sha256.New(), algorithm, value, nil
	case "sha512":
		return sha512.New(), algorithm, value, nil
	default:
		return nil, "", "", fmt.Errorf("unsupported blob digest algorithm %q", algorithm)
	}
}

func validateBlobRange(blob Blob) error {
	if blob.Size <= 0 || blob.Start < 0 || blob.End < blob.Start || blob.End >= blob.Size {
		return errors.New("invalid blob range")
	}
	return nil
}

func acceptableMediaTypes(values []string) []string {
	var result []string
	for _, value := range values {
		for _, mediaType := range strings.Split(value, ",") {
			mediaType = strings.TrimSpace(mediaType)
			if mediaType != "" {
				result = append(result, mediaType)
			}
		}
	}
	return result
}

func parseRange(header string, total int64) (int64, int64, bool, error) {
	if header == "" {
		if total == 0 {
			return 0, -1, false, nil
		}
		return 0, total - 1, false, nil
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") || total <= 0 {
		return 0, 0, false, errors.New("only one satisfiable bytes range is supported")
	}
	value := strings.TrimPrefix(header, "bytes=")
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, false, errors.New("invalid byte range")
	}
	if parts[0] == "" {
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, false, errors.New("invalid suffix byte range")
		}
		if suffix > total {
			suffix = total
		}
		return total - suffix, total - 1, true, nil
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= total {
		return 0, 0, false, errors.New("invalid byte range start")
	}
	if parts[1] == "" {
		return start, total - 1, true, nil
	}
	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || end < start {
		return 0, 0, false, errors.New("invalid byte range end")
	}
	if end >= total {
		end = total - 1
	}
	return start, end, true, nil
}

func writeBackendError(response http.ResponseWriter, err error, notFoundCode string) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeOCIError(response, http.StatusNotFound, notFoundCode, "requested content was not found")
	case errors.Is(err, ErrUnavailable):
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "requested content is temporarily unavailable")
	default:
		writeOCIError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "routing failed")
	}
}

func writeMethodNotAllowed(response http.ResponseWriter) {
	response.Header().Set("Allow", "GET, HEAD")
	writeOCIError(response, http.StatusMethodNotAllowed, "UNSUPPORTED", "only pull methods are supported")
}

func writeOCIError(response http.ResponseWriter, status int, code, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}{Errors: []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{{Code: code, Message: message}}})
}
