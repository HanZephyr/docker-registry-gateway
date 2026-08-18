// Package provider implements direct, authenticated Registry V2 Provider
// requests. It deliberately ignores host proxy environment variables.
package provider

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hjx/docker-registry-gateway/internal/registry"
)

const maxManifestBytes = 10 << 20

// Options configures one upstream Provider client.
type Options struct {
	URL      string
	Username string
	Password string
	CAFile   string
}

// Client is a direct Registry V2 client with short-lived Bearer token reuse.
type Client struct {
	baseURL  *url.URL
	username string
	password string
	http     *http.Client

	mu     sync.Mutex
	tokens map[string]string
}

// ProbeResult summarizes the non-destructive admission check for a Provider.
type ProbeResult struct {
	ManifestDigest string
	BlobDigest     string
	RangeSupported bool
}

// New builds a Provider client without inheriting HTTP_PROXY or HTTPS_PROXY.
func New(options Options) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(strings.TrimSpace(options.URL), "/"))
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, errors.New("provider URL must include scheme and host")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if options.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		contents, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Provider ca_file: %w", err)
		}
		if !roots.AppendCertsFromPEM(contents) {
			return nil, errors.New("Provider ca_file contains no certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			// Object-storage redirects normally carry their own signed URL. Do
			// not leak Registry credentials to their target, even if the target
			// happens to be on the same host.
			request.Header.Del("Authorization")
			return nil
		},
	}
	return &Client{
		baseURL:  baseURL,
		username: options.Username,
		password: options.Password,
		http:     client,
		tokens:   make(map[string]string),
	}, nil
}

// Probe verifies Registry V2 reachability, resolves one configured probe
// image, and tests whether a blob honors a one-byte Range request. It never
// downloads an entire layer.
func (client *Client) Probe(ctx context.Context, reference string) (ProbeResult, error) {
	response, err := client.request(ctx, http.MethodGet, client.registryURL("/v2/"), "", nil)
	if err != nil {
		return ProbeResult{}, err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ProbeResult{}, mapStatus(response.StatusCode)
	}
	repository, tagOrDigest, err := splitProbeReference(reference)
	if err != nil {
		return ProbeResult{}, err
	}
	manifest, err := client.Manifest(ctx, repository, tagOrDigest, probeMediaTypes)
	if err != nil {
		return ProbeResult{}, err
	}
	for depth := 0; depth < 2; depth++ {
		blobDigest, nestedReference, err := probeBlobDigest(manifest.Content)
		if err != nil {
			return ProbeResult{}, err
		}
		if nestedReference != "" {
			manifest, err = client.Manifest(ctx, repository, nestedReference, probeMediaTypes)
			if err != nil {
				return ProbeResult{}, err
			}
			continue
		}
		blob, err := client.Blob(ctx, repository, blobDigest, "bytes=0-0")
		if err != nil {
			if errors.Is(err, registry.ErrUnavailable) {
				return ProbeResult{ManifestDigest: manifest.Digest, BlobDigest: blobDigest, RangeSupported: false}, nil
			}
			return ProbeResult{}, err
		}
		defer blob.Reader.Close()
		if _, err := io.Copy(io.Discard, io.LimitReader(blob.Reader, 1)); err != nil {
			return ProbeResult{}, fmt.Errorf("read probe range: %w", err)
		}
		return ProbeResult{ManifestDigest: manifest.Digest, BlobDigest: blobDigest, RangeSupported: true}, nil
	}
	return ProbeResult{}, errors.New("probe image index nesting exceeds supported depth")
}

var probeMediaTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// Manifest obtains selected manifest or index bytes while preserving upstream
// media-type negotiation.
func (client *Client) Manifest(ctx context.Context, repository, reference string, accepts []string) (registry.Manifest, error) {
	scope := pullScope(repository)
	response, err := client.request(ctx, http.MethodGet, client.registryURL("/v2/"+repository+"/manifests/"+url.PathEscape(reference)), scope, func(request *http.Request) {
		if len(accepts) > 0 {
			request.Header.Set("Accept", strings.Join(accepts, ", "))
		}
	})
	if err != nil {
		return registry.Manifest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return registry.Manifest{}, mapStatus(response.StatusCode)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil {
		return registry.Manifest{}, fmt.Errorf("read upstream manifest: %w", err)
	}
	if len(contents) > maxManifestBytes {
		return registry.Manifest{}, registry.ErrUnavailable
	}
	digest := strings.TrimSpace(response.Header.Get("Docker-Content-Digest"))
	if digest != "" {
		if err := verifyDigest(digest, contents); err != nil {
			return registry.Manifest{}, fmt.Errorf("upstream manifest content digest: %w", err)
		}
	} else {
		digest = sha256Digest(contents)
	}
	if isDigestReference(reference) && !strings.EqualFold(reference, digest) {
		return registry.Manifest{}, fmt.Errorf("upstream manifest digest differs from requested digest: %w", registry.ErrUnavailable)
	}
	return registry.Manifest{
		MediaType: strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]),
		Digest:    digest,
		Content:   contents,
	}, nil
}

// Blob returns a closeable upstream stream. A non-empty rangeHeader is sent to
// the Provider unchanged and must yield a valid 206 Content-Range response.
func (client *Client) Blob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	response, err := client.request(ctx, http.MethodGet, client.registryURL("/v2/"+repository+"/blobs/"+url.PathEscape(digest)), pullScope(repository), func(request *http.Request) {
		if rangeHeader != "" {
			request.Header.Set("Range", rangeHeader)
		}
	})
	if err != nil {
		return registry.Blob{}, err
	}
	if rangeHeader != "" {
		if response.StatusCode != http.StatusPartialContent {
			response.Body.Close()
			return registry.Blob{}, mapStatus(response.StatusCode)
		}
		start, end, size, err := parseContentRange(response.Header.Get("Content-Range"))
		if err != nil {
			response.Body.Close()
			return registry.Blob{}, fmt.Errorf("invalid upstream Content-Range: %w", err)
		}
		responseDigest, err := validateBlobResponseDigest(response, digest)
		if err != nil {
			response.Body.Close()
			return registry.Blob{}, err
		}
		return registry.Blob{Digest: responseDigest, Size: size, Start: start, End: end, Reader: response.Body}, nil
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return registry.Blob{}, mapStatus(response.StatusCode)
	}
	if response.ContentLength < 0 {
		response.Body.Close()
		return registry.Blob{}, errors.New("upstream blob response has no content length")
	}
	if response.ContentLength == 0 {
		response.Body.Close()
		return registry.Blob{}, errors.New("zero-length blobs are not supported")
	}
	responseDigest, err := validateBlobResponseDigest(response, digest)
	if err != nil {
		response.Body.Close()
		return registry.Blob{}, err
	}
	return registry.Blob{
		Digest: responseDigest,
		Size:   response.ContentLength,
		Start:  0,
		End:    response.ContentLength - 1,
		Reader: response.Body,
	}, nil
}

func validateBlobResponseDigest(response *http.Response, requested string) (string, error) {
	declared := responseDigest(response, requested)
	if !strings.EqualFold(declared, requested) {
		return "", fmt.Errorf("upstream blob digest differs from requested digest: %w", registry.ErrUnavailable)
	}
	return requested, nil
}

func (client *Client) request(ctx context.Context, method string, endpoint *url.URL, scope string, mutate func(*http.Request)) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if mutate != nil {
		mutate(request)
	}
	if token := client.token(scope); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request Provider: %w", err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		return response, nil
	}
	challenge := response.Header.Get("WWW-Authenticate")
	response.Body.Close()
	token, err := client.obtainToken(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}
	request, err = http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if mutate != nil {
		mutate(request)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("retry Provider request: %w", err)
	}
	return response, nil
}

func (client *Client) obtainToken(ctx context.Context, challenge, scope string) (string, error) {
	parameters, err := parseBearerChallenge(challenge)
	if err != nil {
		return "", err
	}
	realm, err := url.Parse(parameters["realm"])
	if err != nil || realm.Scheme == "" || realm.Host == "" {
		return "", errors.New("Bearer challenge has invalid realm")
	}
	query := realm.Query()
	if service := parameters["service"]; service != "" {
		query.Set("service", service)
	}
	if scope != "" {
		query.Set("scope", scope)
	}
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept-Encoding", "identity")
	if client.username != "" || client.password != "" {
		request.SetBasicAuth(client.username, client.password)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("request Provider token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", mapStatus(response.StatusCode)
	}
	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode Provider token response: %w", err)
	}
	token := tokenResponse.Token
	if token == "" {
		token = tokenResponse.AccessToken
	}
	if token == "" {
		return "", errors.New("Provider token response contains no token")
	}
	client.mu.Lock()
	client.tokens[scope] = token
	client.mu.Unlock()
	return token, nil
}

func (client *Client) token(scope string) string {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.tokens[scope]
}

func (client *Client) registryURL(path string) *url.URL {
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(client.baseURL.Path, "/") + path
	endpoint.RawPath = ""
	return &endpoint
}

func parseBearerChallenge(value string) (map[string]string, error) {
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return nil, errors.New("unsupported Provider authentication challenge")
	}
	parameters := make(map[string]string)
	for _, part := range strings.Split(strings.TrimSpace(value[len("Bearer "):]), ",") {
		key, rawValue, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			return nil, errors.New("invalid Bearer challenge parameter")
		}
		decoded, err := strconv.Unquote(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, errors.New("invalid quoted Bearer challenge parameter")
		}
		parameters[strings.ToLower(key)] = decoded
	}
	if parameters["realm"] == "" {
		return nil, errors.New("Bearer challenge has no realm")
	}
	return parameters, nil
}

func parseContentRange(value string) (int64, int64, int64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, errors.New("range unit is not bytes")
	}
	rangePart, sizePart, found := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !found {
		return 0, 0, 0, errors.New("range has no total size")
	}
	startPart, endPart, found := strings.Cut(rangePart, "-")
	if !found {
		return 0, 0, 0, errors.New("range has no end")
	}
	start, startErr := strconv.ParseInt(startPart, 10, 64)
	end, endErr := strconv.ParseInt(endPart, 10, 64)
	size, sizeErr := strconv.ParseInt(sizePart, 10, 64)
	if startErr != nil || endErr != nil || sizeErr != nil || start < 0 || end < start || size <= end {
		return 0, 0, 0, errors.New("range values are invalid")
	}
	return start, end, size, nil
}

func responseDigest(response *http.Response, requested string) string {
	if digest := response.Header.Get("Docker-Content-Digest"); digest != "" {
		return digest
	}
	return requested
}

func pullScope(repository string) string {
	return "repository:" + repository + ":pull"
}

func sha256Digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyDigest(expected string, contents []byte) error {
	algorithm, value, found := strings.Cut(strings.ToLower(strings.TrimSpace(expected)), ":")
	if !found || value == "" {
		return fmt.Errorf("invalid digest %q: %w", expected, registry.ErrUnavailable)
	}
	var actual string
	switch algorithm {
	case "sha256":
		actual = sha256Digest(contents)
	case "sha512":
		sum := sha512.Sum512(contents)
		actual = "sha512:" + hex.EncodeToString(sum[:])
	default:
		return fmt.Errorf("unsupported digest algorithm %q: %w", algorithm, registry.ErrUnavailable)
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("digest mismatch: %w", registry.ErrUnavailable)
	}
	return nil
}

func isDigestReference(reference string) bool {
	algorithm, value, found := strings.Cut(strings.TrimSpace(reference), ":")
	return found && algorithm != "" && value != ""
}

func mapStatus(status int) error {
	if status == http.StatusNotFound {
		return registry.ErrNotFound
	}
	return registry.ErrUnavailable
}

func splitProbeReference(reference string) (string, string, error) {
	value := strings.TrimSpace(reference)
	if value == "" {
		return "", "", errors.New("probe reference is required")
	}
	if repository, digest, found := strings.Cut(value, "@"); found {
		if repository == "" || digest == "" {
			return "", "", errors.New("probe digest reference is invalid")
		}
		return repository, digest, nil
	}
	lastSlash := strings.LastIndex(value, "/")
	lastColon := strings.LastIndex(value, ":")
	if lastColon > lastSlash {
		return value[:lastColon], value[lastColon+1:], nil
	}
	return value, "latest", nil
}

func probeBlobDigest(contents []byte) (string, string, error) {
	var document struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		return "", "", fmt.Errorf("decode probe manifest: %w", err)
	}
	if len(document.Manifests) > 0 && document.Manifests[0].Digest != "" {
		return "", document.Manifests[0].Digest, nil
	}
	if document.Config.Digest != "" {
		return document.Config.Digest, "", nil
	}
	if len(document.Layers) > 0 && document.Layers[0].Digest != "" {
		return document.Layers[0].Digest, "", nil
	}
	return "", "", errors.New("probe manifest contains no blob descriptor")
}
