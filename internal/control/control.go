// Package control provides the local-only maintenance channel used by a
// running DRG process. It deliberately has no remote listener or user model.
package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const infoFileName = "control.json"

// Status is the intentionally compact view exposed to the local CLI.
type Status struct {
	State       string           `json:"state"`
	PID         int              `json:"pid"`
	Listeners   []string         `json:"listeners,omitempty"`
	ActivePulls int              `json:"active_pulls"`
	Providers   []ProviderHealth `json:"providers,omitempty"`
}

// ProviderHealth is the non-secret, local diagnostic view of one Provider.
type ProviderHealth struct {
	Name                     string    `json:"name"`
	ThroughputBytesPerSecond float64   `json:"throughput_bytes_per_second"`
	Failures                 int       `json:"failures"`
	LastSuccess              time.Time `json:"last_success,omitempty"`
	LastFailure              time.Time `json:"last_failure,omitempty"`
}

// Callbacks bind command handling to a running Gateway instance.
type Callbacks struct {
	Status func() Status
	Reload func(context.Context) error
	Stop   func(context.Context, bool) error
}

// Info is stored in the private data directory so another local drg command
// can find and authenticate to the running process. Token must never be
// printed, logged, or sent outside the loopback connection.
type Info struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
}

// Server owns a local authenticated HTTP control endpoint.
type Server struct {
	dataDir  string
	infoPath string
	token    string
	listener net.Listener
	http     *http.Server
	once     sync.Once
}

// Start creates a loopback-only endpoint and atomically publishes its private
// discovery file. On Windows, the data-directory ACL is the protection
// boundary; on other platforms the file is also created with mode 0600.
func Start(dataDir string, callbacks Callbacks) (*Server, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("control data directory is required")
	}
	if callbacks.Status == nil || callbacks.Reload == nil || callbacks.Stop == nil {
		return nil, errors.New("all control callbacks are required")
	}
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve control data directory: %w", err)
	}
	if err := os.MkdirAll(absDataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create control data directory: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local control: %w", err)
	}
	token, err := randomToken()
	if err != nil {
		listener.Close()
		return nil, err
	}

	server := &Server{
		dataDir:  absDataDir,
		infoPath: filepath.Join(absDataDir, infoFileName),
		token:    token,
		listener: listener,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", server.authorized(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(response)
			return
		}
		status := callbacks.Status()
		status.PID = os.Getpid()
		writeJSON(response, http.StatusOK, status)
	}))
	mux.HandleFunc("/v1/reload", server.authorized(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(response)
			return
		}
		if err := callbacks.Reload(request.Context()); err != nil {
			writeJSON(response, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(response, http.StatusOK, map[string]string{"state": "reloaded"})
	}))
	mux.HandleFunc("/v1/stop", server.authorized(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(response)
			return
		}
		force := request.URL.Query().Get("force") == "true"
		writeJSON(response, http.StatusOK, map[string]any{"state": "stopping", "force": force})
		// Respond before triggering data-plane shutdown. Otherwise the serving
		// loop could close this control connection before the CLI learns that
		// its stop request was accepted.
		go func() { _ = callbacks.Stop(context.Background(), force) }()
	}))
	server.http = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := writeInfo(server.infoPath, Info{Address: listener.Addr().String(), Token: token, PID: os.Getpid()}); err != nil {
		listener.Close()
		return nil, err
	}
	go func() { _ = server.http.Serve(listener) }()
	return server, nil
}

// DataDir returns the canonical directory containing this Server's discovery
// file. It is useful for command tests and never reveals the token.
func (server *Server) DataDir() string { return server.dataDir }

// Close stops the endpoint and removes only the discovery file it created.
func (server *Server) Close() error {
	var result error
	server.once.Do(func() {
		result = server.http.Close()
		if err := removeOwnedInfo(server.infoPath, server.token); err != nil && !errors.Is(err, os.ErrNotExist) && result == nil {
			result = err
		}
	})
	return result
}

// LoadInfo reads local control discovery material. Callers must not print the
// returned Token.
func LoadInfo(dataDir string) (Info, error) {
	contents, err := os.ReadFile(filepath.Join(dataDir, infoFileName))
	if err != nil {
		return Info{}, fmt.Errorf("read control discovery: %w", err)
	}
	var info Info
	if err := json.Unmarshal(contents, &info); err != nil {
		return Info{}, fmt.Errorf("decode control discovery: %w", err)
	}
	if info.Address == "" || info.Token == "" {
		return Info{}, errors.New("control discovery is incomplete")
	}
	return info, nil
}

// StatusRequest asks a running Gateway for its status over the local channel.
func StatusRequest(ctx context.Context, dataDir string) (Status, error) {
	var status Status
	if err := request(ctx, dataDir, http.MethodGet, "/v1/status", &status); err != nil {
		return Status{}, err
	}
	return status, nil
}

// ReloadRequest asks a running Gateway to validate and atomically adopt a new
// runtime configuration for new requests.
func ReloadRequest(ctx context.Context, dataDir string) error {
	return request(ctx, dataDir, http.MethodPost, "/v1/reload", nil)
}

// StopRequest asks a running Gateway for graceful or forced shutdown.
func StopRequest(ctx context.Context, dataDir string, force bool) error {
	path := "/v1/stop"
	if force {
		path += "?force=true"
	}
	return request(ctx, dataDir, http.MethodPost, path, nil)
}

func (server *Server) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-DRG-Control-Token") != server.token {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "local control authentication failed"})
			return
		}
		next(response, request)
	}
}

func request(ctx context.Context, dataDir, method, path string, output any) error {
	info, err := LoadInfo(dataDir)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+info.Address+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-DRG-Control-Token", info.Token)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request local control: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		contents, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("local control returned %s: %s", response.Status, strings.TrimSpace(string(contents)))
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			return fmt.Errorf("decode local control response: %w", err)
		}
	}
	return nil
}

func writeInfo(path string, info Info) error {
	contents, err := json.Marshal(info)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".drg-control-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func removeOwnedInfo(path, token string) error {
	info, err := LoadInfo(filepath.Dir(path))
	if err != nil || info.Token != token {
		return err
	}
	return os.Remove(path)
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate local control token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeMethodNotAllowed(response http.ResponseWriter) {
	response.Header().Set("Allow", "GET, POST")
	writeJSON(response, http.StatusMethodNotAllowed, map[string]string{"error": "unsupported control method"})
}
