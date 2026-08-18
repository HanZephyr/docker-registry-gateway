package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/config"
)

func TestLoadAcceptsMinimumDockerHubConfiguration(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners:
    - 127.0.0.1:5443
    - '[::1]:5443'
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
resolution:
  conflict_strategy: majority
  tie_breaker: rendezvous_hash
  decision_lease: 10m
probe_ref: library/busybox:latest
allow_non_range_providers: true
`))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if got, want := loaded.Providers[0].Name, "docker_hub"; got != want {
		t.Errorf("provider name = %q, want %q", got, want)
	}
	if !loaded.AllowNonRangeProviders {
		t.Error("allow_non_range_providers default = false, want true")
	}
	if !loaded.Server.TLS.InstallTrust {
		t.Error("server.tls.install_trust default = false, want true")
	}
	if got, want := loaded.Resources.MaxNoRangeRestartDiscard, "64MiB"; got != want {
		t.Errorf("max_no_range_restart_discard default = %q, want %q", got, want)
	}
	if got, want := loaded.Retention.EventRetention, "168h"; got != want {
		t.Errorf("event retention default = %q, want %q", got, want)
	}
}

func TestLoadFileResolvesProviderSecretFileAndValidatesPriority(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	secretPath := filepath.Join(directory, "provider.pat")
	if err := os.WriteFile(secretPath, []byte("a-secret-token\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	configPath := filepath.Join(directory, "drg.yaml")
	if err := os.WriteFile(configPath, []byte(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: primary
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
    priority: 10
    auth:
      username: robot
      secret_file: provider.pat
resolution:
  conflict_strategy: provider_priority
  tie_breaker: configured_order
  decision_lease: 10m
probe_ref: library/busybox:latest
allow_non_range_providers: true
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("config.LoadFile() error = %v", err)
	}
	if got, want := loaded.Providers[0].Auth.SecretFile, secretPath; got != want {
		t.Errorf("secret_file = %q, want resolved path %q", got, want)
	}
	username, password, err := loaded.Providers[0].Auth.Credentials()
	if err != nil {
		t.Fatalf("Auth.Credentials() error = %v", err)
	}
	if username != "robot" || password != "a-secret-token" {
		t.Errorf("credentials = (%q, %q), want (robot, a-secret-token)", username, password)
	}
}

func TestSecurityWarningsExposeDeploymentRisksWithoutBlocking(t *testing.T) {
	t.Parallel()
	loaded, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [0.0.0.0:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: insecure
    url: http://mirror.example.test
    allow_insecure_http: true
    resolver: true
    pull_provider: true
    auth:
      username: user
      password: pass
`))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if got := len(loaded.SecurityWarnings()); got != 3 {
		t.Errorf("warning count = %d, want 3", got)
	}
}

func TestLoadRejectsAmbiguousCredentials(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
    auth:
      username: robot
      password: do-not-use-both
      secret_file: provider.pat
resolution:
  conflict_strategy: majority
  tie_breaker: rendezvous_hash
  decision_lease: 10m
probe_ref: library/busybox:latest
allow_non_range_providers: true
`))
	if err == nil || !strings.Contains(err.Error(), "password and secret_file") {
		t.Fatalf("config.Load() error = %v, want password/secret_file conflict", err)
	}
}

func TestLoadRejectsPriorityStrategyWithoutPriorityForEveryResolver(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
resolution:
  conflict_strategy: provider_priority
  tie_breaker: configured_order
  decision_lease: 10m
probe_ref: library/busybox:latest
allow_non_range_providers: true
`))
	if err == nil || !strings.Contains(err.Error(), "priority") {
		t.Fatalf("config.Load() error = %v, want missing priority rejection", err)
	}
}

func TestLoadHonorsDisabledAutomaticTrustInstallation(t *testing.T) {
	t.Parallel()

	loaded, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    install_trust: false
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if loaded.Server.TLS.InstallTrust {
		t.Error("install_trust = true, want explicit false")
	}
}

func TestLoadRejectsConfigurationWithoutResolver(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: false
    pull_provider: true
resolution:
  conflict_strategy: majority
  tie_breaker: rendezvous_hash
`))
	if err == nil {
		t.Fatal("config.Load() error = nil, want missing resolver rejection")
	}
	if !strings.Contains(err.Error(), "at least one resolver") {
		t.Errorf("config.Load() error = %q, want missing resolver detail", err)
	}
}

func TestLoadRejectsProviderThatPointsAtTheGatewayEndpoint(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: loop
    url: https://drg.localhost:5443
    resolver: true
    pull_provider: true
`))
	if err == nil || !strings.Contains(err.Error(), "points at Gateway") {
		t.Fatalf("config.Load() error = %v, want self-route rejection", err)
	}
}

func TestLoadRejectsOverlappingListeners(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [0.0.0.0:5443, 127.0.0.1:5443]
  tls:
    local_ca: true
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`))
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("config.Load() error = %v, want listener overlap rejection", err)
	}
}

func TestLoadFileResolvesExternalTLSCertificateAndKey(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "gateway.crt"), []byte("certificate"), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "gateway.key"), []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	configPath := filepath.Join(directory, "drg.yaml")
	if err := os.WriteFile(configPath, []byte(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: false
    advertise_endpoint: gateway.example.test:5443
    cert_file: gateway.crt
    key_file: gateway.key
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("config.LoadFile() error = %v", err)
	}
	if loaded.Server.TLS.LocalCA {
		t.Error("local_ca = true, want explicit false")
	}
	if got, want := loaded.Server.TLS.CertFile, filepath.Join(directory, "gateway.crt"); got != want {
		t.Errorf("cert_file = %q, want %q", got, want)
	}
	if got, want := loaded.Server.TLS.KeyFile, filepath.Join(directory, "gateway.key"); got != want {
		t.Errorf("key_file = %q, want %q", got, want)
	}
}

func TestLoadRejectsIncompleteExternalTLSConfiguration(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    local_ca: false
    advertise_endpoint: gateway.example.test:5443
    cert_file: gateway.crt
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`))
	if err == nil || !strings.Contains(err.Error(), "cert_file and key_file") {
		t.Fatalf("config.Load() error = %v, want incomplete external TLS rejection", err)
	}
}

func TestLoadRejectsProviderWithoutAnyRole(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    advertise_endpoint: drg.localhost:5443
providers:
  - name: unusable
    url: https://mirror.example.test
    resolver: false
    pull_provider: false
`))
	if err == nil || !strings.Contains(err.Error(), "at least one role") {
		t.Fatalf("config.Load() error = %v, want role rejection", err)
	}
}

func TestLoadRejectsInvalidDiagnosticRetention(t *testing.T) {
	t.Parallel()

	_, err := config.Load(strings.NewReader(`
version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
retention:
  event_retention: never
  event_max_bytes: 0MiB
  health_retention: 0s
`))
	if err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("config.Load() error = %v, want invalid retention rejection", err)
	}
}
