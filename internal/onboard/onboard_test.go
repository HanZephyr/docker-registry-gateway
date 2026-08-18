package onboard_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/config"
	"github.com/hjx/docker-registry-gateway/internal/onboard"
)

func TestRunCreatesANewValidDefaultConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	err := onboard.Run(context.Background(), onboard.Options{
		ConfigPath: configPath,
		Answers: onboard.Answers{
			Listeners:         []string{"127.0.0.1:5443", "[::1]:5443"},
			AdvertiseEndpoint: "drg.localhost:5443",
		},
	})
	if err != nil {
		t.Fatalf("onboard.Run() error = %v", err)
	}

	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated configuration: %v", err)
	}

	for _, expected := range []string{
		"version: 1",
		"advertise_endpoint: drg.localhost:5443",
		"install_trust: true",
		"- 127.0.0.1:5443",
		"- '[::1]:5443'",
		"url: https://registry-1.docker.io",
		"resolver: true",
		"pull_provider: true",
	} {
		if !strings.Contains(string(contents), expected) {
			t.Errorf("generated configuration does not contain %q:\n%s", expected, contents)
		}
	}
}

func TestRunIncludesChosenProviderAndResourceLimits(t *testing.T) {
	t.Parallel()
	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	if err := onboard.Run(context.Background(), onboard.Options{
		ConfigPath: configPath,
		Answers: onboard.Answers{
			AdvertiseEndpoint: "drg.localhost:5443",
			Providers:         []config.Provider{{Name: "mirror", URL: "https://mirror.example.test", PullProvider: true}},
			Resources:         config.Resources{MaxConcurrentPulls: 2, MaxSegmentsPerBlob: 3, TemporaryDiskQuota: "1GiB", MinSegmentSize: "8MiB", MaxNoRangeRestartDiscard: "32MiB", MaxInflightRequests: 12, MaxQueuedPulls: 6},
		},
	}); err != nil {
		t.Fatalf("onboard.Run() error = %v", err)
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated configuration: %v", err)
	}
	for _, expected := range []string{"name: mirror", "url: https://mirror.example.test", "max_concurrent_pulls: 2", "temporary_disk_quota: 1GiB"} {
		if !strings.Contains(string(contents), expected) {
			t.Errorf("generated configuration lacks %q:\n%s", expected, contents)
		}
	}
}

func TestRunCanGenerateExternalTLSConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	if err := os.WriteFile(filepath.Join(filepath.Dir(configPath), "gateway.crt"), []byte("certificate"), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(configPath), "gateway.key"), []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := onboard.Run(context.Background(), onboard.Options{
		ConfigPath: configPath,
		Answers: onboard.Answers{
			AdvertiseEndpoint: "drg.example.test:5443",
			TLSMode:           "external",
			CertificateFile:   "gateway.crt",
			PrivateKeyFile:    "gateway.key",
		},
	}); err != nil {
		t.Fatalf("onboard.Run() external TLS error = %v", err)
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated configuration: %v", err)
	}
	for _, expected := range []string{"local_ca: false", "cert_file: gateway.crt", "key_file: gateway.key"} {
		if !strings.Contains(string(contents), expected) {
			t.Errorf("external TLS configuration lacks %q:\n%s", expected, contents)
		}
	}
}

func TestRunRefusesToOverwriteExistingConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	if err := os.WriteFile(configPath, []byte("user-owned\n"), 0o600); err != nil {
		t.Fatalf("create existing configuration: %v", err)
	}

	err := onboard.Run(context.Background(), onboard.Options{
		ConfigPath: configPath,
		Answers:    onboard.Answers{AdvertiseEndpoint: "drg.localhost:5443"},
	})
	if err == nil {
		t.Fatal("onboard.Run() error = nil, want refusal to overwrite existing configuration")
	}

	contents, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read existing configuration: %v", readErr)
	}
	if got, want := string(contents), "user-owned\n"; got != want {
		t.Errorf("existing configuration = %q, want %q", got, want)
	}
}
