package onboard_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
