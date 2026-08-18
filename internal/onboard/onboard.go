// Package onboard creates the first DRG configuration without changing Docker
// daemon settings. Interactive prompting is intentionally kept at the CLI
// boundary; this package receives the chosen answers as values.
package onboard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hjx/docker-registry-gateway/internal/config"
)

// Answers contains the deployment choices collected by drg onboard.
type Answers struct {
	Listeners         []string
	AdvertiseEndpoint string
	TLSMode           string
	CertificateFile   string
	PrivateKeyFile    string
	Providers         []config.Provider
	Resources         config.Resources
}

// Options controls an onboarding run.
type Options struct {
	ConfigPath string
	Answers    Answers
}

// Run writes a new default configuration. It never replaces an existing
// configuration file, because that file is user-owned after onboarding.
func Run(ctx context.Context, options Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	configPath := strings.TrimSpace(options.ConfigPath)
	if configPath == "" {
		return errors.New("configuration path is required")
	}

	if _, err := os.Lstat(configPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing configuration %q", configPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect configuration path: %w", err)
	}

	advertiseEndpoint := strings.TrimSpace(options.Answers.AdvertiseEndpoint)
	if advertiseEndpoint == "" {
		return errors.New("advertise endpoint is required")
	}

	listeners := options.Answers.Listeners
	if len(listeners) == 0 {
		listeners = []string{"127.0.0.1:5443", "[::1]:5443"}
	}
	for index, listener := range listeners {
		if strings.TrimSpace(listener) == "" {
			return fmt.Errorf("listener %d is empty", index+1)
		}
	}

	contents, err := defaultConfiguration(advertiseEndpoint, listeners, options.Answers)
	if err != nil {
		return err
	}
	if _, err := config.Load(strings.NewReader(contents)); err != nil {
		return fmt.Errorf("validate generated configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(configPath), ".drg-onboard-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary configuration permissions: %w", err)
	}
	if _, err := temporary.WriteString(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary configuration: %w", err)
	}
	if _, err := config.LoadFile(temporaryPath); err != nil {
		return fmt.Errorf("validate generated configuration files: %w", err)
	}
	if err := os.Rename(temporaryPath, configPath); err != nil {
		return fmt.Errorf("activate configuration: %w", err)
	}
	return nil
}

func defaultConfiguration(advertiseEndpoint string, listeners []string, answers Answers) (string, error) {
	tlsMode := strings.TrimSpace(answers.TLSMode)
	if tlsMode == "" {
		tlsMode = "local_ca"
	}
	if tlsMode != "local_ca" && tlsMode != "external" && tlsMode != "http" {
		return "", fmt.Errorf("unsupported TLS mode %q", tlsMode)
	}
	var builder strings.Builder
	builder.WriteString("# Docker Registry Gateway configuration\n")
	builder.WriteString("version: 1\n\n")
	builder.WriteString("data_dir: .drg\n\n")
	builder.WriteString("server:\n")
	builder.WriteString("  listeners:\n")
	for _, listener := range listeners {
		builder.WriteString("    - ")
		builder.WriteString(yamlScalar(listener))
		builder.WriteByte('\n')
	}
	builder.WriteString("  tls:\n")
	if tlsMode == "local_ca" {
		builder.WriteString("    local_ca: true\n")
		builder.WriteString("    install_trust: true\n")
	} else {
		builder.WriteString("    local_ca: false\n")
		builder.WriteString("    install_trust: false\n")
	}
	builder.WriteString("    advertise_endpoint: ")
	builder.WriteString(yamlScalar(advertiseEndpoint))
	if tlsMode == "external" {
		if strings.TrimSpace(answers.CertificateFile) == "" || strings.TrimSpace(answers.PrivateKeyFile) == "" {
			return "", errors.New("external TLS mode requires certificate and private key files")
		}
		builder.WriteString("\n    cert_file: ")
		builder.WriteString(yamlScalar(answers.CertificateFile))
		builder.WriteString("\n    key_file: ")
		builder.WriteString(yamlScalar(answers.PrivateKeyFile))
	}
	builder.WriteString("\n\n")
	builder.WriteString("providers:\n")
	builder.WriteString("  - name: docker_hub\n")
	builder.WriteString("    url: https://registry-1.docker.io\n")
	builder.WriteString("    resolver: true\n")
	builder.WriteString("    pull_provider: true\n")
	for _, provider := range answers.Providers {
		builder.WriteString("  - name: ")
		builder.WriteString(yamlScalar(provider.Name))
		builder.WriteString("\n    url: ")
		builder.WriteString(yamlScalar(provider.URL))
		builder.WriteString("\n    resolver: ")
		builder.WriteString(fmt.Sprintf("%t", provider.Resolver))
		builder.WriteString("\n    pull_provider: ")
		builder.WriteString(fmt.Sprintf("%t", provider.PullProvider))
		if provider.Priority != nil {
			builder.WriteString(fmt.Sprintf("\n    priority: %d", *provider.Priority))
		}
		if provider.Auth.Username != "" {
			builder.WriteString("\n    auth:\n      username: ")
			builder.WriteString(yamlScalar(provider.Auth.Username))
			if provider.Auth.SecretFile != "" {
				builder.WriteString("\n      secret_file: ")
				builder.WriteString(yamlScalar(provider.Auth.SecretFile))
			} else if provider.Auth.Password != "" {
				builder.WriteString("\n      password: ")
				builder.WriteString(yamlScalar(provider.Auth.Password))
			}
		}
		if provider.CAFile != "" {
			builder.WriteString("\n    ca_file: ")
			builder.WriteString(yamlScalar(provider.CAFile))
		}
		if provider.AllowInsecureHTTP {
			builder.WriteString("\n    allow_insecure_http: true")
		}
		builder.WriteByte('\n')
	}
	builder.WriteByte('\n')
	builder.WriteString("resolution:\n")
	builder.WriteString("  conflict_strategy: majority\n")
	builder.WriteString("  tie_breaker: rendezvous_hash\n")
	builder.WriteString("  decision_lease: 10m\n\n")
	builder.WriteString("probe_ref: library/busybox:latest\n")
	builder.WriteString("allow_non_range_providers: true\n")
	resources := normalizedResources(answers.Resources)
	builder.WriteString("\nresources:\n")
	builder.WriteString(fmt.Sprintf("  max_concurrent_pulls: %d\n", resources.MaxConcurrentPulls))
	builder.WriteString(fmt.Sprintf("  max_segments_per_blob: %d\n", resources.MaxSegmentsPerBlob))
	builder.WriteString("  temporary_disk_quota: " + yamlScalar(resources.TemporaryDiskQuota) + "\n")
	builder.WriteString("  min_segment_size: " + yamlScalar(resources.MinSegmentSize) + "\n")
	builder.WriteString("  max_no_range_restart_discard: " + yamlScalar(resources.MaxNoRangeRestartDiscard) + "\n")
	builder.WriteString(fmt.Sprintf("  max_inflight_requests: %d\n", resources.MaxInflightRequests))
	builder.WriteString(fmt.Sprintf("  max_queued_pulls: %d\n", resources.MaxQueuedPulls))
	retention := config.DefaultRetention()
	builder.WriteString("\nretention:\n")
	builder.WriteString("  event_retention: " + yamlScalar(retention.EventRetention) + "\n")
	builder.WriteString("  event_max_bytes: " + yamlScalar(retention.EventMaxBytes) + "\n")
	builder.WriteString("  health_retention: " + yamlScalar(retention.HealthRetention) + "\n")
	return builder.String(), nil
}

func normalizedResources(resources config.Resources) config.Resources {
	defaults := config.DefaultResources()
	if resources.MaxConcurrentPulls == 0 {
		resources.MaxConcurrentPulls = defaults.MaxConcurrentPulls
	}
	if resources.MaxSegmentsPerBlob == 0 {
		resources.MaxSegmentsPerBlob = defaults.MaxSegmentsPerBlob
	}
	if resources.TemporaryDiskQuota == "" {
		resources.TemporaryDiskQuota = defaults.TemporaryDiskQuota
	}
	if resources.MinSegmentSize == "" {
		resources.MinSegmentSize = defaults.MinSegmentSize
	}
	if resources.MaxNoRangeRestartDiscard == "" {
		resources.MaxNoRangeRestartDiscard = defaults.MaxNoRangeRestartDiscard
	}
	if resources.MaxInflightRequests == 0 {
		resources.MaxInflightRequests = defaults.MaxInflightRequests
	}
	if resources.MaxQueuedPulls == 0 {
		resources.MaxQueuedPulls = defaults.MaxQueuedPulls
	}
	return resources
}

func yamlScalar(value string) string {
	if strings.ContainsAny(value, "[]{}#,&*!|>'\"%@`\n\r\t") || strings.HasPrefix(value, "-") {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return value
}
