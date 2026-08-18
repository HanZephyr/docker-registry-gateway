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
)

// Answers contains the deployment choices collected by drg onboard.
type Answers struct {
	Listeners         []string
	AdvertiseEndpoint string
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

	contents := defaultConfiguration(advertiseEndpoint, listeners)
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
	if err := os.Rename(temporaryPath, configPath); err != nil {
		return fmt.Errorf("activate configuration: %w", err)
	}
	return nil
}

func defaultConfiguration(advertiseEndpoint string, listeners []string) string {
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
	builder.WriteString("    local_ca: true\n")
	builder.WriteString("    install_trust: true\n")
	builder.WriteString("    advertise_endpoint: ")
	builder.WriteString(yamlScalar(advertiseEndpoint))
	builder.WriteString("\n\n")
	builder.WriteString("providers:\n")
	builder.WriteString("  - name: docker_hub\n")
	builder.WriteString("    url: https://registry-1.docker.io\n")
	builder.WriteString("    resolver: true\n")
	builder.WriteString("    pull_provider: true\n\n")
	builder.WriteString("resolution:\n")
	builder.WriteString("  conflict_strategy: majority\n")
	builder.WriteString("  tie_breaker: rendezvous_hash\n")
	builder.WriteString("  decision_lease: 10m\n\n")
	builder.WriteString("probe_ref: library/busybox:latest\n")
	builder.WriteString("allow_non_range_providers: true\n")
	builder.WriteString("\nresources:\n")
	builder.WriteString("  max_concurrent_pulls: 4\n")
	builder.WriteString("  max_segments_per_blob: 4\n")
	builder.WriteString("  temporary_disk_quota: 2GiB\n")
	builder.WriteString("  min_segment_size: 16MiB\n")
	builder.WriteString("  max_no_range_restart_discard: 64MiB\n")
	builder.WriteString("  max_inflight_requests: 32\n")
	builder.WriteString("  max_queued_pulls: 16\n")
	return builder.String()
}

func yamlScalar(value string) string {
	if strings.ContainsAny(value, "[]{}#,&*!|>'\"%@`\n\r\t") || strings.HasPrefix(value, "-") {
		return "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return value
}
