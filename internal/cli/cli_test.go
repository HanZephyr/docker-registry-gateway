package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/cli"
	"github.com/hjx/docker-registry-gateway/internal/control"
	"github.com/hjx/docker-registry-gateway/internal/lease"
)

func TestRunOnboardGuidesUserAndCreatesConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	input := strings.NewReader("\n\n")
	var output bytes.Buffer
	var errors bytes.Buffer

	exitCode := cli.Run(context.Background(), []string{"onboard", "--no-start", "--skip-trust-install", "--config", configPath}, input, &output, &errors)
	if exitCode != 0 {
		t.Fatalf("cli.Run() exit code = %d, stderr = %s", exitCode, errors.String())
	}
	for _, prompt := range []string{"监听地址", "访问地址", "已生成配置"} {
		if !strings.Contains(output.String(), prompt) {
			t.Errorf("stdout does not contain %q:\n%s", prompt, output.String())
		}
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated configuration: %v", err)
	}
	if !strings.Contains(string(contents), "advertise_endpoint: drg.localhost:5443") {
		t.Errorf("generated configuration =\n%s", contents)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(configPath), ".drg", "pki", "server.crt")); err != nil {
		t.Errorf("onboard did not reconcile TLS: %v", err)
	}
}

func TestRunReturnsUsageErrorForUnknownCommand(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	var errors bytes.Buffer
	exitCode := cli.Run(context.Background(), []string{"wat"}, strings.NewReader(""), &output, &errors)
	if exitCode != 2 {
		t.Fatalf("cli.Run() exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(errors.String(), "未知命令") {
		t.Errorf("stderr = %q, want unknown command message", errors.String())
	}
}

func TestRunConfigValidateReportsValidConfiguration(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	contents := `
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
resolution:
  conflict_strategy: majority
  tie_breaker: rendezvous_hash
probe_ref: library/busybox:latest
allow_non_range_providers: true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	var output bytes.Buffer
	var errors bytes.Buffer
	exitCode := cli.Run(context.Background(), []string{"config", "validate", "--config", configPath}, strings.NewReader(""), &output, &errors)
	if exitCode != 0 {
		t.Fatalf("cli.Run() exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if !strings.Contains(output.String(), "配置有效") {
		t.Errorf("stdout = %q, want validation success", output.String())
	}
}

func TestRunTLSReconcileCreatesLocalCertificateMaterial(t *testing.T) {
	t.Parallel()

	configDirectory := t.TempDir()
	configPath := filepath.Join(configDirectory, "drg.yaml")
	contents := `
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
resolution:
  conflict_strategy: majority
  tie_breaker: rendezvous_hash
probe_ref: library/busybox:latest
allow_non_range_providers: true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	var output bytes.Buffer
	var errors bytes.Buffer
	exitCode := cli.Run(context.Background(), []string{"tls", "reconcile", "--config", configPath}, strings.NewReader(""), &output, &errors)
	if exitCode != 0 {
		t.Fatalf("cli.Run() exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if !strings.Contains(output.String(), "TLS 对账完成") {
		t.Errorf("stdout = %q, want reconciliation result", output.String())
	}
	if _, err := os.Stat(filepath.Join(configDirectory, ".drg", "pki", "server.crt")); err != nil {
		t.Errorf("server certificate not created: %v", err)
	}
}

func TestRunLocalControlCommands(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	pathForYAML := strings.ReplaceAll(filepath.ToSlash(dataDir), "'", "''")
	contents := `
version: 1
data_dir: '` + pathForYAML + `'
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
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	var reloads int
	stopped := make(chan bool, 1)
	server, err := control.Start(dataDir, control.Callbacks{
		Status: func() control.Status { return control.Status{State: "running", ActivePulls: 3} },
		Reload: func(context.Context) error {
			reloads++
			return nil
		},
		Stop: func(_ context.Context, force bool) error {
			stopped <- force
			return nil
		},
	})
	if err != nil {
		t.Fatalf("start control server: %v", err)
	}
	defer server.Close()
	leaseStore, err := lease.Open(filepath.Join(dataDir, "decision-leases.json"), time.Now())
	if err != nil {
		t.Fatalf("open lease store: %v", err)
	}
	if err := leaseStore.Put("library/nginx\x00latest\x00application/oci", "sha256:stable", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("seed lease store: %v", err)
	}

	for _, command := range [][]string{
		{"status", "--config", configPath},
		{"reload", "--config", configPath},
		{"resolver", "invalidate", "--config", configPath, "library/nginx:latest"},
		{"stop", "--force", "--config", configPath},
	} {
		var output bytes.Buffer
		var errors bytes.Buffer
		if exitCode := cli.Run(context.Background(), command, strings.NewReader(""), &output, &errors); exitCode != 0 {
			t.Fatalf("drg %s exit code = %d, stderr = %s", command[0], exitCode, errors.String())
		}
	}
	if reloads != 2 {
		t.Errorf("reload count = %d, want 2", reloads)
	}
	updatedLeaseStore, err := lease.Open(filepath.Join(dataDir, "decision-leases.json"), time.Now())
	if err != nil {
		t.Fatalf("reopen invalidated lease store: %v", err)
	}
	if _, found, err := updatedLeaseStore.Get("library/nginx\x00latest\x00application/oci", time.Now()); err != nil || found {
		t.Errorf("invalidated lease = (%t, %v), want absent", found, err)
	}
	select {
	case forcedStop := <-stopped:
		if !forcedStop {
			t.Error("stop --force did not reach control service")
		}
	case <-time.After(time.Second):
		t.Error("stop callback was not invoked")
	}
}

func TestRunServeLoadsAndStopsThroughItsOwnLocalControlEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	pathForYAML := strings.ReplaceAll(filepath.ToSlash(dataDir), "'", "''")
	contents := `
version: 1
data_dir: '` + pathForYAML + `'
server:
  listeners: [127.0.0.1:0]
  tls:
    local_ca: true
    install_trust: false
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	var serveOutput bytes.Buffer
	var serveErrors bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(context.Background(), []string{"serve", "--config", configPath}, strings.NewReader(""), &serveOutput, &serveErrors)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := control.StatusRequest(context.Background(), dataDir); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve did not publish a local control endpoint: stderr=%s", serveErrors.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var output bytes.Buffer
	var errors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"reload", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("reload exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if exitCode := cli.Run(context.Background(), []string{"stop", "--force", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("stop exit code = %d, stderr = %s", exitCode, errors.String())
	}
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("serve exit code = %d, stderr = %s", exitCode, serveErrors.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after local control request")
	}
}
