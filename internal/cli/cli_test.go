package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/cli"
	"github.com/hjx/docker-registry-gateway/internal/config"
	"github.com/hjx/docker-registry-gateway/internal/control"
	"github.com/hjx/docker-registry-gateway/internal/eventlog"
	"github.com/hjx/docker-registry-gateway/internal/lease"
	"github.com/hjx/docker-registry-gateway/internal/routeguard"
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

func TestRunOnboardCanWriteExplicitPlaintextProviderPassword(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	input := strings.NewReader("\n\n\ny\nmirror\nhttps://mirror.example.test\nn\ny\nrobot\npassword\nplain-pat\nn\nn\n")
	var output, errors bytes.Buffer
	exitCode := cli.Run(context.Background(), []string{"onboard", "--no-start", "--skip-trust-install", "--config", configPath}, input, &output, &errors)
	if exitCode != 0 {
		t.Fatalf("cli.Run() exit code = %d, stderr = %s", exitCode, errors.String())
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read generated configuration: %v", err)
	}
	for _, expected := range []string{"name: mirror", "username: robot", "password: plain-pat"} {
		if !strings.Contains(string(contents), expected) {
			t.Errorf("generated configuration lacks %q:\n%s", expected, contents)
		}
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

func TestRunEventsDisplaysNonSecretPullContext(t *testing.T) {
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
    local_ca: false
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
	if err := eventlog.New(dataDir, time.Now).Write(eventlog.Event{Level: "warning", Code: "blob_source_switched", Provider: "mirror-a", Repository: "library/nginx", Reference: "latest", Digest: "sha256:stable", Message: "resumed safely"}); err != nil {
		t.Fatalf("write event: %v", err)
	}
	var output, errors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"events", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("events exit code = %d, stderr = %s", exitCode, errors.String())
	}
	for _, expected := range []string{"Provider=mirror-a", "Repository=library/nginx", "Reference=latest", "Digest=sha256:stable"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("events output lacks %q:\n%s", expected, output.String())
		}
	}
}

func TestRunConfigMigrateLeavesCurrentV1ConfigurationUntouched(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	contents := []byte(`version: 1
server:
  listeners: [127.0.0.1:5443]
  tls:
    advertise_endpoint: drg.localhost:5443
providers:
  - name: docker_hub
    url: https://registry-1.docker.io
    resolver: true
    pull_provider: true
`)
	if err := os.WriteFile(configPath, contents, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var output, errors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"config", "migrate", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("config migrate exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if current, err := os.ReadFile(configPath); err != nil || string(current) != string(contents) {
		t.Errorf("current configuration changed by no-op migration: %v", err)
	}
	if !strings.Contains(output.String(), "无需改写") {
		t.Errorf("migrate output = %q", output.String())
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
	output.Reset()
	errors.Reset()
	if exitCode := cli.Run(context.Background(), []string{"tls", "rotate-root", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("tls rotate-root exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if !strings.Contains(output.String(), "已准备新根 CA") {
		t.Errorf("rotation stdout = %q, want prepared root result", output.String())
	}
	if _, err := os.Stat(filepath.Join(configDirectory, ".drg", "pki", "ca.next.crt")); err != nil {
		t.Errorf("pending root certificate not prepared: %v", err)
	}
	output.Reset()
	errors.Reset()
	if exitCode := cli.Run(context.Background(), []string{"tls", "rotate-root", "--activate", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("tls rotate-root --activate exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if !strings.Contains(output.String(), "根 CA 已轮换") {
		t.Errorf("activation stdout = %q, want root rotation result", output.String())
	}
	if _, err := os.Stat(filepath.Join(configDirectory, ".drg", "pki", "ca.previous.crt")); err != nil {
		t.Errorf("previous root certificate not preserved: %v", err)
	}
}

func TestRunDoctorPerformsReadOnlyLocalDiagnostics(t *testing.T) {
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
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	var setupOutput, setupErrors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"tls", "reconcile", "--config", configPath}, strings.NewReader(""), &setupOutput, &setupErrors); exitCode != 0 {
		t.Fatalf("tls reconcile exit code = %d, stderr = %s", exitCode, setupErrors.String())
	}
	var output, errors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"doctor", "--skip-providers", "--skip-docker", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("doctor exit code = %d, stderr = %s, stdout = %s", exitCode, errors.String(), output.String())
	}
	for _, expected := range []string{"配置：正常", "TLS：正常", "Docker 根证书信任：配置已关闭自动安装", "Docker daemon：已按参数跳过检查", "Docker 镜像源配置属于部署边界"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("doctor output lacks %q:\n%s", expected, output.String())
		}
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
	probeContents := []byte("probe")
	probeSum := sha256.Sum256(probeContents)
	probeDigest := fmt.Sprintf("sha256:%x", probeSum[:])
	probeManifest := []byte(`{"schemaVersion":2,"config":{"digest":"` + probeDigest + `"}}`)
	probeServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get(routeguard.InstanceHeader) == "" || request.Header.Get(routeguard.HopHeader) == "" {
			t.Error("provider admission probe omitted Gateway route-guard headers")
		}
		switch request.URL.Path {
		case "/v2/":
			response.WriteHeader(http.StatusOK)
		case "/v2/library/busybox/manifests/latest":
			response.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = response.Write(probeManifest)
		case "/v2/library/busybox/blobs/" + probeDigest:
			if request.Header.Get("Range") != "bytes=0-0" {
				http.Error(response, "Range required", http.StatusRequestedRangeNotSatisfiable)
				return
			}
			response.Header().Set("Content-Range", "bytes 0-0/5")
			response.Header().Set("Docker-Content-Digest", probeDigest)
			response.WriteHeader(http.StatusPartialContent)
			_, _ = response.Write(probeContents[:1])
		default:
			http.NotFound(response, request)
		}
	}))
	defer probeServer.Close()
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

	var stopOutput string
	for _, command := range [][]string{
		{"status", "--config", configPath},
		{"reload", "--config", configPath},
		{"resolver", "invalidate", "--config", configPath, "library/nginx:latest"},
		{"provider", "add", "--config", configPath, "--name", "mirror", "--url", probeServer.URL, "--pull-provider", "--allow-insecure-http"},
		{"stop", "--force", "--config", configPath},
	} {
		var output bytes.Buffer
		var errors bytes.Buffer
		if exitCode := cli.Run(context.Background(), command, strings.NewReader(""), &output, &errors); exitCode != 0 {
			t.Fatalf("drg %s exit code = %d, stderr = %s", command[0], exitCode, errors.String())
		}
		if command[0] == "stop" {
			stopOutput = output.String()
		}
	}
	if !strings.Contains(stopOutput, "当前状态：活跃拉取 3") || !strings.Contains(stopOutput, "强制停止请求已被 Gateway 接受") {
		t.Errorf("stop output = %q, want active-pull context and accepted force stop", stopOutput)
	}
	if reloads != 3 {
		t.Errorf("reload count = %d, want 3", reloads)
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
	if exitCode := cli.Run(context.Background(), []string{"stop", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("stop exit code = %d, stderr = %s", exitCode, errors.String())
	}
	if !strings.Contains(output.String(), "Gateway 已停止") {
		t.Errorf("graceful stop output = %q, want confirmed completion", output.String())
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

func TestRunServeAllowsExplicitPlainHTTPBackend(t *testing.T) {
	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "drg.yaml")
	pathForYAML := strings.ReplaceAll(filepath.ToSlash(dataDir), "'", "''")
	contents := `
version: 1
data_dir: '` + pathForYAML + `'
server:
  listeners: [127.0.0.1:0]
  tls:
    local_ca: false
    advertise_endpoint: drg.localhost:5443
providers:
  - name: unreachable
    url: https://127.0.0.1:1
    resolver: true
    pull_provider: true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}

	var serveOutput, serveErrors bytes.Buffer
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
			t.Fatalf("plain serve did not publish control endpoint: stderr=%s", serveErrors.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var output, errors bytes.Buffer
	if exitCode := cli.Run(context.Background(), []string{"stop", "--force", "--config", configPath}, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("stop exit code = %d, stderr = %s", exitCode, errors.String())
	}
	select {
	case exitCode := <-done:
		if exitCode != 0 {
			t.Fatalf("serve exit code = %d, stderr = %s", exitCode, serveErrors.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("plain serve did not stop")
	}
	if !strings.Contains(serveOutput.String(), "纯 HTTP") {
		t.Errorf("serve output = %q, want explicit plain HTTP warning", serveOutput.String())
	}
}

func TestRunProviderAddAndRemoveAtomicallyMaintainsConfiguration(t *testing.T) {
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
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	originalContents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read original configuration: %v", err)
	}
	var output, errors bytes.Buffer
	failedAdd := []string{"provider", "add", "--config", configPath, "--name", "unreachable", "--url", "http://127.0.0.1:1", "--pull-provider", "--allow-insecure-http"}
	if exitCode := cli.Run(context.Background(), failedAdd, strings.NewReader(""), &output, &errors); exitCode == 0 {
		t.Fatal("provider add unexpectedly accepted an unreachable Provider")
	}
	if currentContents, readErr := os.ReadFile(configPath); readErr != nil || string(currentContents) != string(originalContents) {
		t.Errorf("configuration changed after failed admission: readErr=%v", readErr)
	}
	output.Reset()
	errors.Reset()
	duplicate := []string{"provider", "add", "--config", configPath, "--name", "docker_hub", "--url", "http://127.0.0.1:1", "--pull-provider", "--allow-insecure-http"}
	if exitCode := cli.Run(context.Background(), duplicate, strings.NewReader(""), &output, &errors); exitCode == 0 {
		t.Fatal("provider add unexpectedly accepted a duplicate provider name")
	}
	if !strings.Contains(errors.String(), "duplicate provider name") {
		t.Errorf("duplicate provider stderr = %q, want static validation error", errors.String())
	}
	if currentContents, readErr := os.ReadFile(configPath); readErr != nil || string(currentContents) != string(originalContents) {
		t.Errorf("configuration changed after static validation failure: readErr=%v", readErr)
	}
	output.Reset()
	errors.Reset()
	probeContents := []byte("probe")
	probeSum := sha256.Sum256(probeContents)
	probeDigest := fmt.Sprintf("sha256:%x", probeSum[:])
	probeManifest := []byte(`{"schemaVersion":2,"config":{"digest":"` + probeDigest + `"}}`)
	probeServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/":
			response.WriteHeader(http.StatusOK)
		case "/v2/library/busybox/manifests/latest":
			response.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = response.Write(probeManifest)
		case "/v2/library/busybox/blobs/" + probeDigest:
			response.Header().Set("Content-Range", "bytes 0-0/5")
			response.Header().Set("Docker-Content-Digest", probeDigest)
			response.WriteHeader(http.StatusPartialContent)
			_, _ = response.Write(probeContents[:1])
		default:
			http.NotFound(response, request)
		}
	}))
	defer probeServer.Close()
	add := []string{"provider", "add", "--config", configPath, "--name", "mirror", "--url", probeServer.URL, "--resolver", "--pull-provider", "--allow-insecure-http"}
	if exitCode := cli.Run(context.Background(), add, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("provider add exit code = %d, stderr = %s", exitCode, errors.String())
	}
	loaded, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("load added configuration: %v", err)
	}
	if len(loaded.Providers) != 2 || loaded.Providers[1].Name != "mirror" {
		t.Errorf("providers after add = %#v, want configured mirror", loaded.Providers)
	}
	if _, err := os.Stat(configPath + ".bak"); err != nil {
		t.Errorf("configuration backup missing: %v", err)
	}

	output.Reset()
	errors.Reset()
	remove := []string{"provider", "remove", "--config", configPath, "docker_hub"}
	if exitCode := cli.Run(context.Background(), remove, strings.NewReader(""), &output, &errors); exitCode != 0 {
		t.Fatalf("provider remove exit code = %d, stderr = %s", exitCode, errors.String())
	}
	loaded, err = config.LoadFile(configPath)
	if err != nil {
		t.Fatalf("load removed configuration: %v", err)
	}
	if len(loaded.Providers) != 1 || loaded.Providers[0].Name != "mirror" {
		t.Errorf("providers after remove = %#v, want only mirror", loaded.Providers)
	}
}
