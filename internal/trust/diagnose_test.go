package trust_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/localca"
	"github.com/hjx/docker-registry-gateway/internal/trust"
)

func TestDiagnoseVerifiesLinuxDockerTrustFile(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	result, err := localca.Reconcile(context.Background(), localca.Options{DataDir: dataDir, AdvertiseEndpoint: "drg.localhost:443"})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	certsDir := t.TempDir()
	missing, err := trust.Diagnose(trust.Options{CAPath: result.CAPath, AdvertiseEndpoint: "drg.localhost:443", Platform: "linux", LinuxCertsDir: certsDir})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !missing.Checked || missing.Trusted {
		t.Fatalf("missing diagnosis = %+v, want checked untrusted", missing)
	}
	for _, name := range []string{"drg.localhost", "host.docker.internal"} {
		directory := filepath.Join(certsDir, name)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create trust directory: %v", err)
		}
		contents, err := os.ReadFile(result.CAPath)
		if err != nil {
			t.Fatalf("read CA: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "drg-ca.crt"), contents, 0o644); err != nil {
			t.Fatalf("write trusted root: %v", err)
		}
	}
	trusted, err := trust.Diagnose(trust.Options{CAPath: result.CAPath, AdvertiseEndpoint: "drg.localhost:443", Platform: "linux", LinuxCertsDir: certsDir})
	if err != nil {
		t.Fatalf("Diagnose() after installation error = %v", err)
	}
	if !trusted.Checked || !trusted.Trusted {
		t.Errorf("trusted diagnosis = %+v, want checked trusted", trusted)
	}
}
