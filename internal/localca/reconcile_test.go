package localca_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/localca"
)

func TestReconcileCreatesTrustedLeafForConfiguredAndDesktopNames(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	now := time.Date(2026, time.August, 18, 0, 0, 0, 0, time.UTC)
	result, err := localca.Reconcile(context.Background(), localca.Options{
		DataDir:           dataDir,
		AdvertiseEndpoint: "drg.localhost:5443",
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("localca.Reconcile() error = %v", err)
	}
	if !result.RootCreated || !result.LeafIssued {
		t.Errorf("result = %+v, want newly created root and leaf", result)
	}
	if result.InstanceID == "" {
		t.Error("result InstanceID is empty, want stable Gateway identity derived from the root CA")
	}

	root := readCertificate(t, filepath.Join(dataDir, "pki", "ca.crt"))
	leaf := readCertificate(t, filepath.Join(dataDir, "pki", "server.crt"))
	if err := leaf.VerifyHostname("drg.localhost"); err != nil {
		t.Errorf("leaf does not verify configured DNS name: %v", err)
	}
	if err := leaf.VerifyHostname("host.docker.internal"); err != nil {
		t.Errorf("leaf does not verify Docker Desktop DNS name: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "drg.localhost", CurrentTime: now.Add(time.Hour)}); err != nil {
		t.Errorf("leaf does not verify against generated root: %v", err)
	}

	if _, err := os.Stat(result.IdentityPath); err != nil {
		t.Errorf("identity file missing at %q: %v", result.IdentityPath, err)
	}
}

func TestReconcileRejectsInsecureExistingRootPrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are not represented by POSIX file mode bits")
	}
	dataDir := t.TempDir()
	options := localca.Options{DataDir: dataDir, AdvertiseEndpoint: "drg.localhost:5443"}
	if _, err := localca.Reconcile(context.Background(), options); err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	keyPath := filepath.Join(dataDir, "pki", "ca.key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod root key: %v", err)
	}
	if _, err := localca.Reconcile(context.Background(), options); err == nil {
		t.Fatal("Reconcile() error = nil, want insecure CA key rejection")
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read certificate %q: %v", path, err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatalf("decode certificate %q: no PEM block", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", path, err)
	}
	return certificate
}
