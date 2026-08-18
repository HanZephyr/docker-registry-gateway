package certmanager_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/certmanager"
	"github.com/hjx/docker-registry-gateway/internal/localca"
)

func TestManagerKeepsOldCertificateOnFailedReloadAndActivatesReplacement(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	initial := time.Date(2026, time.August, 19, 0, 0, 0, 0, time.UTC)
	result, err := localca.Reconcile(context.Background(), localca.Options{
		DataDir:           directory,
		AdvertiseEndpoint: "drg.localhost:5443",
		Now:               func() time.Time { return initial },
	})
	if err != nil {
		t.Fatalf("initial Reconcile() error = %v", err)
	}
	manager, err := certmanager.New(result.Certificate, result.PrivateKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	before := certificateSerial(t, manager)
	if err := manager.Reload(); err != nil {
		t.Fatalf("unchanged Reload() error = %v", err)
	}
	if got := certificateSerial(t, manager); got.Cmp(before) != 0 {
		t.Errorf("unchanged serial = %s, want %s", got, before)
	}

	if _, err := localca.Reconcile(context.Background(), localca.Options{
		DataDir:           directory,
		AdvertiseEndpoint: "drg.localhost:5443",
		Now:               func() time.Time { return initial.Add(61 * 24 * time.Hour) },
	}); err != nil {
		t.Fatalf("renew leaf Reconcile() error = %v", err)
	}
	if err := manager.Reload(); err != nil {
		t.Fatalf("renewed Reload() error = %v", err)
	}
	if got := certificateSerial(t, manager); got.Cmp(before) == 0 {
		t.Errorf("renewed serial = %s, want a new leaf certificate", got)
	}
}

func certificateSerial(t *testing.T, manager *certmanager.Manager) *big.Int {
	t.Helper()
	certificate, err := manager.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate() error = %v", err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return parsed.SerialNumber
}
