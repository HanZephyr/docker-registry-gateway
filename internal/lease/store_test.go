package lease_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/lease"
)

func TestStorePersistsNonExpiredLeaseAndPrunesExpiredLease(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "leases.json")
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	store, err := lease.Open(path, now)
	if err != nil {
		t.Fatalf("lease.Open() error = %v", err)
	}
	if err := store.Put("library/nginx\x00latest", "sha256:stable", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	reopened, err := lease.Open(path, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	digest, found, err := reopened.Get("library/nginx\x00latest", now.Add(time.Minute))
	if err != nil || !found || digest != "sha256:stable" {
		t.Fatalf("Get() = (%q, %t, %v), want persisted digest", digest, found, err)
	}
	if _, found, err := reopened.Get("library/nginx\x00latest", now.Add(11*time.Minute)); err != nil || found {
		t.Fatalf("expired Get() = (%t, %v), want absent", found, err)
	}
}

func TestStoreDeletesEveryAcceptVariantForAReference(t *testing.T) {
	t.Parallel()

	now := time.Now()
	store, err := lease.Open("", now)
	if err != nil {
		t.Fatalf("lease.Open() error = %v", err)
	}
	for _, key := range []string{
		"library/nginx\x00latest\x00application/oci",
		"library/nginx\x00latest\x00application/docker",
		"library/nginx\x001.0\x00application/oci",
	} {
		if err := store.Put(key, "sha256:stable", now.Add(time.Minute)); err != nil {
			t.Fatalf("Put(%q): %v", key, err)
		}
	}
	if err := store.DeletePrefix("library/nginx\x00latest\x00"); err != nil {
		t.Fatalf("DeletePrefix() error = %v", err)
	}
	if _, found, _ := store.Get("library/nginx\x00latest\x00application/oci", now); found {
		t.Error("OCI accept variant remained after reference invalidation")
	}
	if _, found, _ := store.Get("library/nginx\x001.0\x00application/oci", now); !found {
		t.Error("unrelated tag was removed by reference invalidation")
	}
}
