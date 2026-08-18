// Package healthhistory persists non-secret Provider transfer metrics without
// introducing a database dependency.
package healthhistory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/router"
)

const (
	fileVersion = 1
	// Retention is the default provider-health history window. Deployments may
	// override it through their bounded file-retention configuration.
	Retention = 7 * 24 * time.Hour
)

// Store owns one atomically-updated health-history file.
type Store struct {
	path      string
	now       func() time.Time
	retention time.Duration
}

type persistedFile struct {
	Version   int                     `json:"version"`
	Providers []router.HealthSnapshot `json:"providers"`
}

// Open constructs a Store. The parent directory is made only when saving, so
// read-only CLI status checks do not mutate the filesystem.
func Open(path string, now func() time.Time, retention ...time.Duration) *Store {
	if now == nil {
		now = time.Now
	}
	configuredRetention := Retention
	if len(retention) > 0 && retention[0] > 0 {
		configuredRetention = retention[0]
	}
	return &Store{path: path, now: now, retention: configuredRetention}
}

// Load returns snapshots observed within retention. A malformed file is
// reported to the caller; the process can then keep running with empty health.
func (store *Store) Load(retention time.Duration) ([]router.HealthSnapshot, error) {
	if store == nil || store.path == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read provider health history: %w", err)
	}
	var persisted persistedFile
	if err := json.Unmarshal(contents, &persisted); err != nil {
		return nil, fmt.Errorf("decode provider health history: %w", err)
	}
	if persisted.Version != fileVersion {
		return nil, fmt.Errorf("unsupported provider health history version %d", persisted.Version)
	}
	if retention <= 0 {
		retention = store.retention
	}
	cutoff := store.now().Add(-retention)
	result := make([]router.HealthSnapshot, 0, len(persisted.Providers))
	for _, snapshot := range persisted.Providers {
		if snapshot.Provider == "" || snapshot.ThroughputBytesPerSecond < 0 || !observedSince(snapshot, cutoff) {
			continue
		}
		snapshot.Failures = 0
		result = append(result, snapshot)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Provider < result[right].Provider
	})
	return result, nil
}

// Save atomically replaces the history file. Failure counters are omitted by
// setting them to zero before serialization: they are process-local routing
// state, not durable history.
func (store *Store) Save(snapshots []router.HealthSnapshot) error {
	if store == nil || store.path == "" {
		return nil
	}
	providers := make([]router.HealthSnapshot, 0, len(snapshots))
	cutoff := store.now().Add(-store.retention)
	for _, snapshot := range snapshots {
		if snapshot.Provider == "" || snapshot.ThroughputBytesPerSecond < 0 || !observedSince(snapshot, cutoff) {
			continue
		}
		snapshot.Failures = 0
		providers = append(providers, snapshot)
	}
	sort.Slice(providers, func(left, right int) bool {
		return providers[left].Provider < providers[right].Provider
	})
	contents, err := json.Marshal(persistedFile{Version: fileVersion, Providers: providers})
	if err != nil {
		return fmt.Errorf("encode provider health history: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create provider health history directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".drg-health-*.json")
	if err != nil {
		return fmt.Errorf("create temporary provider health history: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect temporary provider health history: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write provider health history: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close provider health history: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("activate provider health history: %w", err)
	}
	return nil
}

func observedSince(snapshot router.HealthSnapshot, cutoff time.Time) bool {
	latest := snapshot.LastSuccess
	if snapshot.LastFailure.After(latest) {
		latest = snapshot.LastFailure
	}
	return !latest.IsZero() && !latest.Before(cutoff)
}
