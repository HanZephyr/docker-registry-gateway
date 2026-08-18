// Package lease persists short-lived Resolver decisions without a database.
package lease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store is a process-safe file-backed decision-lease store. An empty path
// creates an in-memory store, useful when persistence is intentionally absent.
type Store struct {
	mu      sync.Mutex
	path    string
	entries map[string]entry
}

type entry struct {
	Digest    string    `json:"digest"`
	ExpiresAt time.Time `json:"expires_at"`
}

type disk struct {
	Entries map[string]entry `json:"entries"`
}

// Open loads and prunes a lease store using now as the clock boundary.
func Open(path string, now time.Time) (*Store, error) {
	store := &Store{path: path, entries: make(map[string]entry)}
	if path == "" {
		return store, nil
	}
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read decision leases: %w", err)
	}
	var persisted disk
	if err := json.Unmarshal(contents, &persisted); err != nil {
		return nil, fmt.Errorf("decode decision leases: %w", err)
	}
	if persisted.Entries != nil {
		store.entries = persisted.Entries
	}
	if store.prune(now) {
		if err := store.save(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// Get returns a non-expired digest decision for key.
func (store *Store) Get(key string, now time.Time) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.entries[key]
	if !found {
		return "", false, nil
	}
	if !value.ExpiresAt.After(now) {
		delete(store.entries, key)
		if err := store.save(); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	return value.Digest, true, nil
}

// Put records a decision until expiresAt. The update is atomically persisted
// before it is reported successful when the Store has a file path.
func (store *Store) Put(key, digest string, expiresAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries[key] = entry{Digest: digest, ExpiresAt: expiresAt}
	return store.save()
}

// Clear removes every lease, including the backing data if configured.
func (store *Store) Clear() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries = make(map[string]entry)
	return store.save()
}

// DeletePrefix removes every lease whose canonical key starts with prefix.
// Router lease keys use a reference prefix so all Accept variants of one tag
// can be invalidated together.
func (store *Store) DeletePrefix(prefix string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	for key := range store.entries {
		if strings.HasPrefix(key, prefix) {
			delete(store.entries, key)
		}
	}
	return store.save()
}

func (store *Store) prune(now time.Time) bool {
	changed := false
	for key, value := range store.entries {
		if !value.ExpiresAt.After(now) {
			delete(store.entries, key)
			changed = true
		}
	}
	return changed
}

func (store *Store) save() error {
	if store.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create lease directory: %w", err)
	}
	contents, err := json.Marshal(disk{Entries: store.entries})
	if err != nil {
		return fmt.Errorf("encode decision leases: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".drg-leases-*.json")
	if err != nil {
		return fmt.Errorf("create temporary decision leases: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("activate decision leases: %w", err)
	}
	return nil
}
