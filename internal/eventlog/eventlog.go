// Package eventlog keeps bounded, non-secret Gateway diagnostics in files.
package eventlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	retention = 7 * 24 * time.Hour
	maxBytes  = int64(100 << 20)
)

// Event intentionally excludes headers, credentials, tokens and redirect URLs.
type Event struct {
	Time     time.Time `json:"time"`
	Level    string    `json:"level"`
	Code     string    `json:"code"`
	Provider string    `json:"provider,omitempty"`
	Message  string    `json:"message"`
}

// Log appends events to a bounded daily JSONL history.
type Log struct {
	directory string
	now       func() time.Time
	mu        sync.Mutex
}

func New(dataDir string, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}
	return &Log{directory: filepath.Join(dataDir, "events"), now: now}
}

func (log *Log) Write(event Event) error {
	if log == nil || log.directory == "" {
		return nil
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if event.Time.IsZero() {
		event.Time = log.now().UTC()
	}
	contents, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	contents = append(contents, '\n')
	if err := os.MkdirAll(log.directory, 0o700); err != nil {
		return err
	}
	if err := log.cleanupLocked(int64(len(contents))); err != nil {
		return err
	}
	path := filepath.Join(log.directory, event.Time.UTC().Format("2006-01-02")+".jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (log *Log) cleanupLocked(incoming int64) error {
	entries, err := os.ReadDir(log.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	type fileInfo struct {
		path     string
		modified time.Time
		size     int64
	}
	var files []fileInfo
	var total int64
	cutoff := log.now().Add(-retention)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		path := filepath.Join(log.directory, entry.Name())
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
			continue
		}
		files = append(files, fileInfo{path, info.ModTime(), info.Size()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modified.Before(files[j].modified) })
	for _, file := range files {
		if total+incoming <= maxBytes {
			break
		}
		if err := os.Remove(file.path); err != nil {
			return err
		}
		total -= file.size
	}
	return nil
}

// Read returns at most limit newest events, ordered oldest to newest.
func (log *Log) Read(limit int) ([]Event, error) {
	if log == nil || log.directory == "" {
		return nil, nil
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	entries, err := os.ReadDir(log.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			paths = append(paths, filepath.Join(log.directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	var events []Event
	for _, path := range paths {
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil, openErr
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			var event Event
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				events = append(events, event)
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}
