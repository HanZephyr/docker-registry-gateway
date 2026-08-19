// Package eventlog keeps bounded, non-secret Gateway diagnostics in files.
package eventlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultRetention = 7 * 24 * time.Hour
	defaultMaxBytes  = int64(100 << 20)
	followInterval   = 250 * time.Millisecond
)

// Event intentionally excludes headers, credentials, tokens and redirect URLs.
type Event struct {
	Time       time.Time `json:"time"`
	Level      string    `json:"level"`
	Code       string    `json:"code"`
	Provider   string    `json:"provider,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Reference  string    `json:"reference,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	Message    string    `json:"message"`
}

// Log appends events to a bounded daily JSONL history.
type Log struct {
	directory string
	now       func() time.Time
	retention time.Duration
	maxBytes  int64
	mu        sync.Mutex
}

// Options configures bounded local event retention.
type Options struct {
	Retention time.Duration
	MaxBytes  int64
}

func New(dataDir string, now func() time.Time, options ...Options) *Log {
	if now == nil {
		now = time.Now
	}
	configured := Options{Retention: defaultRetention, MaxBytes: defaultMaxBytes}
	if len(options) > 0 {
		if options[0].Retention > 0 {
			configured.Retention = options[0].Retention
		}
		if options[0].MaxBytes > 0 {
			configured.MaxBytes = options[0].MaxBytes
		}
	}
	return &Log{directory: filepath.Join(dataDir, "events"), now: now, retention: configured.Retention, maxBytes: configured.MaxBytes}
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
	cutoff := log.now().Add(-log.retention)
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
		if total+incoming <= log.maxBytes {
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
	paths, err := log.paths()
	if err != nil {
		return nil, err
	}
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

// Follow emits the newest limit events, then every event appended afterwards.
// It follows daily rotation and returns cleanly when context is cancelled.
func (log *Log) Follow(ctx context.Context, limit int, observe func(Event)) error {
	if log == nil || log.directory == "" || observe == nil {
		return nil
	}
	cursors, err := log.captureCursors()
	if err != nil {
		return err
	}
	initial, err := log.Read(limit)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(initial))
	for _, event := range initial {
		observe(event)
		seen[eventKey(event)] = struct{}{}
	}

	ticker := time.NewTicker(followInterval)
	defer ticker.Stop()
	for {
		if err := log.drain(cursors, seen, observe); err != nil {
			return err
		}
		// The cursor was captured immediately before Read. Only this first drain
		// can overlap with the initial snapshot, so retaining keys any longer
		// would make a long-running diagnostic command grow without bound.
		seen = nil
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type followCursor struct {
	offset  int64
	pending []byte
}

func (log *Log) paths() ([]string, error) {
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
	return paths, nil
}

func (log *Log) captureCursors() (map[string]*followCursor, error) {
	paths, err := log.paths()
	if err != nil {
		return nil, err
	}
	cursors := make(map[string]*followCursor, len(paths))
	for _, path := range paths {
		offset, err := lastCompleteOffset(path)
		if err != nil {
			return nil, err
		}
		cursors[path] = &followCursor{offset: offset}
	}
	return cursors, nil
}

func (log *Log) drain(cursors map[string]*followCursor, seen map[string]struct{}, observe func(Event)) error {
	paths, err := log.paths()
	if err != nil {
		return err
	}
	for _, path := range paths {
		cursor, found := cursors[path]
		if !found {
			cursor = &followCursor{}
			cursors[path] = cursor
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Size() < cursor.offset {
			cursor.offset = 0
			cursor.pending = nil
		}
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := file.Seek(cursor.offset, io.SeekStart); err != nil {
			_ = file.Close()
			return err
		}
		contents, readErr := io.ReadAll(file)
		closeErr := file.Close()
		cursor.offset += int64(len(contents))
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		cursor.pending = append(cursor.pending, contents...)
		for {
			index := bytes.IndexByte(cursor.pending, '\n')
			if index < 0 {
				break
			}
			line := cursor.pending[:index]
			cursor.pending = cursor.pending[index+1:]
			var event Event
			if json.Unmarshal(line, &event) != nil {
				continue
			}
			key := eventKey(event)
			if seen != nil {
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
			}
			observe(event)
		}
	}
	return nil
}

func lastCompleteOffset(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	const tailSize = int64(64 << 10)
	start := max(info.Size()-tailSize, 0)
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		return 0, err
	}
	for index := len(contents) - 1; index >= 0; index-- {
		if contents[index] == '\n' {
			return start + int64(index+1), nil
		}
	}
	return 0, nil
}

func eventKey(event Event) string {
	return event.Time.UTC().Format(time.RFC3339Nano) + "\x00" + event.Level + "\x00" + event.Code + "\x00" + event.Provider + "\x00" + event.Repository + "\x00" + event.Reference + "\x00" + event.Digest + "\x00" + event.Message
}
