package router

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/registry"
)

func TestSegmentedReaderFallsBackAfterStorageFailure(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first")
	if err := os.WriteFile(firstPath, []byte("abc"), 0o600); err != nil {
		t.Fatalf("write first segment: %v", err)
	}
	firstReady := make(chan error, 1)
	firstReady <- nil
	secondReady := make(chan error, 1)
	secondReady <- segmentStorageError{io.ErrShortWrite}
	done := make(chan struct{})
	close(done)
	var offset int64 = -1
	reader := &segmentedReader{
		ctx:      context.Background(),
		digest:   "sha256:blob",
		size:     6,
		segments: []segment{{start: 0, end: 2, physicalStart: 0, path: firstPath}, {start: 3, end: 5, physicalStart: 3}},
		ready:    []chan error{firstReady, secondReady},
		done:     done,
		fallbackOpen: func(start int64) (registry.Blob, error) {
			offset = start
			return registry.Blob{Digest: "sha256:blob", Size: 6, Start: start, End: 5, Reader: io.NopCloser(bytes.NewReader([]byte("def")))}, nil
		},
	}
	defer reader.Close()

	contents, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if got, want := string(contents), "abcdef"; got != want {
		t.Errorf("contents = %q, want %q", got, want)
	}
	if offset != 3 {
		t.Errorf("fallback offset = %d, want 3", offset)
	}
}
