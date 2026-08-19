package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hjx/docker-registry-gateway/internal/registry"
)

const segmentOverlap int64 = 64 << 10

// TempBudget prevents concurrent pulls from filling the temporary filesystem.
// It is intentionally process-local: DRG does not coordinate or merge work
// across clients.
type TempBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
}

// NewTempBudget creates a shared temporary-file reservation budget.
func NewTempBudget(limit int64) *TempBudget {
	return &TempBudget{limit: limit}
}

func (budget *TempBudget) acquire(bytes int64) (func(), bool) {
	if budget == nil || bytes <= 0 {
		return func() {}, budget == nil
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.limit <= 0 || bytes > budget.limit-budget.used {
		return nil, false
	}
	budget.used += bytes
	var once sync.Once
	return func() {
		once.Do(func() {
			budget.mu.Lock()
			budget.used -= bytes
			budget.mu.Unlock()
		})
	}, true
}

func (router *Router) trySegmentedBlob(ctx context.Context, repository, digest string) (registry.Blob, bool) {
	if router.maxSegmentsPerBlob < 2 || router.minSegmentSize <= 0 || router.tempBudget == nil || router.temporaryDir == "" {
		return registry.Blob{}, false
	}
	metadata, err := router.openBlob(ctx, repository, digest, "bytes=0-0")
	if err != nil {
		return registry.Blob{}, false
	}
	_ = metadata.Reader.Close()
	segments := planSegments(metadata.Size, router.maxSegmentsPerBlob, router.minSegmentSize)
	if len(segments) < 2 {
		return registry.Blob{}, false
	}
	reserve := segmentStorageBytes(segments)
	release, acquired := router.tempBudget.acquire(reserve)
	if !acquired {
		return registry.Blob{}, false
	}
	ranges := segmentRanges(segments)
	reader, err := router.startSegmentDownloads(ctx, repository, digest, metadata.Size, segments, release)
	if err != nil {
		release()
		return registry.Blob{}, false
	}
	router.emit(Event{
		Level:      "info",
		Code:       "segmented_download_started",
		Repository: repository,
		Digest:     digest,
		Message:    fmt.Sprintf("segments=%d; ranges=%s", len(segments), ranges),
	})
	return registry.Blob{Digest: digest, Size: metadata.Size, Start: 0, End: metadata.Size - 1, Reader: reader}, true
}

type segment struct {
	start         int64
	end           int64
	physicalStart int64
	path          string
}

func planSegments(size int64, maximum int, minimumSize int64) []segment {
	if size <= 0 || maximum < 2 || minimumSize <= 0 || minimumSize > size/2 {
		return nil
	}
	// A segment count must not make an even logical split smaller than the
	// configured minimum. Floor, rather than ceiling, preserves that contract.
	requested := size / minimumSize
	count := maximum
	if requested < int64(maximum) {
		count = int(requested)
	}
	if count < 2 {
		return nil
	}
	segments := make([]segment, count)
	for index := range segments {
		start := int64(index) * size / int64(count)
		end := int64(index+1)*size/int64(count) - 1
		physicalStart := start
		if index > 0 {
			overlap := segmentOverlap
			if overlap > start {
				overlap = start
			}
			physicalStart -= overlap
		}
		segments[index] = segment{start: start, end: end, physicalStart: physicalStart}
	}
	return segments
}

func segmentStorageBytes(segments []segment) int64 {
	var total int64
	for _, segment := range segments {
		length := segment.end - segment.physicalStart + 1
		if length <= 0 || total > (1<<63-1)-length {
			return 0
		}
		total += length
	}
	return total
}

func segmentRanges(segments []segment) string {
	ranges := make([]string, len(segments))
	for index, segment := range segments {
		ranges[index] = fmt.Sprintf("bytes=%d-%d", segment.physicalStart, segment.end)
	}
	return strings.Join(ranges, ",")
}

func (router *Router) startSegmentDownloads(parent context.Context, repository, digest string, size int64, segments []segment, release func()) (*segmentedReader, error) {
	directory := router.temporaryDir
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	downloadContext, cancel := context.WithCancel(parent)
	ready := make([]chan error, len(segments))
	done := make(chan struct{})
	reader := &segmentedReader{
		ctx:      parent,
		segments: segments,
		ready:    ready,
		done:     done,
		cancel:   cancel,
		release:  release,
		digest:   digest,
		size:     size,
		fallbackOpen: func(offset int64) (registry.Blob, error) {
			return router.openBlob(parent, repository, digest, fmt.Sprintf("bytes=%d-%d", offset, size-1))
		},
		onFallback: func() {
			router.emit(Event{Level: "warning", Code: "segmented_download_degraded", Repository: repository, Digest: digest, Message: "temporary segmented storage failed; continued as a single resumable stream"})
		},
	}
	var group sync.WaitGroup
	for index := range segments {
		ready[index] = make(chan error, 1)
		group.Add(1)
		go func(index int) {
			defer group.Done()
			err := router.downloadSegment(downloadContext, repository, digest, size, &segments[index], directory)
			if err != nil {
				cancel()
			}
			ready[index] <- err
			close(ready[index])
		}(index)
	}
	go func() {
		group.Wait()
		close(done)
	}()
	return reader, nil
}

func (router *Router) downloadSegment(ctx context.Context, repository, digest string, size int64, target *segment, directory string) error {
	rangeHeader := fmt.Sprintf("bytes=%d-%d", target.physicalStart, target.end)
	blob, err := router.openBlob(ctx, repository, digest, rangeHeader)
	if err != nil {
		return err
	}
	defer blob.Reader.Close()
	if blob.Size != size || blob.Start != target.physicalStart || blob.End != target.end {
		return errors.New("Provider returned an unexpected segment range")
	}
	file, err := os.CreateTemp(directory, ".drg-segment-*")
	if err != nil {
		return segmentStorageError{err}
	}
	target.path = file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(target.path)
		return segmentStorageError{err}
	}
	expected := target.end - target.physicalStart + 1
	count, copyErr := io.Copy(file, io.LimitReader(blob.Reader, expected))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || count != expected {
		_ = os.Remove(target.path)
		if copyErr != nil {
			return segmentStorageError{copyErr}
		}
		if closeErr != nil {
			return segmentStorageError{closeErr}
		}
		return segmentStorageError{io.ErrUnexpectedEOF}
	}
	return nil
}

func verifySegmentOverlap(leftSegment, rightSegment segment) error {
	overlap := rightSegment.start - rightSegment.physicalStart
	if overlap == 0 {
		return nil
	}
	left, err := os.Open(leftSegment.path)
	if err != nil {
		return err
	}
	right, openErr := os.Open(rightSegment.path)
	if openErr != nil {
		_ = left.Close()
		return openErr
	}
	leftOffset := rightSegment.physicalStart - leftSegment.physicalStart
	err = compareRanges(left, leftOffset, right, 0, overlap)
	leftCloseErr := left.Close()
	rightCloseErr := right.Close()
	if err != nil {
		return err
	}
	if leftCloseErr != nil {
		return leftCloseErr
	}
	return rightCloseErr
}

func compareRanges(left *os.File, leftOffset int64, right *os.File, rightOffset int64, length int64) error {
	leftBuffer := make([]byte, 32<<10)
	rightBuffer := make([]byte, len(leftBuffer))
	for length > 0 {
		chunk := int64(len(leftBuffer))
		if chunk > length {
			chunk = length
		}
		if _, err := left.ReadAt(leftBuffer[:chunk], leftOffset); err != nil {
			return err
		}
		if _, err := right.ReadAt(rightBuffer[:chunk], rightOffset); err != nil {
			return err
		}
		for index := int64(0); index < chunk; index++ {
			if leftBuffer[index] != rightBuffer[index] {
				return errors.New("Provider segment overlap does not match")
			}
		}
		leftOffset += chunk
		rightOffset += chunk
		length -= chunk
	}
	return nil
}

type segmentedReader struct {
	ctx             context.Context
	segments        []segment
	ready           []chan error
	done            <-chan struct{}
	cancel          context.CancelFunc
	current         int
	file            *os.File
	remaining       int64
	release         func()
	fallbackOpen    func(int64) (registry.Blob, error)
	onFallback      func()
	fallback        io.ReadCloser
	delivered       int64
	pendingFallback error
	digest          string
	size            int64
	once            sync.Once
}

type segmentStorageError struct{ err error }

func (err segmentStorageError) Error() string { return err.err.Error() }
func (err segmentStorageError) Unwrap() error { return err.err }

func (reader *segmentedReader) Read(buffer []byte) (int, error) {
	if reader.fallback != nil {
		return reader.readFallback(buffer)
	}
	if reader.pendingFallback != nil {
		cause := reader.pendingFallback
		reader.pendingFallback = nil
		return reader.startFallback(buffer, cause)
	}
	for {
		if reader.current >= len(reader.segments) {
			reader.cleanup()
			return 0, io.EOF
		}
		if reader.file == nil {
			if err := <-reader.ready[reader.current]; err != nil {
				if reader.shouldFallback(err) {
					return reader.startFallback(buffer, err)
				}
				reader.cleanup()
				return 0, err
			}
			segment := reader.segments[reader.current]
			if reader.current > 0 {
				if err := verifySegmentOverlap(reader.segments[reader.current-1], segment); err != nil {
					if reader.shouldFallback(err) {
						return reader.startFallback(buffer, err)
					}
					reader.cleanup()
					return 0, err
				}
			}
			file, err := os.Open(segment.path)
			if err != nil {
				if reader.shouldFallback(err) {
					return reader.startFallback(buffer, err)
				}
				reader.cleanup()
				return 0, err
			}
			if _, err := file.Seek(segment.start-segment.physicalStart, io.SeekStart); err != nil {
				_ = file.Close()
				if reader.shouldFallback(err) {
					return reader.startFallback(buffer, err)
				}
				reader.cleanup()
				return 0, err
			}
			reader.file = file
			reader.remaining = segment.end - segment.start + 1
		}
		if reader.remaining == 0 {
			reader.closeCurrent()
			reader.current++
			continue
		}
		limit := len(buffer)
		if int64(limit) > reader.remaining {
			limit = int(reader.remaining)
		}
		count, err := reader.file.Read(buffer[:limit])
		reader.remaining -= int64(count)
		reader.delivered += int64(count)
		if err != nil && !errors.Is(err, io.EOF) {
			if reader.shouldFallback(err) {
				if count > 0 {
					reader.pendingFallback = err
					return count, nil
				}
				return reader.startFallback(buffer, err)
			}
			reader.cleanup()
			return count, err
		}
		if reader.remaining == 0 {
			reader.closeCurrent()
			reader.current++
			if count > 0 {
				return count, nil
			}
			continue
		}
		if count > 0 {
			return count, nil
		}
		if reader.shouldFallback(io.ErrUnexpectedEOF) {
			return reader.startFallback(buffer, io.ErrUnexpectedEOF)
		}
		reader.cleanup()
		return 0, io.ErrUnexpectedEOF
	}
}

func (reader *segmentedReader) shouldFallback(err error) bool {
	if reader == nil || reader.fallbackOpen == nil || reader.ctx == nil || reader.ctx.Err() != nil {
		return false
	}
	var storageFailure segmentStorageError
	if errors.As(err, &storageFailure) {
		return true
	}
	var pathFailure *os.PathError
	return errors.As(err, &pathFailure)
}

func (reader *segmentedReader) startFallback(buffer []byte, cause error) (int, error) {
	reader.cleanup()
	blob, err := reader.fallbackOpen(reader.delivered)
	if err != nil || !validResumedBlob(blob, reader.digest, reader.delivered, reader.size-1, reader.size) {
		if blob.Reader != nil {
			_ = blob.Reader.Close()
		}
		return 0, fmt.Errorf("segmented download storage failure and single-stream fallback failed: %w", cause)
	}
	reader.fallback = blob.Reader
	if reader.onFallback != nil {
		reader.onFallback()
	}
	return reader.readFallback(buffer)
}

func (reader *segmentedReader) readFallback(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	count, err := reader.fallback.Read(buffer)
	reader.delivered += int64(count)
	if err != nil && !errors.Is(err, io.EOF) {
		return count, err
	}
	return count, err
}

func (reader *segmentedReader) Close() error {
	reader.cleanup()
	if reader.fallback != nil {
		return reader.fallback.Close()
	}
	return nil
}

func (reader *segmentedReader) closeCurrent() {
	if reader.file != nil {
		_ = reader.file.Close()
		reader.file = nil
	}
}

func (reader *segmentedReader) cleanup() {
	reader.once.Do(func() {
		if reader.cancel != nil {
			reader.cancel()
		}
		if reader.done != nil {
			<-reader.done
		}
		reader.closeCurrent()
		removeSegments(reader.segments)
		if reader.release != nil {
			reader.release()
		}
	})
}

func removeSegments(segments []segment) {
	for _, segment := range segments {
		if segment.path != "" {
			_ = os.Remove(segment.path)
		}
	}
}
