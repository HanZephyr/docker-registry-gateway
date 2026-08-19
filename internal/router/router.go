// Package router selects trusted Provider results for one downstream pull.
package router

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/lease"
	"github.com/hjx/docker-registry-gateway/internal/registry"
)

const (
	defaultStallTimeout       = 15 * time.Second
	speedSwitchAfterBytes     = 1 << 20
	speedSwitchAfterDuration  = time.Second
	speedSwitchImprovementMin = 1.5
)

var errProviderStalled = errors.New("provider stream made no progress")
var errProviderSlow = errors.New("provider stream is materially slower than a known alternative")

// Source binds Provider roles to a Registry content backend.
type Source struct {
	Name         string
	Resolver     bool
	PullProvider bool
	Priority     *int
	Backend      registry.Backend
}

// Event is a non-secret routing observation for the local event log. It never
// contains credentials, headers, or Provider redirect URLs.
type Event struct {
	Level        string
	Code         string
	Provider     string
	Repository   string
	Reference    string
	Digest       string
	ResumeOffset *int64
	Message      string
}

// Observer receives routing events synchronously. Callers should make the
// implementation bounded and non-blocking enough for a pull hot path.
type Observer interface{ Observe(Event) }

// ObserverFunc adapts a function into a routing Event observer.
type ObserverFunc func(Event)

func (function ObserverFunc) Observe(event Event) { function(event) }

// Options controls deterministic conflict selection.
type Options struct {
	ConflictStrategy         string
	TieBreaker               string
	Salt                     []byte
	Health                   *Health
	MaxSegmentsPerBlob       int
	MinSegmentSize           int64
	TemporaryDir             string
	TempBudget               *TempBudget
	NoRangeRestartEnabled    *bool
	MaxNoRangeRestartDiscard int64
	DecisionLease            time.Duration
	LeaseStore               *lease.Store
	Observer                 Observer
	StallTimeout             time.Duration
}

// Router implements the downstream Registry backend using multiple Providers.
type Router struct {
	sources                  []Source
	conflictStrategy         string
	tieBreaker               string
	salt                     []byte
	noRangeRestartEnabled    bool
	maxNoRangeRestartDiscard int64
	decisionLease            time.Duration
	leaseStore               *lease.Store
	health                   *Health
	maxSegmentsPerBlob       int
	minSegmentSize           int64
	temporaryDir             string
	tempBudget               *TempBudget
	observer                 Observer
	stallTimeout             time.Duration
}

// New creates a Router. Configuration validation guarantees sources contain
// the required roles; this constructor remains safe for incomplete input.
func New(sources []Source, options Options) *Router {
	conflictStrategy := options.ConflictStrategy
	if conflictStrategy == "" {
		conflictStrategy = "majority"
	}
	tieBreaker := options.TieBreaker
	if tieBreaker == "" {
		tieBreaker = "rendezvous_hash"
	}
	noRangeRestartEnabled := true
	if options.NoRangeRestartEnabled != nil {
		noRangeRestartEnabled = *options.NoRangeRestartEnabled
	}
	maxNoRangeRestartDiscard := options.MaxNoRangeRestartDiscard
	if maxNoRangeRestartDiscard == 0 {
		maxNoRangeRestartDiscard = 64 << 20
	}
	health := options.Health
	if health == nil {
		health = NewHealth()
	}
	maxSegments := options.MaxSegmentsPerBlob
	if maxSegments < 1 {
		maxSegments = 1
	}
	stallTimeout := options.StallTimeout
	if stallTimeout <= 0 {
		stallTimeout = defaultStallTimeout
	}
	return &Router{
		sources:                  append([]Source(nil), sources...),
		conflictStrategy:         conflictStrategy,
		tieBreaker:               tieBreaker,
		salt:                     append([]byte(nil), options.Salt...),
		noRangeRestartEnabled:    noRangeRestartEnabled,
		maxNoRangeRestartDiscard: maxNoRangeRestartDiscard,
		decisionLease:            options.DecisionLease,
		leaseStore:               options.LeaseStore,
		health:                   health,
		maxSegmentsPerBlob:       maxSegments,
		minSegmentSize:           options.MinSegmentSize,
		temporaryDir:             options.TemporaryDir,
		tempBudget:               options.TempBudget,
		observer:                 options.Observer,
		stallTimeout:             stallTimeout,
	}
}

// Manifest resolves a mutable reference once per lease, then always serves the
// selected immutable digest through a Pull Provider. Digest references bypass
// Resolver voting entirely.
func (router *Router) Manifest(ctx context.Context, repository, reference string, accepts []string) (registry.Manifest, error) {
	if isDigestReference(reference) {
		return router.pullManifest(ctx, repository, reference, accepts)
	}
	key := leaseKey(repository, reference, accepts)
	if router.leaseStore != nil && router.decisionLease > 0 {
		if digest, found, err := router.leaseStore.Get(key, time.Now()); err == nil && found {
			router.emit(Event{Level: "info", Code: "decision_lease_used", Repository: repository, Reference: reference, Digest: digest, Message: "reused the existing resolver decision lease"})
			return router.pullManifest(ctx, repository, digest, accepts)
		}
	}
	selection, err := router.resolveManifest(ctx, repository, reference, accepts)
	if err != nil {
		return registry.Manifest{}, err
	}
	manifest, err := router.pullManifest(ctx, repository, selection.Digest, accepts)
	if err != nil {
		return registry.Manifest{}, err
	}
	manifest.Notice = selection.Notice
	if router.leaseStore != nil && router.decisionLease > 0 {
		// A disk error must not turn a successful pull into an unavailable
		// response. The current process still has the selected immutable
		// result and a later resolution can recover persistence.
		_ = router.leaseStore.Put(key, selection.Digest, time.Now().Add(router.decisionLease))
	}
	return manifest, nil
}

// resolveManifest concurrently asks resolver Sources and selects a digest.
func (router *Router) resolveManifest(ctx context.Context, repository, reference string, accepts []string) (registry.Manifest, error) {
	type result struct {
		index    int
		manifest registry.Manifest
		err      error
	}

	var resolvers []int
	for index, source := range router.sources {
		if source.Resolver && source.Backend != nil && router.health.available(source.Name, time.Now()) {
			resolvers = append(resolvers, index)
		}
	}
	if len(resolvers) == 0 {
		return registry.Manifest{}, router.health.unavailableError(router.sources, true)
	}

	results := make(chan result, len(resolvers))
	var group sync.WaitGroup
	for _, index := range resolvers {
		source := router.sources[index]
		group.Add(1)
		go func(index int, source Source) {
			defer group.Done()
			manifest, err := source.Backend.Manifest(ctx, repository, reference, accepts)
			results <- result{index: index, manifest: manifest, err: err}
		}(index, source)
	}
	group.Wait()
	close(results)

	candidates := make(map[string]*candidate)
	var successful int
	allNotFound := true
	for result := range results {
		if result.err != nil || result.manifest.Digest == "" {
			if result.err != nil {
				router.recordSourceFailure(router.sources[result.index].Name, result.err)
			}
			if !errors.Is(result.err, registry.ErrNotFound) {
				allNotFound = false
			}
			continue
		}
		successful++
		allNotFound = false
		entry := candidates[result.manifest.Digest]
		if entry == nil {
			entry = &candidate{manifest: result.manifest}
			candidates[result.manifest.Digest] = entry
		}
		entry.indexes = append(entry.indexes, result.index)
	}
	if successful == 0 {
		if allNotFound {
			return registry.Manifest{}, registry.ErrNotFound
		}
		return registry.Manifest{}, registry.ErrUnavailable
	}

	ordered := make([]*candidate, 0, len(candidates))
	for _, candidate := range candidates {
		sort.Ints(candidate.indexes)
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if len(ordered[left].indexes) != len(ordered[right].indexes) {
			return len(ordered[left].indexes) > len(ordered[right].indexes)
		}
		return ordered[left].manifest.Digest < ordered[right].manifest.Digest
	})
	if len(ordered) > 1 {
		router.emit(Event{
			Level:      "warning",
			Code:       "resolver_conflict",
			Repository: repository,
			Reference:  reference,
			Message:    fmt.Sprintf("%d resolvers returned %d different manifest digests", successful, len(ordered)),
		})
	}
	var selected registry.Manifest
	if router.conflictStrategy == "provider_priority" {
		manifest, found := router.byProviderPriority(ordered)
		if !found {
			return registry.Manifest{}, registry.ErrUnavailable
		}
		selected = manifest
	} else if len(ordered[0].indexes) > successful/2 {
		selected = ordered[0].manifest
	} else {
		manifest, err := router.breakTie(repository, reference, accepts, ordered)
		if err != nil {
			return registry.Manifest{}, err
		}
		selected = manifest
	}
	if len(ordered) > 1 {
		selected.Notice = fmt.Sprintf("DRG resolver conflict selected %s using %s", selected.Digest, router.conflictStrategy)
	}
	router.emit(Event{
		Level:      "info",
		Code:       "resolution_selected",
		Repository: repository,
		Reference:  reference,
		Digest:     selected.Digest,
		Message:    "resolver decision selected an immutable manifest digest",
	})
	return selected, nil
}

func (router *Router) pullManifest(ctx context.Context, repository, digest string, accepts []string) (registry.Manifest, error) {
	for _, index := range router.health.orderedPullSourceIndexes(router.sources) {
		source := router.sources[index]
		manifest, err := source.Backend.Manifest(ctx, repository, digest, accepts)
		if err != nil {
			router.recordSourceFailure(source.Name, err)
			continue
		}
		if strings.EqualFold(manifest.Digest, digest) && manifest.MediaType != "" {
			router.emit(Event{Level: "info", Code: "manifest_source_selected", Provider: source.Name, Repository: repository, Digest: digest, Message: "pull provider returned the selected immutable manifest"})
			return manifest, nil
		}
	}
	return registry.Manifest{}, router.health.unavailableError(router.sources, false)
}

func isDigestReference(reference string) bool {
	return strings.Contains(strings.TrimSpace(reference), ":")
}

func leaseKey(repository, reference string, accepts []string) string {
	unique := make(map[string]struct{}, len(accepts))
	for _, accept := range accepts {
		value := strings.TrimSpace(accept)
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	canonicalAccepts := make([]string, 0, len(unique))
	for accept := range unique {
		canonicalAccepts = append(canonicalAccepts, accept)
	}
	sort.Strings(canonicalAccepts)
	return strings.Join([]string{repository, reference, strings.Join(canonicalAccepts, "\x1f")}, "\x00")
}

func (router *Router) byProviderPriority(candidates []*candidate) (registry.Manifest, bool) {
	var selected *candidate
	var selectedPriority int
	var selectedIndex int
	for _, candidate := range candidates {
		for _, index := range candidate.indexes {
			priority := router.sources[index].Priority
			if priority == nil {
				continue
			}
			if selected == nil || *priority < selectedPriority || (*priority == selectedPriority && index < selectedIndex) {
				selected = candidate
				selectedPriority = *priority
				selectedIndex = index
			}
		}
	}
	if selected == nil {
		return registry.Manifest{}, false
	}
	return selected.manifest, true
}

func (router *Router) breakTie(repository, reference string, accepts []string, candidates []*candidate) (registry.Manifest, error) {
	switch router.tieBreaker {
	case "fail":
		return registry.Manifest{}, registry.ErrUnavailable
	case "configured_order":
		sort.Slice(candidates, func(left, right int) bool {
			return candidates[left].indexes[0] < candidates[right].indexes[0]
		})
		return candidates[0].manifest, nil
	default:
		best := candidates[0]
		bestScore := rendezvousScore(router.salt, repository, reference, accepts, best.manifest.Digest)
		for _, candidate := range candidates[1:] {
			score := rendezvousScore(router.salt, repository, reference, accepts, candidate.manifest.Digest)
			if strings.Compare(score, bestScore) > 0 {
				best, bestScore = candidate, score
			}
		}
		return best.manifest, nil
	}
}

// Blob opens a Pull Provider in configured order. If the selected stream ends
// prematurely, its reader resumes from an untried Provider with a Range that
// starts exactly after the bytes already delivered downstream.
func (router *Router) Blob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	router.health.RecordPullActivity()
	if rangeHeader == "" {
		if blob, segmented := router.trySegmentedBlob(ctx, repository, digest); segmented {
			return blob, nil
		}
	}
	return router.openBlob(ctx, repository, digest, rangeHeader)
}

func (router *Router) openBlob(ctx context.Context, repository, digest, rangeHeader string) (registry.Blob, error) {
	allNotFound := true
	attempted := make(map[int]bool)
	attemptedSource := false
	for _, index := range router.health.orderedPullSourceIndexes(router.sources) {
		attemptedSource = true
		source := router.sources[index]
		attemptContext, cancel := context.WithCancel(ctx)
		startedAttempt := time.Now()
		blob, err := source.Backend.Blob(attemptContext, repository, digest, rangeHeader)
		if err == nil {
			router.health.RecordFirstByte(source.Name, time.Since(startedAttempt))
			if !validInitialBlob(blob, digest) {
				if blob.Reader != nil {
					_ = blob.Reader.Close()
				}
				cancel()
				router.recordSourceFailure(source.Name, registry.NewFailure(registry.FailureIntegrity, 0, errors.New("invalid initial blob metadata")))
				allNotFound = false
				continue
			}
			attempted[index] = true
			blob.Reader = &resumableBlobReader{
				ctx:           ctx,
				router:        router,
				repository:    repository,
				digest:        digest,
				current:       blob.Reader,
				currentCancel: cancel,
				currentAt:     index,
				currentName:   source.Name,
				startedAt:     time.Now(),
				attempted:     attempted,
				offset:        blob.Start,
				end:           blob.End,
				size:          blob.Size,
			}
			router.emit(Event{Level: "info", Code: "blob_source_selected", Provider: source.Name, Repository: repository, Digest: digest, Message: "pull provider opened a blob stream"})
			return blob, nil
		}
		cancel()
		router.recordSourceFailure(source.Name, err)
		if !errors.Is(err, registry.ErrNotFound) {
			allNotFound = false
		}
	}
	if !attemptedSource {
		return registry.Blob{}, router.health.unavailableError(router.sources, false)
	}
	if allNotFound {
		return registry.Blob{}, registry.ErrNotFound
	}
	return registry.Blob{}, router.health.unavailableError(router.sources, false)
}

type resumableBlobReader struct {
	ctx        context.Context
	router     *Router
	repository string
	digest     string

	current       io.ReadCloser
	currentCancel context.CancelFunc
	currentAt     int
	currentName   string
	startedAt     time.Time
	transferBytes int64
	recorded      bool
	attempted     map[int]bool
	offset        int64
	end           int64
	size          int64
	pending       error
}

func (reader *resumableBlobReader) Read(buffer []byte) (int, error) {
	if reader.pending != nil {
		pending := reader.pending
		reader.pending = nil
		return reader.resume(buffer, pending)
	}
	canSwitch := reader.hasUntriedPullSource()
	stalled := make(chan struct{}, 1)
	var timer *time.Timer
	cancelCurrent := reader.currentCancel
	if canSwitch && cancelCurrent != nil && reader.router.stallTimeout > 0 {
		timer = time.AfterFunc(reader.router.stallTimeout, func() {
			cancelCurrent()
			stalled <- struct{}{}
		})
	}
	count, err := reader.current.Read(buffer)
	if timer != nil {
		timer.Stop()
	}
	wasStalled := false
	select {
	case <-stalled:
		wasStalled = true
	default:
	}
	reader.offset += int64(count)
	reader.transferBytes += int64(count)
	if reader.offset > reader.end+1 {
		reader.recordFailure()
		return count, io.ErrUnexpectedEOF
	}
	if reader.offset == reader.end+1 {
		reader.recordSuccess()
		if err != nil && !errors.Is(err, io.EOF) {
			return count, io.EOF
		}
		return count, err
	}
	if count > 0 {
		if wasStalled {
			reader.pending = errProviderStalled
		} else if err != nil {
			reader.pending = err
		} else if reader.shouldSwitchForSpeed() {
			reader.pending = errProviderSlow
		}
		return count, nil
	}
	if wasStalled {
		return reader.resume(buffer, errProviderStalled)
	}
	if err == nil {
		return 0, nil
	}
	return reader.resume(buffer, err)
}

func (reader *resumableBlobReader) resume(buffer []byte, cause error) (int, error) {
	_ = reader.current.Close()
	if reader.currentCancel != nil {
		reader.currentCancel()
		reader.currentCancel = nil
	}
	if !errors.Is(cause, errProviderStalled) && !errors.Is(cause, errProviderSlow) {
		reader.recordFailure()
	}
	for _, index := range reader.router.health.orderedPullSourceIndexes(reader.router.sources) {
		source := reader.router.sources[index]
		if reader.attempted[index] {
			continue
		}
		reader.attempted[index] = true
		rangeHeader := fmt.Sprintf("bytes=%d-%d", reader.offset, reader.end)
		attemptContext, cancel := context.WithCancel(reader.ctx)
		startedAttempt := time.Now()
		blob, err := source.Backend.Blob(attemptContext, reader.repository, reader.digest, rangeHeader)
		if err == nil && validResumedBlob(blob, reader.digest, reader.offset, reader.end, reader.size) {
			reader.router.health.RecordFirstByte(source.Name, time.Since(startedAttempt))
			previous := reader.currentName
			reader.current = blob.Reader
			reader.currentCancel = cancel
			reader.currentAt = index
			reader.currentName = source.Name
			reader.startedAt = time.Now()
			reader.transferBytes = 0
			reader.recorded = false
			reason := fmt.Sprintf("resumed interrupted blob stream after switching from %s", previous)
			switch {
			case errors.Is(cause, errProviderStalled):
				reason = fmt.Sprintf("switched from %s after it made no progress", previous)
			case errors.Is(cause, errProviderSlow):
				reason = fmt.Sprintf("switched from %s because an available Provider had materially better recent throughput", previous)
			}
			resumeOffset := reader.offset
			reader.router.emit(Event{Level: "warning", Code: "blob_source_switched", Provider: source.Name, Repository: reader.repository, Digest: reader.digest, ResumeOffset: &resumeOffset, Message: reason})
			return reader.Read(buffer)
		}
		if blob.Reader != nil {
			_ = blob.Reader.Close()
		}
		cancel()
		if reader.router.noRangeRestartEnabled && reader.offset <= reader.router.maxNoRangeRestartDiscard {
			restartContext, restartCancel := context.WithCancel(reader.ctx)
			startedRestart := time.Now()
			if restarted, restartedErr := source.Backend.Blob(restartContext, reader.repository, reader.digest, ""); restartedErr == nil {
				if validRestartedBlob(restarted, reader.digest, reader.size) {
					reader.router.health.RecordFirstByte(source.Name, time.Since(startedRestart))
					if _, discardErr := io.CopyN(io.Discard, restarted.Reader, reader.offset); discardErr == nil {
						reader.current = restarted.Reader
						reader.currentCancel = restartCancel
						reader.currentAt = index
						reader.currentName = source.Name
						reader.startedAt = time.Now()
						reader.transferBytes = 0
						reader.recorded = false
						reader.router.emit(Event{Level: "warning", Code: "blob_source_restarted_no_range", Provider: source.Name, Repository: reader.repository, Digest: reader.digest, Message: "resumed by restarting a non-Range provider and discarding the already delivered prefix"})
						return reader.Read(buffer)
					}
				}
				if restarted.Reader != nil {
					_ = restarted.Reader.Close()
				}
			}
			restartCancel()
		}
		reader.router.recordSourceFailure(source.Name, err)
	}
	if errors.Is(cause, io.EOF) {
		return 0, io.ErrUnexpectedEOF
	}
	return 0, cause
}

func (router *Router) recordSourceFailure(provider string, err error) {
	if errors.Is(err, registry.ErrNotFound) {
		router.emit(Event{Level: "info", Code: "provider_content_not_found", Provider: provider, Message: "provider does not currently contain the requested immutable content"})
		return
	}
	switch {
	case registry.IsFailureKind(err, registry.FailureRateLimited):
		router.health.RecordProviderFailure(provider, err)
		router.emit(Event{Level: "warning", Code: "provider_rate_limited", Provider: provider, Message: "provider entered its upstream rate-limit cooldown"})
	case registry.IsFailureKind(err, registry.FailureAuthentication):
		router.health.RecordProviderFailure(provider, err)
		router.emit(Event{Level: "error", Code: "provider_authentication_invalid", Provider: provider, Message: "provider authentication failed after one token refresh"})
	case registry.IsFailureKind(err, registry.FailureIntegrity):
		router.health.RecordProviderFailure(provider, err)
		router.emit(Event{Level: "error", Code: "provider_integrity_isolated", Provider: provider, Message: "provider content or metadata disagreed with the selected digest and was isolated"})
	default:
		router.health.RecordProviderFailure(provider, err)
		router.emit(Event{Level: "warning", Code: "provider_unavailable", Provider: provider, Message: "provider request failed temporarily"})
	}
}

func (router *Router) emit(event Event) {
	if router == nil || router.observer == nil {
		return
	}
	router.observer.Observe(event)
}

func (reader *resumableBlobReader) recordSuccess() {
	if reader.recorded {
		return
	}
	reader.recorded = true
	reader.router.health.RecordSuccess(reader.currentName, reader.transferBytes, time.Since(reader.startedAt))
}

func (reader *resumableBlobReader) recordFailure() {
	if reader.recorded {
		return
	}
	reader.recorded = true
	reader.router.health.RecordFailure(reader.currentName)
}

func (reader *resumableBlobReader) hasUntriedPullSource() bool {
	for _, index := range reader.router.health.orderedPullSourceIndexes(reader.router.sources) {
		if !reader.attempted[index] {
			return true
		}
	}
	return false
}

func (reader *resumableBlobReader) shouldSwitchForSpeed() bool {
	elapsed := time.Since(reader.startedAt)
	if reader.transferBytes < speedSwitchAfterBytes || elapsed < speedSwitchAfterDuration {
		return false
	}
	currentRate := float64(reader.transferBytes) / elapsed.Seconds()
	return reader.router.health.hasClearlyBetterPullSource(reader.router.sources, reader.currentName, reader.attempted, currentRate)
}

func (reader *resumableBlobReader) Close() error {
	if reader.currentCancel != nil {
		reader.currentCancel()
		reader.currentCancel = nil
	}
	if reader.current == nil {
		return nil
	}
	return reader.current.Close()
}

func validInitialBlob(blob registry.Blob, requestedDigest string) bool {
	return blob.Reader != nil && strings.EqualFold(blob.Digest, requestedDigest) && blob.Size > 0 && blob.Start >= 0 && blob.End >= blob.Start && blob.End < blob.Size
}

func validResumedBlob(blob registry.Blob, requestedDigest string, start, end, size int64) bool {
	return validInitialBlob(blob, requestedDigest) && blob.Size == size && blob.Start == start && blob.End == end
}

func validRestartedBlob(blob registry.Blob, requestedDigest string, size int64) bool {
	return validInitialBlob(blob, requestedDigest) && blob.Size == size && blob.Start == 0 && blob.End == size-1
}

type candidate struct {
	manifest registry.Manifest
	indexes  []int
}

func rendezvousScore(salt []byte, repository, reference string, accepts []string, digest string) string {
	key := strings.Join([]string{string(salt), repository, reference, strings.Join(accepts, ","), digest}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return string(sum[:])
}
