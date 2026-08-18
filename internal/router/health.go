package router

import (
	"sort"
	"sync"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/registry"
)

const defaultRateLimitCooldown = time.Minute

// Health keeps process-local, recent transfer quality for Provider ordering.
// It is intentionally advisory: all Providers remain eligible until a real
// request proves otherwise, and static priority breaks cold-start ties.
type Health struct {
	mu               sync.RWMutex
	states           map[string]healthState
	lastPullActivity time.Time
}

type healthState struct {
	throughputBytesPerSecond float64
	hasThroughput            bool
	firstByte                time.Duration
	hasFirstByte             bool
	failures                 int
	lastSuccess              time.Time
	lastFailure              time.Time
	rateLimitedUntil         time.Time
	authenticationInvalid    bool
	integrityInvalid         bool
	rangeUnsupported         bool
}

// HealthSnapshot is the non-secret portion of Provider transfer history. A
// restored snapshot deliberately excludes failure counts so a process restart
// begins with fresh availability checks rather than inheriting a stale fault.
type HealthSnapshot struct {
	Provider                 string
	ThroughputBytesPerSecond float64
	FirstByte                time.Duration
	Failures                 int
	LastSuccess              time.Time
	LastFailure              time.Time
	RateLimitedUntil         time.Time
	AuthenticationInvalid    bool
	IntegrityInvalid         bool
	RangeUnsupported         bool
}

// NewHealth creates an empty tracker with no artificial preference.
func NewHealth() *Health {
	return &Health{states: make(map[string]healthState)}
}

// RecordSuccess incorporates an observed completed transfer using an EWMA so
// a single unusually fast or slow layer does not permanently dominate routing.
func (health *Health) RecordSuccess(provider string, bytes int64, elapsed time.Duration) {
	if health == nil || provider == "" || bytes <= 0 || elapsed <= 0 {
		return
	}
	rate := float64(bytes) / elapsed.Seconds()
	health.mu.Lock()
	defer health.mu.Unlock()
	state := health.states[provider]
	if state.hasThroughput {
		state.throughputBytesPerSecond = state.throughputBytesPerSecond*0.7 + rate*0.3
	} else {
		state.throughputBytesPerSecond = rate
		state.hasThroughput = true
	}
	state.failures = 0
	state.lastSuccess = time.Now().UTC()
	state.rateLimitedUntil = time.Time{}
	state.authenticationInvalid = false
	state.integrityInvalid = false
	state.rangeUnsupported = false
	health.states[provider] = state
}

// RecordFirstByte incorporates the latency to receive an upstream response's
// first byte or headers. It is intentionally measured from real transfers,
// not a user-configured synthetic timeout.
func (health *Health) RecordFirstByte(provider string, elapsed time.Duration) {
	if health == nil || provider == "" || elapsed <= 0 {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	health.lastPullActivity = time.Now().UTC()
	state := health.states[provider]
	if state.hasFirstByte {
		state.firstByte = time.Duration(float64(state.firstByte)*0.7 + float64(elapsed)*0.3)
	} else {
		state.firstByte = elapsed
		state.hasFirstByte = true
	}
	health.states[provider] = state
}

// RecordPullActivity marks a real downstream blob request. Provider probes do
// not call this method, which lets the process distinguish user traffic from
// maintenance traffic when deciding whether an active probe may run.
func (health *Health) RecordPullActivity() {
	if health == nil {
		return
	}
	health.mu.Lock()
	health.lastPullActivity = time.Now().UTC()
	health.mu.Unlock()
}

// HasRecentPullActivity reports whether a real downstream pull was observed
// during the supplied quiet period.
func (health *Health) HasRecentPullActivity(quietPeriod time.Duration) bool {
	if health == nil || quietPeriod <= 0 {
		return false
	}
	health.mu.RLock()
	last := health.lastPullActivity
	health.mu.RUnlock()
	return !last.IsZero() && last.After(time.Now().UTC().Add(-quietPeriod))
}

// RecordFailure lowers the Provider before later requests try it again.
func (health *Health) RecordFailure(provider string) {
	if health == nil || provider == "" {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	state := health.states[provider]
	state.failures++
	state.lastFailure = time.Now().UTC()
	health.states[provider] = state
}

// RecordRateLimited holds a Provider out of selection until the upstream's
// retry window has passed. A missing upstream hint gets a conservative,
// internal cooldown rather than a user-tunable download timeout.
func (health *Health) RecordRateLimited(provider string, retryAfter time.Duration) {
	if health == nil || provider == "" {
		return
	}
	if retryAfter <= 0 {
		retryAfter = defaultRateLimitCooldown
	}
	now := time.Now().UTC()
	health.mu.Lock()
	defer health.mu.Unlock()
	state := health.states[provider]
	state.rateLimitedUntil = now.Add(retryAfter)
	state.lastFailure = now
	health.states[provider] = state
}

// RecordAuthenticationFailure removes a Provider until a reload, probe, or a
// subsequent successful transfer proves that its upstream identity recovered.
func (health *Health) RecordAuthenticationFailure(provider string) {
	health.recordUnavailable(provider, func(state *healthState) { state.authenticationInvalid = true })
}

// RecordIntegrityViolation isolates content that disagreed with its selected
// digest. It is intentionally stronger than an ordinary transient failure.
func (health *Health) RecordIntegrityViolation(provider string) {
	health.recordUnavailable(provider, func(state *healthState) { state.integrityInvalid = true })
}

// RecordRangeUnsupported removes a Provider from blob selection when the
// deployment explicitly requires resumable Range transfers. A future
// successful admission probe restores it.
func (health *Health) RecordRangeUnsupported(provider string) {
	health.recordUnavailable(provider, func(state *healthState) { state.rangeUnsupported = true })
}

// RecordProviderFailure maps a typed upstream failure to its selection
// consequence. It is shared by real transfers and active admission probes so
// an idle Provider cannot remain falsely eligible after a known auth, content
// integrity, or rate-limit failure.
func (health *Health) RecordProviderFailure(provider string, err error) {
	switch {
	case registry.IsFailureKind(err, registry.FailureRateLimited):
		health.RecordRateLimited(provider, registry.RetryAfter(err))
	case registry.IsFailureKind(err, registry.FailureAuthentication):
		health.RecordAuthenticationFailure(provider)
	case registry.IsFailureKind(err, registry.FailureIntegrity):
		health.RecordIntegrityViolation(provider)
	default:
		health.RecordFailure(provider)
	}
}

// RecordProbeSuccess restores a Provider after a fresh V2/manifest/blob
// admission probe without discarding its historical throughput observation.
func (health *Health) RecordProbeSuccess(provider string) {
	if health == nil || provider == "" {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	state := health.states[provider]
	state.rateLimitedUntil = time.Time{}
	state.authenticationInvalid = false
	state.integrityInvalid = false
	state.rangeUnsupported = false
	health.states[provider] = state
}

func (health *Health) recordUnavailable(provider string, mutate func(*healthState)) {
	if health == nil || provider == "" {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	state := health.states[provider]
	mutate(&state)
	state.lastFailure = time.Now().UTC()
	health.states[provider] = state
}

// Snapshot returns deterministic, safe-to-display transfer-health data.
func (health *Health) Snapshot() []HealthSnapshot {
	if health == nil {
		return nil
	}
	health.mu.RLock()
	defer health.mu.RUnlock()
	result := make([]HealthSnapshot, 0, len(health.states))
	for provider, state := range health.states {
		result = append(result, HealthSnapshot{
			Provider:                 provider,
			ThroughputBytesPerSecond: state.throughputBytesPerSecond,
			FirstByte:                state.firstByte,
			Failures:                 state.failures,
			LastSuccess:              state.lastSuccess,
			LastFailure:              state.lastFailure,
			RateLimitedUntil:         state.rateLimitedUntil,
			AuthenticationInvalid:    state.authenticationInvalid,
			IntegrityInvalid:         state.integrityInvalid,
			RangeUnsupported:         state.rangeUnsupported,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Provider < result[right].Provider
	})
	return result
}

// Restore reuses only historical throughput and timestamps. Failure counters
// are intentionally reset because the next fast admission probe is the source
// of truth after a process restart.
func (health *Health) Restore(snapshots []HealthSnapshot) {
	if health == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	for _, snapshot := range snapshots {
		if snapshot.Provider == "" || snapshot.ThroughputBytesPerSecond < 0 {
			continue
		}
		state := health.states[snapshot.Provider]
		if snapshot.ThroughputBytesPerSecond > 0 {
			state.throughputBytesPerSecond = snapshot.ThroughputBytesPerSecond
			state.hasThroughput = true
		}
		if snapshot.FirstByte > 0 {
			state.firstByte = snapshot.FirstByte
			state.hasFirstByte = true
		}
		state.lastSuccess = snapshot.LastSuccess.UTC()
		state.lastFailure = snapshot.LastFailure.UTC()
		state.failures = 0
		state.rateLimitedUntil = time.Time{}
		state.authenticationInvalid = false
		state.integrityInvalid = false
		state.rangeUnsupported = false
		health.states[snapshot.Provider] = state
	}
}

func (health *Health) orderedPullSourceIndexes(sources []Source) []int {
	indexes := make([]int, 0, len(sources))
	for index, source := range sources {
		if source.PullProvider && source.Backend != nil && health.available(source.Name, time.Now()) {
			indexes = append(indexes, index)
		}
	}
	health.mu.RLock()
	states := make(map[string]healthState, len(health.states))
	for name, state := range health.states {
		states[name] = state
	}
	health.mu.RUnlock()
	sort.SliceStable(indexes, func(left, right int) bool {
		leftSource, rightSource := sources[indexes[left]], sources[indexes[right]]
		leftState, rightState := states[leftSource.Name], states[rightSource.Name]
		if leftState.failures != rightState.failures {
			return leftState.failures < rightState.failures
		}
		if leftState.hasThroughput != rightState.hasThroughput {
			return leftState.hasThroughput
		}
		if leftState.hasFirstByte != rightState.hasFirstByte {
			return leftState.hasFirstByte
		}
		if leftState.hasFirstByte && leftState.firstByte != rightState.firstByte {
			return leftState.firstByte < rightState.firstByte
		}
		if leftState.hasThroughput && leftState.throughputBytesPerSecond != rightState.throughputBytesPerSecond {
			return leftState.throughputBytesPerSecond > rightState.throughputBytesPerSecond
		}
		return configuredSourcePrecedes(leftSource, rightSource, indexes[left], indexes[right])
	})
	return indexes
}

func (health *Health) available(provider string, now time.Time) bool {
	if health == nil {
		return true
	}
	health.mu.RLock()
	state := health.states[provider]
	health.mu.RUnlock()
	return !state.authenticationInvalid && !state.integrityInvalid && !state.rangeUnsupported && !state.rateLimitedUntil.After(now)
}

func (health *Health) unavailableError(sources []Source, resolver bool) error {
	if health == nil {
		return registry.ErrUnavailable
	}
	now := time.Now()
	allRateLimited := true
	hasCandidate := false
	var earliest time.Time
	health.mu.RLock()
	defer health.mu.RUnlock()
	for _, source := range sources {
		if source.Backend == nil || (resolver && !source.Resolver) || (!resolver && !source.PullProvider) {
			continue
		}
		hasCandidate = true
		state := health.states[source.Name]
		if !state.rateLimitedUntil.After(now) || state.authenticationInvalid || state.integrityInvalid || state.rangeUnsupported {
			allRateLimited = false
			continue
		}
		if earliest.IsZero() || state.rateLimitedUntil.Before(earliest) {
			earliest = state.rateLimitedUntil
		}
	}
	if hasCandidate && allRateLimited && !earliest.IsZero() {
		return registry.NewFailure(registry.FailureRateLimited, time.Until(earliest), nil)
	}
	return registry.ErrUnavailable
}

func (health *Health) hasClearlyBetterPullSource(sources []Source, current string, attempted map[int]bool, currentRate float64) bool {
	if health == nil || currentRate <= 0 {
		return false
	}
	health.mu.RLock()
	states := make(map[string]healthState, len(health.states))
	for provider, state := range health.states {
		states[provider] = state
	}
	health.mu.RUnlock()
	for _, index := range health.orderedPullSourceIndexes(sources) {
		if attempted[index] || sources[index].Name == current {
			continue
		}
		state := states[sources[index].Name]
		if state.hasThroughput && state.throughputBytesPerSecond >= currentRate*speedSwitchImprovementMin {
			return true
		}
	}
	return false
}

func configuredSourcePrecedes(left, right Source, leftIndex, rightIndex int) bool {
	if left.Priority != nil && right.Priority != nil && *left.Priority != *right.Priority {
		return *left.Priority < *right.Priority
	}
	if left.Priority != nil && right.Priority == nil {
		return true
	}
	if left.Priority == nil && right.Priority != nil {
		return false
	}
	return leftIndex < rightIndex
}
