package router

import (
	"sort"
	"sync"
	"time"
)

// Health keeps process-local, recent transfer quality for Provider ordering.
// It is intentionally advisory: all Providers remain eligible until a real
// request proves otherwise, and static priority breaks cold-start ties.
type Health struct {
	mu     sync.RWMutex
	states map[string]healthState
}

type healthState struct {
	throughputBytesPerSecond float64
	hasThroughput            bool
	failures                 int
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
	health.states[provider] = state
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
	health.states[provider] = state
}

func (health *Health) orderedPullSourceIndexes(sources []Source) []int {
	indexes := make([]int, 0, len(sources))
	for index, source := range sources {
		if source.PullProvider && source.Backend != nil {
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
		if leftState.hasThroughput && leftState.throughputBytesPerSecond != rightState.throughputBytesPerSecond {
			return leftState.throughputBytesPerSecond > rightState.throughputBytesPerSecond
		}
		return configuredSourcePrecedes(leftSource, rightSource, indexes[left], indexes[right])
	})
	return indexes
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
