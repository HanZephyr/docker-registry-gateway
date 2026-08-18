package registry

import (
	"errors"
	"fmt"
	"time"
)

// FailureKind preserves an upstream condition that affects routing without
// exposing Provider headers, credentials, or response bodies downstream.
type FailureKind string

const (
	FailureRateLimited    FailureKind = "rate_limited"
	FailureAuthentication FailureKind = "authentication"
	FailureIntegrity      FailureKind = "integrity"
	FailureRoutingLoop    FailureKind = "routing_loop"
)

// Failure is a temporary upstream condition. It unwraps to ErrUnavailable so
// existing Backend callers retain their simple availability contract.
type Failure struct {
	Kind       FailureKind
	RetryAfter time.Duration
	Cause      error
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "registry temporary failure"
	}
	if failure.Cause != nil {
		return fmt.Sprintf("registry %s failure: %v", failure.Kind, failure.Cause)
	}
	return fmt.Sprintf("registry %s failure", failure.Kind)
}

func (failure *Failure) Unwrap() error { return ErrUnavailable }

// NewFailure returns a typed temporary error. Negative retry durations are
// normalized because they are not meaningful to a downstream Docker client.
func NewFailure(kind FailureKind, retryAfter time.Duration, cause error) error {
	if retryAfter < 0 {
		retryAfter = 0
	}
	return &Failure{Kind: kind, RetryAfter: retryAfter, Cause: cause}
}

// IsFailureKind reports whether err contains the requested routing condition.
func IsFailureKind(err error, kind FailureKind) bool {
	var failure *Failure
	return errors.As(err, &failure) && failure.Kind == kind
}

// RetryAfter returns a typed failure's non-negative retry hint, if any.
func RetryAfter(err error) time.Duration {
	var failure *Failure
	if errors.As(err, &failure) && failure.RetryAfter > 0 {
		return failure.RetryAfter
	}
	return 0
}
