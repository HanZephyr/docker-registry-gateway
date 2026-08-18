// Package routeguard prevents an upstream Provider route from re-entering a
// Gateway instance or traversing an unbounded Gateway chain.
package routeguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	// InstanceHeader carries the ordered, non-secret Gateway instance trace.
	InstanceHeader = "X-DRG-Instance"
	// HopHeader carries the number of Gateway hops already traversed.
	HopHeader      = "X-DRG-Hop"
	defaultMaxHops = 3
)

// ErrLoop means a request would return to a Gateway or exceed its hop budget.
var ErrLoop = errors.New("gateway routing loop detected")

// Guard validates an incoming route and prepares the next direct Provider
// request. Its zero value is disabled for embedders that do not route upstream.
type Guard struct {
	instanceID string
	maxHops    int
}

type route struct {
	instances []string
	hops      int
}

type routeKey struct{}

// New creates a guard for one stable, non-secret Gateway instance identity.
func New(instanceID string, maxHops int) Guard {
	if maxHops <= 0 {
		maxHops = defaultMaxHops
	}
	return Guard{instanceID: strings.TrimSpace(instanceID), maxHops: maxHops}
}

// Inbound rejects malformed loop-protection headers, a returned instance, or
// a route that has exhausted the hop limit. The returned Context must be used
// for downstream routing so an outbound Provider request extends this trace.
func (guard Guard) Inbound(ctx context.Context, headers http.Header) (context.Context, error) {
	if guard.instanceID == "" {
		return ctx, nil
	}
	route, err := parse(headers)
	if err != nil {
		return ctx, err
	}
	for _, instance := range route.instances {
		if instance == guard.instanceID {
			return ctx, ErrLoop
		}
	}
	if route.hops >= guard.maxHops {
		return ctx, ErrLoop
	}
	return context.WithValue(ctx, routeKey{}, route), nil
}

// Outbound writes the current instance and the next hop count to an upstream
// request. It never forwards client-controlled values that were not first
// validated by Inbound.
func (guard Guard) Outbound(ctx context.Context, headers http.Header) error {
	if guard.instanceID == "" {
		return nil
	}
	route, _ := ctx.Value(routeKey{}).(route)
	for _, instance := range route.instances {
		if instance == guard.instanceID {
			return ErrLoop
		}
	}
	if route.hops >= guard.maxHops {
		return ErrLoop
	}
	route.instances = append(route.instances, guard.instanceID)
	headers.Set(InstanceHeader, strings.Join(route.instances, ", "))
	headers.Set(HopHeader, strconv.Itoa(route.hops+1))
	return nil
}

func parse(headers http.Header) (route, error) {
	instancesRaw := headers.Values(InstanceHeader)
	hopsRaw := headers.Values(HopHeader)
	if len(instancesRaw) == 0 && len(hopsRaw) == 0 {
		return route{}, nil
	}
	if len(instancesRaw) == 0 || len(hopsRaw) != 1 {
		return route{}, fmt.Errorf("%w: incomplete route headers", ErrLoop)
	}
	var instances []string
	for _, raw := range instancesRaw {
		for _, part := range strings.Split(raw, ",") {
			instance := strings.TrimSpace(part)
			if instance == "" {
				return route{}, fmt.Errorf("%w: empty Gateway instance", ErrLoop)
			}
			instances = append(instances, instance)
		}
	}
	hops, err := strconv.Atoi(strings.TrimSpace(hopsRaw[0]))
	if err != nil || hops < 0 || hops != len(instances) {
		return route{}, fmt.Errorf("%w: invalid Gateway hop count", ErrLoop)
	}
	return route{instances: instances, hops: hops}, nil
}
