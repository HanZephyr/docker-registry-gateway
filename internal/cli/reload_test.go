package cli

import (
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/config"
)

func TestResolverConfigurationChangedPreservesLeasesForPullOnlyChanges(t *testing.T) {
	t.Parallel()
	priority := 10
	current := config.Config{
		Resolution: config.Resolution{ConflictStrategy: "majority", TieBreaker: "rendezvous_hash", DecisionLease: "10m"},
		Providers: []config.Provider{
			{Name: "resolver", URL: "https://resolver.example.test", Resolver: true, Priority: &priority},
			{Name: "pull-one", URL: "https://pull-one.example.test", PullProvider: true},
		},
	}
	candidate := current
	candidate.Providers = append(append([]config.Provider(nil), current.Providers...), config.Provider{Name: "pull-two", URL: "https://pull-two.example.test", PullProvider: true})
	if resolverConfigurationChanged(current, candidate) {
		t.Fatal("pull-only Provider addition should preserve existing leases")
	}
	candidate.Resolution.TieBreaker = "configured_order"
	if !resolverConfigurationChanged(current, candidate) {
		t.Fatal("tie breaker change should invalidate existing leases")
	}
}
