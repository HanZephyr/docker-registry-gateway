package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/config"
	"github.com/hjx/docker-registry-gateway/internal/provider"
)

func TestRequireRangeProviderAdmissionRejectsNonRangePullProvider(t *testing.T) {
	t.Parallel()

	configuration := config.Config{
		ProbeRef: "library/busybox:latest",
		Providers: []config.Provider{
			{Name: "resolver-only", Resolver: true},
			{Name: "pull", PullProvider: true},
		},
	}
	var probed []string
	err := requireRangeProviderAdmission(context.Background(), configuration, func(_ context.Context, configured config.Provider, _ string, _ bool) (provider.ProbeResult, error) {
		probed = append(probed, configured.Name)
		return provider.ProbeResult{RangeSupported: false}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "pull 不支持 Range") {
		t.Fatalf("requireRangeProviderAdmission() error = %v, want pull Range rejection", err)
	}
	if got, want := strings.Join(probed, ","), "pull"; got != want {
		t.Errorf("probed providers = %q, want %q", got, want)
	}
}

func TestRequireRangeProviderAdmissionAllowsConfiguredDegradedProviders(t *testing.T) {
	t.Parallel()

	configuration := config.Config{
		AllowNonRangeProviders: true,
		Providers:              []config.Provider{{Name: "pull", PullProvider: true}},
	}
	if err := requireRangeProviderAdmission(context.Background(), configuration, func(context.Context, config.Provider, string, bool) (provider.ProbeResult, error) {
		t.Fatal("degraded mode must not require startup admission")
		return provider.ProbeResult{}, nil
	}); err != nil {
		t.Fatalf("requireRangeProviderAdmission() error = %v", err)
	}
}
