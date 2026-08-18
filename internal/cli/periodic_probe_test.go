package cli

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/config"
)

func TestPeriodicProviderProbesUseLatestConfigurationAndStop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var configurationMu sync.RWMutex
	configuration := config.Config{ProbeRef: "first"}
	launched := make(chan string)
	stop := startPeriodicProviderProbes(ctx, 10*time.Millisecond, func() config.Config {
		configurationMu.RLock()
		defer configurationMu.RUnlock()
		return configuration
	}, func(current config.Config) {
		launched <- current.ProbeRef
	})

	select {
	case got := <-launched:
		if got != "first" {
			t.Fatalf("first periodic configuration = %q, want first", got)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic probe was not launched")
	}
	configurationMu.Lock()
	configuration.ProbeRef = "second"
	configurationMu.Unlock()
	select {
	case got := <-launched:
		if got != "second" {
			t.Fatalf("updated periodic configuration = %q, want second", got)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic probe did not observe reloaded configuration")
	}

	stop()
	select {
	case got := <-launched:
		t.Fatalf("probe %q launched after stop", got)
	case <-time.After(30 * time.Millisecond):
	}
}
