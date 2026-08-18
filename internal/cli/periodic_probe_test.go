package cli

import (
	"context"
	"errors"
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

func TestCertificateMaintenanceReportsFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reported := make(chan error, 4)
	stop := startCertificateMaintenance(ctx, 10*time.Millisecond, func() error {
		return errors.New("certificate file is invalid")
	}, func(err error) {
		reported <- err
	})
	select {
	case err := <-reported:
		if err == nil || err.Error() != "certificate file is invalid" {
			t.Errorf("reported maintenance error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate maintenance failure was not reported")
	}
	stop()
}
