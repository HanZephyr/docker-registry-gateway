package control_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/control"
)

func TestLocalControlServerAuthenticatesAndDispatchesCommands(t *testing.T) {
	t.Parallel()

	var reloads int
	stopped := make(chan bool, 1)
	server, err := control.Start(t.TempDir(), control.Callbacks{
		Status: func() control.Status { return control.Status{State: "running", ActivePulls: 2} },
		Reload: func(context.Context) error {
			reloads++
			return nil
		},
		Stop: func(_ context.Context, force bool) error {
			stopped <- force
			return nil
		},
	})
	if err != nil {
		t.Fatalf("control.Start() error = %v", err)
	}
	defer server.Close()

	status, err := control.StatusRequest(context.Background(), server.DataDir())
	if err != nil {
		t.Fatalf("StatusRequest() error = %v", err)
	}
	if status.State != "running" || status.ActivePulls != 2 {
		t.Errorf("status = %#v, want running with two pulls", status)
	}
	if err := control.ReloadRequest(context.Background(), server.DataDir()); err != nil {
		t.Fatalf("ReloadRequest() error = %v", err)
	}
	if reloads != 1 {
		t.Errorf("reload count = %d, want 1", reloads)
	}
	if err := control.StopRequest(context.Background(), server.DataDir(), true); err != nil {
		t.Fatalf("StopRequest() error = %v", err)
	}
	select {
	case forcedStop := <-stopped:
		if !forcedStop {
			t.Error("force argument did not reach stop callback")
		}
	case <-time.After(time.Second):
		t.Error("stop callback was not invoked")
	}

	info, err := control.LoadInfo(server.DataDir())
	if err != nil {
		t.Fatalf("LoadInfo() error = %v", err)
	}
	response, err := http.Get("http://" + info.Address + "/v1/status")
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
}
