package routeguard_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/routeguard"
)

func TestGuardRejectsRequestThatReturnsToTheSameGateway(t *testing.T) {
	guard := routeguard.New("gateway-a", 3)
	headers := make(http.Header)
	headers.Set(routeguard.InstanceHeader, "gateway-b, gateway-a")
	headers.Set(routeguard.HopHeader, "2")

	_, err := guard.Inbound(context.Background(), headers)
	if !errors.Is(err, routeguard.ErrLoop) {
		t.Fatalf("Inbound() error = %v, want routing loop", err)
	}
}
