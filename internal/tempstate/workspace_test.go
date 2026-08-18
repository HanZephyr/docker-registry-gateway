package tempstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareReclaimsOnlyConfirmedExitedWorkspaces(t *testing.T) {
	base := t.TempDir()
	identity := "gateway-data-directory"
	root := filepath.Join(base, "drg-segments", workspaceKey(identity))
	stale := filepath.Join(root, "run-stale")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatalf("create stale workspace: %v", err)
	}
	contents, err := json.Marshal(owner{PID: 2147483647, StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("encode marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stale, ownerFileName), contents, 0o600); err != nil {
		t.Fatalf("write stale marker: %v", err)
	}
	unknown := filepath.Join(root, "do-not-touch")
	if err := os.MkdirAll(unknown, 0o700); err != nil {
		t.Fatalf("create unknown directory: %v", err)
	}

	workspace, err := Prepare(base, identity)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale workspace stat error = %v, want removed", err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Errorf("unknown directory stat error = %v, want preserved", err)
	}
	if marker, err := readOwner(filepath.Join(workspace.Dir, ownerFileName)); err != nil || marker.PID != os.Getpid() {
		t.Errorf("current workspace marker = %#v, %v", marker, err)
	}
}

func TestProcessRunningRecognizesCurrentProcess(t *testing.T) {
	if !processRunning(os.Getpid()) {
		t.Fatal("current process should be recognized as running")
	}
}
