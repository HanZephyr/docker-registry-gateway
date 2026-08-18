// Package tempstate owns DRG's short-lived, per-process segmented-download
// workspace. It deliberately never treats a system temporary directory as its
// own: all cleanup is constrained to a namespaced directory and an exited
// process marker.
package tempstate

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ownerFileName = "owner.json"

type owner struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
}

// Workspace is a dedicated temporary directory for one Gateway process.
// Close removes only this process's directory; it never removes its parent.
type Workspace struct {
	Dir string
}

// Prepare creates an isolated workspace below base. Before doing so it
// reclaims only sibling workspaces that have a valid owner marker whose
// process is confirmed to have exited. Unknown files, malformed markers, and
// live processes are left untouched deliberately.
func Prepare(base, identity string) (*Workspace, error) {
	if strings.TrimSpace(identity) == "" {
		return nil, errors.New("temporary workspace identity is required")
	}
	if strings.TrimSpace(base) == "" {
		base = os.TempDir()
	}
	root := filepath.Join(base, "drg-segments", workspaceKey(identity))
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create temporary workspace root: %w", err)
	}
	if err := reclaimExitedWorkspaces(root); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return nil, fmt.Errorf("create temporary workspace: %w", err)
	}
	marker := owner{PID: os.Getpid(), StartedAt: time.Now().UTC()}
	contents, err := json.Marshal(marker)
	if err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("encode temporary workspace marker: %w", err)
	}
	if err := os.WriteFile(filepath.Join(directory, ownerFileName), contents, 0o600); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("write temporary workspace marker: %w", err)
	}
	return &Workspace{Dir: directory}, nil
}

// Close removes this exact per-process workspace after all segmented readers
// have drained. Failure is returned for logging; it must not affect a pull
// that already completed.
func (workspace *Workspace) Close() error {
	if workspace == nil || workspace.Dir == "" {
		return nil
	}
	return os.RemoveAll(workspace.Dir)
}

func workspaceKey(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%x", sum[:12])
}

func reclaimExitedWorkspaces(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read temporary workspace root: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		marker, err := readOwner(filepath.Join(directory, ownerFileName))
		if err != nil || marker.PID <= 0 || processRunning(marker.PID) {
			continue
		}
		if err := os.RemoveAll(directory); err != nil {
			return fmt.Errorf("remove exited temporary workspace %q: %w", directory, err)
		}
	}
	return nil
}

func readOwner(path string) (owner, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return owner{}, err
	}
	var result owner
	if err := json.Unmarshal(contents, &result); err != nil {
		return owner{}, err
	}
	if result.PID <= 0 || result.StartedAt.IsZero() {
		return owner{}, errors.New("temporary workspace marker is incomplete")
	}
	return result, nil
}
