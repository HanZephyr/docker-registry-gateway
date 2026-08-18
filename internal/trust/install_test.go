package trust_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hjx/docker-registry-gateway/internal/trust"
)

func TestInstallWindowsDockerDesktopImportsRootIntoUserStore(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	if err := os.WriteFile(caPath, []byte("test root certificate"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	var commandName string
	var commandArguments []string
	result, err := trust.Install(trust.Options{
		CAPath:            caPath,
		AdvertiseEndpoint: "drg.example.test:5443",
		Platform:          "windows",
		CommandRunner: func(name string, arguments ...string) ([]byte, error) {
			commandName = name
			commandArguments = append([]string(nil), arguments...)
			return []byte("certificate added"), nil
		},
	})
	if err != nil {
		t.Fatalf("trust.Install() error = %v", err)
	}
	if commandName != "certutil" {
		t.Errorf("command = %q, want certutil", commandName)
	}
	if got, want := strings.Join(commandArguments, " "), "-user -addstore Root "+caPath; got != want {
		t.Errorf("certutil arguments = %q, want %q", got, want)
	}
	if len(result.Installed) != 1 || !strings.Contains(result.Installed[0], "CurrentUser") {
		t.Errorf("installed = %q, want Windows CurrentUser root store", result.Installed)
	}
	if !strings.Contains(strings.Join(result.Notices, "\n"), "Docker Desktop") {
		t.Errorf("notices = %q, want Docker Desktop restart guidance", result.Notices)
	}
}

func TestInstallContainerDoesNotWriteHostTrustDirectories(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	if err := os.WriteFile(caPath, []byte("test root certificate"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	result, err := trust.Install(trust.Options{
		CAPath:            caPath,
		AdvertiseEndpoint: "drg.example.test:5443",
		Platform:          "linux",
		IsContainer:       true,
		LinuxCertsDir:     filepath.Join(directory, "host-certs"),
	})
	if err != nil {
		t.Fatalf("trust.Install() error = %v", err)
	}
	if len(result.Instructions) == 0 {
		t.Fatal("container deployment returned no host installation instructions")
	}
	if _, err := os.Stat(filepath.Join(directory, "host-certs")); !os.IsNotExist(err) {
		t.Errorf("container install wrote a host trust directory, stat error = %v", err)
	}
}

func TestInstallMacOSAttemptsSystemKeychainTrust(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	if err := os.WriteFile(caPath, []byte("test root certificate"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	var commandName string
	var commandArguments []string
	result, err := trust.Install(trust.Options{
		CAPath:            caPath,
		AdvertiseEndpoint: "drg.example.test:5443",
		Platform:          "darwin",
		CommandRunner: func(name string, arguments ...string) ([]byte, error) {
			commandName = name
			commandArguments = append([]string(nil), arguments...)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("trust.Install() error = %v", err)
	}
	if commandName != "security" {
		t.Errorf("command = %q, want security", commandName)
	}
	if got, want := strings.Join(commandArguments, " "), "add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "+caPath; got != want {
		t.Errorf("security arguments = %q, want %q", got, want)
	}
	if len(result.Installed) != 1 {
		t.Errorf("installed = %q, want system keychain installation", result.Installed)
	}
}
