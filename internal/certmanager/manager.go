// Package certmanager provides an atomically reloadable downstream TLS
// certificate. Existing connections retain their negotiated certificate while
// new handshakes immediately use the replacement.
package certmanager

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
)

// Manager owns one certificate/key pair configured by path.
type Manager struct {
	certificatePath string
	keyPath         string
	current         atomic.Pointer[tls.Certificate]
}

// New loads an initial usable certificate pair.
func New(certificatePath, keyPath string) (*Manager, error) {
	manager := &Manager{certificatePath: certificatePath, keyPath: keyPath}
	if err := manager.Reload(); err != nil {
		return nil, err
	}
	return manager, nil
}

// Reload validates and atomically activates the configured pair. A failed
// reload keeps the previous certificate serving new clients.
func (manager *Manager) Reload() error {
	if manager == nil {
		return errors.New("certificate manager is nil")
	}
	certificate, err := tls.LoadX509KeyPair(manager.certificatePath, manager.keyPath)
	if err != nil {
		return err
	}
	manager.current.Store(&certificate)
	return nil
}

// GetCertificate is suitable for tls.Config.GetCertificate.
func (manager *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if manager == nil {
		return nil, errors.New("certificate manager is nil")
	}
	certificate := manager.current.Load()
	if certificate == nil {
		return nil, errors.New("no downstream TLS certificate is loaded")
	}
	return certificate, nil
}
