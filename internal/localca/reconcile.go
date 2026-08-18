// Package localca manages the local, per-Gateway certificate authority.
package localca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	rootCertificateFile = "ca.crt"
	rootKeyFile         = "ca.key"
	serverCertificate   = "server.crt"
	serverKey           = "server.key"
	identityFile        = "identity.json"
	previousRootFile    = "ca.previous.crt"
	pendingRootFile     = "ca.next.crt"
	pendingRootKeyFile  = "ca.next.key"

	leafValidity = 90 * 24 * time.Hour
	renewBefore  = 30 * 24 * time.Hour
	rootValidity = 10 * 365 * 24 * time.Hour
	clockLeeway  = 5 * time.Minute
)

// Options describes a reconciliation request.
type Options struct {
	DataDir           string
	AdvertiseEndpoint string
	Now               func() time.Time
}

// Result describes files reconciled during a call.
type Result struct {
	RootCreated    bool
	RootRotated    bool
	LeafIssued     bool
	InstanceID     string
	CAPath         string
	PreviousCAPath string
	PendingCAPath  string
	PendingKeyPath string
	Certificate    string
	PrivateKey     string
	IdentityPath   string
}

type identity struct {
	RootFingerprintSHA256 string `json:"root_fingerprint_sha256"`
}

// Reconcile creates or verifies a durable root CA, then creates or renews the
// leaf certificate required for the configured downstream endpoint.
func Reconcile(ctx context.Context, options Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(options.DataDir) == "" {
		return Result{}, errors.New("data directory is required")
	}
	host, _, err := splitEndpoint(options.AdvertiseEndpoint)
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}

	pkiDirectory := filepath.Join(options.DataDir, "pki")
	if err := os.MkdirAll(pkiDirectory, 0o700); err != nil {
		return Result{}, fmt.Errorf("create PKI directory: %w", err)
	}

	result := Result{
		CAPath:         filepath.Join(pkiDirectory, rootCertificateFile),
		PreviousCAPath: filepath.Join(pkiDirectory, previousRootFile),
		PendingCAPath:  filepath.Join(pkiDirectory, pendingRootFile),
		PendingKeyPath: filepath.Join(pkiDirectory, pendingRootKeyFile),
		Certificate:    filepath.Join(pkiDirectory, serverCertificate),
		PrivateKey:     filepath.Join(pkiDirectory, serverKey),
		IdentityPath:   filepath.Join(pkiDirectory, identityFile),
	}
	rootKeyPath := filepath.Join(pkiDirectory, rootKeyFile)

	rootCertificate, rootKey, rootCreated, err := loadOrCreateRoot(result.CAPath, rootKeyPath, result.IdentityPath, now)
	if err != nil {
		return Result{}, err
	}
	result.RootCreated = rootCreated
	result.InstanceID = fingerprint(rootCertificate)

	leaf, leafKey, err := loadLeaf(result.Certificate, result.PrivateKey)
	if err != nil || leafNeedsRenewal(leaf, rootCertificate, host, now) {
		if err := issueLeaf(result.Certificate, result.PrivateKey, rootCertificate, rootKey, host, now); err != nil {
			return Result{}, err
		}
		result.LeafIssued = true
		return result, nil
	}
	if leafKey == nil {
		return Result{}, errors.New("server key is missing")
	}
	return result, nil
}

// PrepareRootRotation creates a pending replacement root without changing the
// root that the running Gateway (and Docker clients) currently trust. Callers
// must install PendingCAPath into Docker trust before calling
// ActivateRootRotation. Keeping this explicit makes a failed trust installation
// incapable of activating an untrusted server leaf.
func PrepareRootRotation(ctx context.Context, options Options) (Result, error) {
	result, err := Reconcile(ctx, options)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}
	if fileExists(result.PreviousCAPath) {
		return Result{}, errors.New("the previous local CA is still retained; explicitly clear it before preparing another root rotation")
	}
	pendingCertificateExists := fileExists(result.PendingCAPath)
	pendingKeyExists := fileExists(result.PendingKeyPath)
	if pendingCertificateExists != pendingKeyExists {
		return Result{}, errors.New("pending local CA certificate and private key must either both exist or both be absent")
	}
	if pendingCertificateExists {
		pendingRoot, err := readCertificate(result.PendingCAPath)
		if err != nil || !pendingRoot.IsCA {
			return Result{}, errors.New("pending local CA certificate is invalid")
		}
		if err := verifyPrivateKeyPermissions(result.PendingKeyPath); err != nil {
			return Result{}, err
		}
		if _, err := readECPrivateKey(result.PendingKeyPath); err != nil {
			return Result{}, fmt.Errorf("read pending local CA private key: %w", err)
		}
		return result, nil
	}
	newRoot, newKey, err := createRoot(now)
	if err != nil {
		return Result{}, err
	}
	if err := writeCertificate(result.PendingCAPath, newRoot); err != nil {
		return Result{}, fmt.Errorf("write pending local CA certificate: %w", err)
	}
	if err := writeECPrivateKey(result.PendingKeyPath, newKey); err != nil {
		_ = os.Remove(result.PendingCAPath)
		return Result{}, fmt.Errorf("write pending local CA private key: %w", err)
	}
	return result, nil
}

// ActivateRootRotation atomically promotes a prepared root after its public
// certificate has been trusted by Docker. The existing root is retained as
// ca.previous.crt and may only be removed through ClearPreviousRoot.
func ActivateRootRotation(ctx context.Context, options Options) (Result, error) {
	result, err := Reconcile(ctx, options)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if fileExists(result.PreviousCAPath) {
		return Result{}, errors.New("the previous local CA is still retained; explicitly clear it before activating another root rotation")
	}
	if !fileExists(result.PendingCAPath) || !fileExists(result.PendingKeyPath) {
		return Result{}, errors.New("no prepared local CA rotation exists; run tls rotate-root first")
	}
	pendingRoot, err := readCertificate(result.PendingCAPath)
	if err != nil || !pendingRoot.IsCA {
		return Result{}, errors.New("pending local CA certificate is invalid")
	}
	if err := verifyPrivateKeyPermissions(result.PendingKeyPath); err != nil {
		return Result{}, err
	}
	pendingKey, err := readECPrivateKey(result.PendingKeyPath)
	if err != nil {
		return Result{}, fmt.Errorf("read pending local CA private key: %w", err)
	}
	currentRoot, err := readCertificate(result.CAPath)
	if err != nil {
		return Result{}, fmt.Errorf("read current local CA certificate: %w", err)
	}
	if err := writeCertificate(result.PreviousCAPath, currentRoot); err != nil {
		return Result{}, fmt.Errorf("preserve previous local CA certificate: %w", err)
	}
	if err := writeCertificate(result.CAPath, pendingRoot); err != nil {
		return Result{}, fmt.Errorf("activate pending local CA certificate: %w", err)
	}
	if err := writeECPrivateKey(filepath.Join(filepath.Dir(result.CAPath), rootKeyFile), pendingKey); err != nil {
		return Result{}, fmt.Errorf("activate pending local CA private key: %w", err)
	}
	if err := writeIdentity(result.IdentityPath, pendingRoot); err != nil {
		return Result{}, fmt.Errorf("activate local CA identity: %w", err)
	}
	now := time.Now().UTC()
	if options.Now != nil {
		now = options.Now().UTC()
	}
	host, _, err := splitEndpoint(options.AdvertiseEndpoint)
	if err != nil {
		return Result{}, err
	}
	if err := issueLeaf(result.Certificate, result.PrivateKey, pendingRoot, pendingKey, host, now); err != nil {
		return Result{}, err
	}
	if err := os.Remove(result.PendingCAPath); err != nil {
		return Result{}, fmt.Errorf("remove activated pending local CA certificate: %w", err)
	}
	if err := os.Remove(result.PendingKeyPath); err != nil {
		return Result{}, fmt.Errorf("remove activated pending local CA private key: %w", err)
	}
	result.RootRotated = true
	result.LeafIssued = true
	result.InstanceID = fingerprint(pendingRoot)
	return result, nil
}

// ClearPreviousRoot removes only the local rotation marker. It is deliberately
// explicit because a prior root remains a valid Docker trust anchor until an
// operator has completed their own trust-store cleanup.
func ClearPreviousRoot(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return errors.New("data directory is required")
	}
	path := filepath.Join(dataDir, "pki", previousRootFile)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove previous local CA certificate: %w", err)
	}
	return nil
}

func splitEndpoint(endpoint string) (string, string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil || host == "" || port == "" {
		return "", "", fmt.Errorf("invalid advertise endpoint %q", endpoint)
	}
	return host, port, nil
}

func loadOrCreateRoot(certificatePath, keyPath, identityPath string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, bool, error) {
	certificateExists := fileExists(certificatePath)
	keyExists := fileExists(keyPath)
	identityExists := fileExists(identityPath)
	if certificateExists != keyExists {
		return nil, nil, false, errors.New("local CA certificate and private key must either both exist or both be absent")
	}
	if !certificateExists {
		if identityExists {
			return nil, nil, false, errors.New("local CA material is missing for an existing Gateway identity; run an explicit root CA recovery or rotation")
		}
		certificate, key, err := createRoot(now)
		if err != nil {
			return nil, nil, false, err
		}
		if err := writeCertificate(certificatePath, certificate); err != nil {
			return nil, nil, false, err
		}
		if err := writeECPrivateKey(keyPath, key); err != nil {
			return nil, nil, false, err
		}
		if err := writeIdentity(identityPath, certificate); err != nil {
			return nil, nil, false, err
		}
		return certificate, key, true, nil
	}

	certificate, err := readCertificate(certificatePath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read local CA certificate: %w", err)
	}
	if !certificate.IsCA {
		return nil, nil, false, errors.New("stored local CA certificate is not a certificate authority")
	}
	if err := verifyPrivateKeyPermissions(keyPath); err != nil {
		return nil, nil, false, err
	}
	key, err := readECPrivateKey(keyPath)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read local CA private key: %w", err)
	}
	if !identityExists {
		return nil, nil, false, errors.New("local CA identity file is missing; refusing to assume this root belongs to the Gateway")
	}
	if err := verifyIdentity(identityPath, certificate); err != nil {
		return nil, nil, false, err
	}
	return certificate, key, false, nil
}

func verifyPrivateKeyPermissions(path string) error {
	if runtime.GOOS == "windows" {
		// Windows access is protected by the containing data-directory ACL. The
		// file is always created through atomicWrite with owner-only intent; the
		// platform-specific ACL inspection is handled by the deployment doctor.
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("local CA private key permissions allow group or other access")
	}
	return nil
}

func createRoot(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate local CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Docker Registry Gateway Local CA"},
		NotBefore:             now.Add(-clockLeeway),
		NotAfter:              now.Add(rootValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create local CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated local CA certificate: %w", err)
	}
	return certificate, key, nil
}

func issueLeaf(certificatePath, keyPath string, root *x509.Certificate, rootKey *ecdsa.PrivateKey, endpointHost string, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Docker Registry Gateway"},
		NotBefore:    now.Add(-clockLeeway),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if endpointIP := net.ParseIP(endpointHost); endpointIP != nil {
		template.IPAddresses = []net.IP{endpointIP}
	} else {
		template.DNSNames = append(template.DNSNames, endpointHost)
	}
	template.DNSNames = appendUniqueDNSName(template.DNSNames, "host.docker.internal")

	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse generated server certificate: %w", err)
	}
	if err := writeCertificate(certificatePath, certificate); err != nil {
		return err
	}
	if err := writeECPrivateKey(keyPath, key); err != nil {
		return err
	}
	return nil
}

func leafNeedsRenewal(leaf, root *x509.Certificate, endpointHost string, now time.Time) bool {
	if leaf == nil {
		return true
	}
	if leaf.NotAfter.Before(now.Add(renewBefore)) || leaf.NotBefore.After(now.Add(clockLeeway)) {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifyOptions := x509.VerifyOptions{Roots: roots, CurrentTime: now}
	if endpointIP := net.ParseIP(endpointHost); endpointIP != nil {
		verifyOptions.DNSName = endpointIP.String()
	} else {
		verifyOptions.DNSName = endpointHost
	}
	if _, err := leaf.Verify(verifyOptions); err != nil {
		return true
	}
	return leaf.VerifyHostname("host.docker.internal") != nil
}

func loadLeaf(certificatePath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if !fileExists(certificatePath) || !fileExists(keyPath) {
		return nil, nil, errors.New("server certificate material is missing")
	}
	certificate, err := readCertificate(certificatePath)
	if err != nil {
		return nil, nil, err
	}
	key, err := readECPrivateKey(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return certificate, key, nil
}

func writeIdentity(path string, certificate *x509.Certificate) error {
	contents, err := json.Marshal(identity{RootFingerprintSHA256: fingerprint(certificate)})
	if err != nil {
		return fmt.Errorf("encode local CA identity: %w", err)
	}
	return atomicWrite(path, append(contents, '\n'), 0o600)
}

func verifyIdentity(path string, certificate *x509.Certificate) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read local CA identity: %w", err)
	}
	var stored identity
	if err := json.Unmarshal(contents, &stored); err != nil {
		return fmt.Errorf("decode local CA identity: %w", err)
	}
	want := fingerprint(certificate)
	if stored.RootFingerprintSHA256 != want {
		return errors.New("local CA fingerprint does not match the Gateway identity")
	}
	return nil
}

func fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeCertificate(path string, certificate *x509.Certificate) error {
	return atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o644)
}

func writeECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode EC private key: %w", err)
	}
	return atomicWrite(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func readCertificate(path string) (*x509.Certificate, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM block is missing")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("EC private key PEM block is missing")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func atomicWrite(path string, contents []byte, permissions fs.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".drg-pki-*")
	if err != nil {
		return fmt.Errorf("create temporary PKI file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(permissions); err != nil {
		temporary.Close()
		return fmt.Errorf("set PKI file permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write PKI file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close PKI file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate PKI file: %w", err)
	}
	return nil
}

func appendUniqueDNSName(names []string, candidate string) []string {
	for _, name := range names {
		if strings.EqualFold(name, candidate) {
			return names
		}
	}
	return append(names, candidate)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
