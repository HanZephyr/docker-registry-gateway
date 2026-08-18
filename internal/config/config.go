// Package config owns the versioned, strictly validated DRG configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

// Config is the V1 DRG configuration file.
type Config struct {
	Version                         int        `yaml:"version"`
	DataDir                         string     `yaml:"data_dir"`
	Server                          Server     `yaml:"server"`
	Providers                       []Provider `yaml:"providers"`
	Resolution                      Resolution `yaml:"resolution"`
	ProbeRef                        string     `yaml:"probe_ref"`
	Resources                       Resources  `yaml:"resources"`
	AllowNonRangeProviders          bool       `yaml:"-"`
	AllowNonRangeProvidersSpecified *bool      `yaml:"allow_non_range_providers"`
}

// Resources bounds work admitted by one Gateway process. Byte quantities use
// binary units such as 64MiB and 2GiB, rather than ambiguous decimal suffixes.
type Resources struct {
	MaxConcurrentPulls       int    `yaml:"max_concurrent_pulls"`
	MaxSegmentsPerBlob       int    `yaml:"max_segments_per_blob"`
	TemporaryDiskQuota       string `yaml:"temporary_disk_quota"`
	MinSegmentSize           string `yaml:"min_segment_size"`
	MaxNoRangeRestartDiscard string `yaml:"max_no_range_restart_discard"`
	MaxInflightRequests      int    `yaml:"max_inflight_requests"`
	MaxQueuedPulls           int    `yaml:"max_queued_pulls"`
	TempDir                  string `yaml:"temp_dir"`
}

// Server configures downstream Registry listeners.
type Server struct {
	Listeners []string `yaml:"listeners"`
	TLS       TLS      `yaml:"tls"`
}

// TLS configures Gateway-facing transport security.
type TLS struct {
	LocalCA               bool   `yaml:"-"`
	LocalCASpecified      *bool  `yaml:"local_ca"`
	AdvertiseEndpoint     string `yaml:"advertise_endpoint"`
	CertFile              string `yaml:"cert_file"`
	KeyFile               string `yaml:"key_file"`
	InstallTrust          bool   `yaml:"-"`
	InstallTrustSpecified *bool  `yaml:"install_trust"`
}

// Provider declares an upstream Registry.
type Provider struct {
	Name              string `yaml:"name"`
	URL               string `yaml:"url"`
	Resolver          bool   `yaml:"resolver"`
	PullProvider      bool   `yaml:"pull_provider"`
	Priority          *int   `yaml:"priority"`
	Auth              Auth   `yaml:"auth"`
	CAFile            string `yaml:"ca_file"`
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http"`
}

// Auth is the non-interactive machine identity used for one upstream
// Provider. Password and SecretFile are deliberately mutually exclusive.
type Auth struct {
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	SecretFile string `yaml:"secret_file"`
}

// SecurityWarning describes a non-blocking configuration risk. DRG reports
// these before startup but never substitutes product policy for deployment
// decisions such as deliberately exposing a Gateway to a private network.
type SecurityWarning struct {
	Code    string
	Message string
}

// SecurityWarnings returns all high-priority configuration risks without
// including authentication material or file contents.
func (value Config) SecurityWarnings() []SecurityWarning {
	var warnings []SecurityWarning
	hasCredentials := false
	for _, provider := range value.Providers {
		if provider.Auth.Password != "" {
			warnings = append(warnings, SecurityWarning{Code: "plaintext_provider_password", Message: fmt.Sprintf("Provider %q 在主配置中使用明文 password，建议改用 secret_file", provider.Name)})
		}
		if provider.Auth.Password != "" || provider.Auth.SecretFile != "" {
			hasCredentials = true
		}
		if provider.AllowInsecureHTTP {
			warnings = append(warnings, SecurityWarning{Code: "insecure_provider_http", Message: fmt.Sprintf("Provider %q 已启用不安全 HTTP 上游", provider.Name)})
		}
		if provider.Auth.SecretFile != "" && runtime.GOOS != "windows" {
			if info, err := os.Stat(provider.Auth.SecretFile); err == nil && info.Mode().Perm()&0o077 != 0 {
				warnings = append(warnings, SecurityWarning{Code: "provider_secret_permissions", Message: fmt.Sprintf("Provider %q 的 secret_file 权限允许其他用户读取", provider.Name)})
			}
		}
	}
	if hasCredentials && hasNonLoopbackListener(value.Server.Listeners) {
		warnings = append(warnings, SecurityWarning{Code: "credentialed_public_listener", Message: "Gateway 监听非回环地址且已配置 Provider 凭据；请确保网络边界和主机访问控制符合预期"})
	}
	if !value.Server.TLS.LocalCA && value.Server.TLS.CertFile == "" {
		warnings = append(warnings, SecurityWarning{Code: "downstream_plain_http", Message: "Gateway 未启用本地 CA 且未配置 cert_file/key_file，将以纯 HTTP 后端监听；请确认 Docker daemon 已显式允许该不安全 Registry"})
	}
	return warnings
}

func hasNonLoopbackListener(listeners []string) bool {
	for _, listener := range listeners {
		host, _, err := net.SplitHostPort(listener)
		if err != nil {
			return true
		}
		host = strings.Trim(host, "[]")
		if host == "localhost" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			continue
		}
		return true
	}
	return false
}

// Credentials returns the Provider credentials without exposing the source of
// the password to callers. A secret_file is intentionally a one-line file so
// accidental multi-line configuration cannot become part of an HTTP header.
func (auth Auth) Credentials() (string, string, error) {
	if auth.SecretFile == "" {
		return auth.Username, auth.Password, nil
	}
	contents, err := os.ReadFile(auth.SecretFile)
	if err != nil {
		return "", "", fmt.Errorf("read secret_file: %w", err)
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(contents), "\n"), "\r")
	if password == "" || strings.ContainsAny(password, "\r\n") {
		return "", "", errors.New("secret_file must contain exactly one non-empty line")
	}
	return auth.Username, password, nil
}

// Resolution configures mutable-tag conflict resolution.
type Resolution struct {
	ConflictStrategy string `yaml:"conflict_strategy"`
	TieBreaker       string `yaml:"tie_breaker"`
	DecisionLease    string `yaml:"decision_lease"`
}

// Load decodes exactly one YAML document, rejects unknown fields, and returns
// only a configuration that satisfies the V1 structural contract.
func Load(reader io.Reader) (Config, error) {
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)

	var value Config
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("configuration must contain exactly one YAML document")
		}
		return Config{}, fmt.Errorf("decode trailing configuration document: %w", err)
	}

	value.applyDefaults()
	if err := value.Validate(); err != nil {
		return Config{}, err
	}
	return value, nil
}

func (value *Config) applyDefaults() {
	if value.DataDir == "" {
		value.DataDir = ".drg"
	}
	if value.Server.TLS.InstallTrustSpecified == nil {
		value.Server.TLS.InstallTrust = true
	} else {
		value.Server.TLS.InstallTrust = *value.Server.TLS.InstallTrustSpecified
	}
	if value.Server.TLS.LocalCASpecified == nil {
		value.Server.TLS.LocalCA = true
	} else {
		value.Server.TLS.LocalCA = *value.Server.TLS.LocalCASpecified
	}
	if value.Resolution.ConflictStrategy == "" {
		value.Resolution.ConflictStrategy = "majority"
	}
	if value.Resolution.TieBreaker == "" {
		value.Resolution.TieBreaker = "rendezvous_hash"
	}
	if value.Resolution.DecisionLease == "" {
		value.Resolution.DecisionLease = "10m"
	}
	if value.ProbeRef == "" {
		value.ProbeRef = "library/busybox:latest"
	}
	value.Resources.applyDefaults()
	if value.AllowNonRangeProvidersSpecified == nil {
		value.AllowNonRangeProviders = true
	} else {
		value.AllowNonRangeProviders = *value.AllowNonRangeProvidersSpecified
	}
}

func (resources *Resources) applyDefaults() {
	if resources.MaxConcurrentPulls == 0 {
		resources.MaxConcurrentPulls = 4
	}
	if resources.MaxSegmentsPerBlob == 0 {
		resources.MaxSegmentsPerBlob = 4
	}
	if resources.TemporaryDiskQuota == "" {
		resources.TemporaryDiskQuota = "2GiB"
	}
	if resources.MinSegmentSize == "" {
		resources.MinSegmentSize = "16MiB"
	}
	if resources.MaxNoRangeRestartDiscard == "" {
		resources.MaxNoRangeRestartDiscard = "64MiB"
	}
	if resources.MaxInflightRequests == 0 {
		resources.MaxInflightRequests = 32
	}
	if resources.MaxQueuedPulls == 0 {
		resources.MaxQueuedPulls = 16
	}
}

// LoadFile loads a configuration file and resolves every documented relative
// file reference against the configuration file's directory. It also checks
// that secret_file references are usable before the process accepts config.
func LoadFile(path string) (Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve configuration path: %w", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	value, err := Load(file)
	if err != nil {
		return Config{}, err
	}
	return value.resolveFilePaths(filepath.Dir(absPath))
}

// Validate checks the static V1 configuration contract without contacting a
// Provider. Runtime admission and health checks happen separately.
func (value Config) Validate() error {
	if value.Version != CurrentVersion {
		return fmt.Errorf("unsupported configuration version %d (want %d)", value.Version, CurrentVersion)
	}
	if err := validateServer(value.Server); err != nil {
		return err
	}
	if err := validateProviders(value.Providers); err != nil {
		return err
	}
	if err := validateProviderSelfRoutes(value.Server.TLS.AdvertiseEndpoint, value.Providers); err != nil {
		return err
	}
	if err := validateResolution(value.Resolution, value.Providers); err != nil {
		return err
	}
	if err := validateResources(value.Resources); err != nil {
		return err
	}
	if strings.TrimSpace(value.ProbeRef) == "" {
		return errors.New("probe_ref is required")
	}
	return nil
}

func validateResources(resources Resources) error {
	for name, value := range map[string]int{
		"max_concurrent_pulls":  resources.MaxConcurrentPulls,
		"max_segments_per_blob": resources.MaxSegmentsPerBlob,
		"max_inflight_requests": resources.MaxInflightRequests,
		"max_queued_pulls":      resources.MaxQueuedPulls,
	} {
		if value <= 0 {
			return fmt.Errorf("resources %s must be greater than zero", name)
		}
	}
	for name, value := range map[string]string{
		"temporary_disk_quota":         resources.TemporaryDiskQuota,
		"min_segment_size":             resources.MinSegmentSize,
		"max_no_range_restart_discard": resources.MaxNoRangeRestartDiscard,
	} {
		if _, err := ParseByteSize(value); err != nil {
			return fmt.Errorf("resources %s: %w", name, err)
		}
	}
	return nil
}

func validateServer(server Server) error {
	if len(server.Listeners) == 0 {
		return errors.New("at least one listener is required")
	}
	type listenerEndpoint struct {
		host string
		port string
	}
	seen := make(map[string]struct{}, len(server.Listeners))
	endpoints := make([]listenerEndpoint, 0, len(server.Listeners))
	for _, listener := range server.Listeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			return errors.New("listener cannot be empty")
		}
		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid listener %q: %w", listener, err)
		}
		if host == "" || port == "" {
			return fmt.Errorf("invalid listener %q", listener)
		}
		if _, exists := seen[listener]; exists {
			return fmt.Errorf("duplicate listener %q", listener)
		}
		seen[listener] = struct{}{}
		for _, previous := range endpoints {
			if listenerEndpointsOverlap(previous.host, previous.port, host, port) {
				return fmt.Errorf("listener %q overlaps %q", listener, net.JoinHostPort(previous.host, previous.port))
			}
		}
		endpoints = append(endpoints, listenerEndpoint{host: host, port: port})
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(server.TLS.AdvertiseEndpoint)); err != nil {
		return fmt.Errorf("invalid advertise_endpoint %q: %w", server.TLS.AdvertiseEndpoint, err)
	}
	if server.TLS.LocalCA && (strings.TrimSpace(server.TLS.CertFile) != "" || strings.TrimSpace(server.TLS.KeyFile) != "") {
		return errors.New("cert_file and key_file require local_ca: false")
	}
	if !server.TLS.LocalCA && (strings.TrimSpace(server.TLS.CertFile) == "") != (strings.TrimSpace(server.TLS.KeyFile) == "") {
		return errors.New("cert_file and key_file must be configured together")
	}
	return nil
}

func listenerEndpointsOverlap(leftHost, leftPort, rightHost, rightPort string) bool {
	if leftPort != rightPort {
		return false
	}
	leftHost = strings.Trim(strings.ToLower(leftHost), "[]")
	rightHost = strings.Trim(strings.ToLower(rightHost), "[]")
	if leftHost == rightHost {
		return true
	}
	leftIP := net.ParseIP(leftHost)
	rightIP := net.ParseIP(rightHost)
	if leftHost == "0.0.0.0" {
		return rightIP == nil || rightIP.To4() != nil
	}
	if rightHost == "0.0.0.0" {
		return leftIP == nil || leftIP.To4() != nil
	}
	if leftHost == "::" {
		return rightIP == nil || rightIP.To4() == nil
	}
	if rightHost == "::" {
		return leftIP == nil || leftIP.To4() == nil
	}
	return false
}

func validateProviders(providers []Provider) error {
	if len(providers) == 0 {
		return errors.New("at least one provider is required")
	}

	providerNames := make(map[string]struct{}, len(providers))
	providerOrigins := make(map[string]struct{}, len(providers))
	hasResolver := false
	hasPullProvider := false
	for _, provider := range providers {
		name := strings.TrimSpace(provider.Name)
		if name == "" {
			return errors.New("provider name is required")
		}
		if _, exists := providerNames[name]; exists {
			return fmt.Errorf("duplicate provider name %q", name)
		}
		providerNames[name] = struct{}{}

		origin, err := validateProviderURL(provider)
		if err != nil {
			return fmt.Errorf("provider %q: %w", name, err)
		}
		if err := validateProviderAuth(provider.Auth); err != nil {
			return fmt.Errorf("provider %q: %w", name, err)
		}
		if _, exists := providerOrigins[origin]; exists {
			return fmt.Errorf("duplicate provider url %q", origin)
		}
		providerOrigins[origin] = struct{}{}
		hasResolver = hasResolver || provider.Resolver
		hasPullProvider = hasPullProvider || provider.PullProvider
	}
	if !hasResolver {
		return errors.New("at least one resolver is required")
	}
	if !hasPullProvider {
		return errors.New("at least one pull provider is required")
	}
	return nil
}

func validateProviderSelfRoutes(advertiseEndpoint string, providers []Provider) error {
	advertiseHost, advertisePort, err := net.SplitHostPort(strings.TrimSpace(advertiseEndpoint))
	if err != nil {
		return err
	}
	advertiseHost = strings.Trim(strings.ToLower(advertiseHost), "[]")
	for _, provider := range providers {
		parsed, err := url.Parse(strings.TrimSpace(provider.URL))
		if err != nil {
			continue
		}
		providerHost := strings.Trim(strings.ToLower(parsed.Hostname()), "[]")
		providerPort := parsed.Port()
		if providerPort == "" {
			switch strings.ToLower(parsed.Scheme) {
			case "https":
				providerPort = "443"
			case "http":
				providerPort = "80"
			}
		}
		if providerHost == advertiseHost && providerPort == advertisePort {
			return fmt.Errorf("provider %q points at Gateway advertise_endpoint %q", provider.Name, advertiseEndpoint)
		}
	}
	return nil
}

func validateProviderURL(provider Provider) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(provider.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("url must include a scheme and host")
	}
	if parsed.User != nil {
		return "", errors.New("url must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("url must not contain a query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("url must not contain a path")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && provider.AllowInsecureHTTP) {
		return "", errors.New("url must use https unless allow_insecure_http is true")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func validateProviderAuth(auth Auth) error {
	username := strings.TrimSpace(auth.Username)
	password := strings.TrimSpace(auth.Password)
	secretFile := strings.TrimSpace(auth.SecretFile)
	if password != "" && secretFile != "" {
		return errors.New("auth password and secret_file are mutually exclusive")
	}
	if (password != "" || secretFile != "") && username == "" {
		return errors.New("auth username is required when password or secret_file is set")
	}
	if username != "" && password == "" && secretFile == "" {
		return errors.New("auth password or secret_file is required when username is set")
	}
	return nil
}

func validateResolution(resolution Resolution, providers []Provider) error {
	switch resolution.ConflictStrategy {
	case "majority", "provider_priority":
	default:
		return fmt.Errorf("unsupported resolution conflict_strategy %q", resolution.ConflictStrategy)
	}
	switch resolution.TieBreaker {
	case "configured_order", "rendezvous_hash", "fail":
	default:
		return fmt.Errorf("unsupported resolution tie_breaker %q", resolution.TieBreaker)
	}
	lease, err := time.ParseDuration(resolution.DecisionLease)
	if err != nil || lease <= 0 {
		return fmt.Errorf("decision_lease must be a positive Go duration, got %q", resolution.DecisionLease)
	}
	if resolution.ConflictStrategy == "provider_priority" {
		seenPriorities := make(map[int]string)
		for _, provider := range providers {
			if !provider.Resolver {
				continue
			}
			if provider.Priority == nil {
				return fmt.Errorf("resolver %q must set priority when conflict_strategy is provider_priority", provider.Name)
			}
			if *provider.Priority < 0 {
				return fmt.Errorf("resolver %q priority must be zero or greater", provider.Name)
			}
			if other, exists := seenPriorities[*provider.Priority]; exists {
				return fmt.Errorf("resolvers %q and %q share priority %d", other, provider.Name, *provider.Priority)
			}
			seenPriorities[*provider.Priority] = provider.Name
		}
	}
	return nil
}

func (value Config) resolveFilePaths(baseDirectory string) (Config, error) {
	resolved := value
	resolved.DataDir = resolvePath(baseDirectory, resolved.DataDir)
	if resolved.Resources.TempDir != "" {
		resolved.Resources.TempDir = resolvePath(baseDirectory, resolved.Resources.TempDir)
	}
	if resolved.Server.TLS.CertFile != "" {
		resolved.Server.TLS.CertFile = resolvePath(baseDirectory, resolved.Server.TLS.CertFile)
		if err := validateReadableFile(resolved.Server.TLS.CertFile); err != nil {
			return Config{}, fmt.Errorf("server tls cert_file: %w", err)
		}
	}
	if resolved.Server.TLS.KeyFile != "" {
		resolved.Server.TLS.KeyFile = resolvePath(baseDirectory, resolved.Server.TLS.KeyFile)
		if err := validateReadableFile(resolved.Server.TLS.KeyFile); err != nil {
			return Config{}, fmt.Errorf("server tls key_file: %w", err)
		}
	}
	for index := range resolved.Providers {
		provider := &resolved.Providers[index]
		if provider.Auth.SecretFile != "" {
			provider.Auth.SecretFile = resolvePath(baseDirectory, provider.Auth.SecretFile)
			if err := validateReadableFile(provider.Auth.SecretFile); err != nil {
				return Config{}, fmt.Errorf("provider %q secret_file: %w", provider.Name, err)
			}
			if _, _, err := provider.Auth.Credentials(); err != nil {
				return Config{}, fmt.Errorf("provider %q secret_file: %w", provider.Name, err)
			}
		}
		if provider.CAFile != "" {
			provider.CAFile = resolvePath(baseDirectory, provider.CAFile)
			if err := validateReadableFile(provider.CAFile); err != nil {
				return Config{}, fmt.Errorf("provider %q ca_file: %w", provider.Name, err)
			}
		}
	}
	return resolved, nil
}

func resolvePath(baseDirectory, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(baseDirectory, value)
}

func validateReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must refer to a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return file.Close()
}

// ParseByteSize parses a positive binary byte quantity accepted by V1 config.
func ParseByteSize(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	for _, unit := range []struct {
		suffix     string
		multiplier int64
	}{
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	} {
		if !strings.HasSuffix(trimmed, unit.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(trimmed, unit.suffix))
		parsed, err := strconv.ParseInt(number, 10, 64)
		if err != nil || parsed <= 0 || parsed > (1<<63-1)/unit.multiplier {
			return 0, fmt.Errorf("must be a positive byte quantity with KiB, MiB, GiB or B units, got %q", value)
		}
		return parsed * unit.multiplier, nil
	}
	return 0, fmt.Errorf("must be a positive byte quantity with KiB, MiB, GiB or B units, got %q", value)
}
