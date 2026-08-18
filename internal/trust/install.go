// Package trust installs, or explains how to install, the local DRG root CA
// into the Docker daemon's registry trust locations.
package trust

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const managedCAFile = "drg-ca.crt"

// Options defines the deployment context. Platform, LinuxCertsDir and
// CommandRunner are injectable to make platform behavior testable without
// changing the host.
type Options struct {
	CAPath            string
	AdvertiseEndpoint string
	ManagedFileName   string
	Platform          string
	LinuxCertsDir     string
	IsContainer       bool
	CommandRunner     CommandRunner
}

// CommandRunner executes a platform trust command without exposing a shell.
type CommandRunner func(name string, arguments ...string) ([]byte, error)

// Result lists every managed trust file and any manual action still needed.
type Result struct {
	Installed    []string
	Notices      []string
	Instructions []string
}

// Diagnosis is the read-only trust result consumed by `drg doctor`.
// Checked=false means DRG cannot safely inspect the daemon host (for example
// when DRG itself is running inside a container).
type Diagnosis struct {
	Checked bool
	Trusted bool
	Details string
}

// Diagnose verifies the current local root in the Docker trust location that
// DRG can identify without changing Docker configuration or certificates.
func Diagnose(options Options) (Diagnosis, error) {
	if strings.TrimSpace(options.CAPath) == "" {
		return Diagnosis{}, errors.New("CA path is required")
	}
	contents, err := os.ReadFile(options.CAPath)
	if err != nil {
		return Diagnosis{}, fmt.Errorf("read local root CA: %w", err)
	}
	if options.IsContainer {
		return Diagnosis{Details: "DRG 正在容器内运行，无法安全读取 Docker 宿主机信任库；请按 tls reconcile 输出的宿主机步骤核验。"}, nil
	}
	platform := options.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	names, err := registryNames(options.AdvertiseEndpoint)
	if err != nil {
		return Diagnosis{}, err
	}
	switch platform {
	case "linux":
		baseDirectory := options.LinuxCertsDir
		if baseDirectory == "" {
			baseDirectory = "/etc/docker/certs.d"
		}
		for _, name := range names {
			path := filepath.Join(baseDirectory, name, managedCAFile)
			installed, readErr := os.ReadFile(path)
			if readErr != nil || !sameCertificate(contents, installed) {
				return Diagnosis{Checked: true, Details: fmt.Sprintf("Docker 信任文件缺失或不匹配：%s", path)}, nil
			}
		}
		return Diagnosis{Checked: true, Trusted: true, Details: "Docker certs.d 当前根证书与 DRG 本地根一致"}, nil
	case "windows":
		return diagnoseWindowsTrust(options, contents)
	case "darwin":
		return diagnoseMacOSTrust(options, contents)
	default:
		return Diagnosis{Details: fmt.Sprintf("当前平台 %s 没有可安全读取的 Docker 根证书位置。", platform)}, nil
	}
}

func sameCertificate(left, right []byte) bool {
	leftCertificate, leftErr := parseCertificate(left)
	rightCertificate, rightErr := parseCertificate(right)
	return leftErr == nil && rightErr == nil && string(leftCertificate.Raw) == string(rightCertificate.Raw)
}

func parseCertificate(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("certificate PEM block is missing")
	}
	return x509.ParseCertificate(block.Bytes)
}

func rootSHA1(contents []byte) (string, error) {
	certificate, err := parseCertificate(contents)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// Install updates native Docker trust locations when the current process can
// safely identify them. A container never modifies guessed host paths; it
// returns explicit per-platform instructions instead.
func Install(options Options) (Result, error) {
	if strings.TrimSpace(options.CAPath) == "" {
		return Result{}, errors.New("CA path is required")
	}
	contents, err := os.ReadFile(options.CAPath)
	if err != nil {
		return Result{}, fmt.Errorf("read local root CA: %w", err)
	}
	if len(contents) == 0 {
		return Result{}, errors.New("local root CA is empty")
	}
	managedFileName, err := managedFileName(options.ManagedFileName)
	if err != nil {
		return Result{}, err
	}
	names, err := registryNames(options.AdvertiseEndpoint)
	if err != nil {
		return Result{}, err
	}
	platform := options.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	if options.IsContainer {
		return Result{Instructions: containerInstructions(options.CAPath, names, managedFileName)}, nil
	}

	switch platform {
	case "windows":
		result, err := installWindowsRoot(options)
		if err != nil {
			return Result{Notices: []string{fmt.Sprintf("无法将根证书导入 Windows 当前用户根证书库: %v", err)}, Instructions: []string{
				fmt.Sprintf("certutil -user -addstore Root %s", shellQuote(options.CAPath)),
				"成功导入后重启 Docker Desktop。",
			}}, nil
		}
		result.Notices = append(result.Notices, "Docker Desktop 会从 Windows 用户信任根同步 CA；请重启 Docker Desktop 后再拉取镜像。")
		return result, nil
	case "linux":
		baseDirectory := options.LinuxCertsDir
		if baseDirectory == "" {
			baseDirectory = "/etc/docker/certs.d"
		}
		result, err := installInto(baseDirectory, names, contents, managedFileName)
		if err != nil {
			return Result{
				Notices: []string{fmt.Sprintf("无法写入 Docker 信任目录 %s: %v", baseDirectory, err)},
				Instructions: []string{
					fmt.Sprintf("sudo mkdir -p %s", shellQuote(filepath.Join(baseDirectory, names[0]))),
					fmt.Sprintf("sudo cp %s %s", shellQuote(options.CAPath), shellQuote(filepath.Join(baseDirectory, names[0], managedFileName))),
					"然后重启或重载 Docker daemon（具体方式取决于你的发行版）。",
				},
			}, nil
		}
		return result, nil
	case "darwin":
		result, err := installMacOSRoot(options)
		if err != nil {
			return Result{Notices: []string{fmt.Sprintf("无法将根证书导入 macOS 系统钥匙串: %v", err)}, Instructions: []string{
				fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", shellQuote(options.CAPath)),
				"成功导入后重启 Docker Desktop。",
			}}, nil
		}
		result.Notices = append(result.Notices, "系统钥匙串已更新；请重启 Docker Desktop 后再拉取镜像。")
		return result, nil
	default:
		return Result{Instructions: []string{
			fmt.Sprintf("请将 %s 作为根 CA 安装到运行 Docker daemon 的宿主机，再为 %s 配置 Registry 信任。", options.CAPath, strings.Join(names, "、")),
		}}, nil
	}
}

// InContainer reports conservative evidence that DRG is running inside a
// container. A false result only means no supported evidence was found.
func InContainer() bool {
	if os.Getenv("container") != "" || os.Getenv("CONTAINER") != "" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func installInto(baseDirectory string, names []string, contents []byte, managedFileName string) (Result, error) {
	result := Result{}
	for _, name := range names {
		directory := filepath.Join(baseDirectory, name)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return Result{}, err
		}
		path := filepath.Join(directory, managedFileName)
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			return Result{}, err
		}
		result.Installed = append(result.Installed, path)
	}
	return result, nil
}

func registryNames(advertiseEndpoint string) ([]string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(advertiseEndpoint))
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid advertise endpoint %q", advertiseEndpoint)
	}
	name := registryDirectoryName(host, port)
	desktopName := registryDirectoryName("host.docker.internal", port)
	if strings.EqualFold(name, desktopName) {
		return []string{name}, nil
	}
	return []string{name, desktopName}, nil
}

func registryDirectoryName(host, port string) string {
	if port == "443" {
		return host
	}
	if strings.Contains(host, ":") {
		return net.JoinHostPort(host, port)
	}
	return host + ":" + port
}

func containerInstructions(caPath string, names []string, managedFileName string) []string {
	joined := strings.Join(names, "、")
	return []string{
		fmt.Sprintf("容器内的 DRG 不会改写宿主机。将持久卷中的根证书 %s 复制到运行 Docker daemon 的宿主机。", caPath),
		fmt.Sprintf("Linux：对每个名称（%s）执行 sudo mkdir -p /etc/docker/certs.d/<名称>，再复制为 /etc/docker/certs.d/<名称>/%s。", joined, managedFileName),
		fmt.Sprintf("Windows Docker Desktop：执行 certutil -user -addstore Root %s，然后重启 Docker Desktop。", shellQuote(caPath)),
		fmt.Sprintf("macOS Docker Desktop：执行 sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s，然后重启 Docker Desktop。", shellQuote(caPath)),
	}
}

func managedFileName(configured string) (string, error) {
	if configured == "" {
		return managedCAFile, nil
	}
	if filepath.Base(configured) != configured || configured == "." || configured == string(filepath.Separator) {
		return "", errors.New("managed CA file name must not contain a path")
	}
	return configured, nil
}

func installWindowsRoot(options Options) (Result, error) {
	runner := options.CommandRunner
	if runner == nil {
		runner = func(name string, arguments ...string) ([]byte, error) {
			return exec.Command(name, arguments...).CombinedOutput()
		}
	}
	if _, err := runner("certutil", "-user", "-addstore", "Root", options.CAPath); err != nil {
		return Result{}, err
	}
	return Result{Installed: []string{"Windows CurrentUser Trusted Root Certification Authorities"}}, nil
}

func installMacOSRoot(options Options) (Result, error) {
	runner := options.CommandRunner
	if runner == nil {
		runner = func(name string, arguments ...string) ([]byte, error) {
			return exec.Command(name, arguments...).CombinedOutput()
		}
	}
	if _, err := runner("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", options.CAPath); err != nil {
		return Result{}, err
	}
	return Result{Installed: []string{"macOS System.keychain Trusted Roots"}}, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
