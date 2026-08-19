// Package cli implements the user-facing drg command contract.
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mattn/go-runewidth"

	"github.com/hjx/docker-registry-gateway/internal/certmanager"
	"github.com/hjx/docker-registry-gateway/internal/config"
	"github.com/hjx/docker-registry-gateway/internal/control"
	"github.com/hjx/docker-registry-gateway/internal/eventlog"
	"github.com/hjx/docker-registry-gateway/internal/gateway"
	"github.com/hjx/docker-registry-gateway/internal/healthhistory"
	"github.com/hjx/docker-registry-gateway/internal/lease"
	"github.com/hjx/docker-registry-gateway/internal/localca"
	"github.com/hjx/docker-registry-gateway/internal/onboard"
	"github.com/hjx/docker-registry-gateway/internal/provider"
	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/routeguard"
	"github.com/hjx/docker-registry-gateway/internal/router"
	"github.com/hjx/docker-registry-gateway/internal/tempstate"
	"github.com/hjx/docker-registry-gateway/internal/trust"
	"gopkg.in/yaml.v3"
)

// Run executes a drg command and returns a process-compatible exit code.
func Run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		printUsage(errorOutput)
		return 2
	}

	switch arguments[0] {
	case "onboard":
		return runOnboard(ctx, arguments[1:], input, output, errorOutput)
	case "config":
		return runConfig(arguments[1:], output, errorOutput)
	case "doctor":
		return runDoctor(ctx, arguments[1:], output, errorOutput)
	case "logs":
		return runLogs(ctx, "logs", arguments[1:], input, output, errorOutput)
	case "events":
		return runLogs(ctx, "events", arguments[1:], input, output, errorOutput)
	case "serve":
		return runServe(ctx, arguments[1:], output, errorOutput)
	case "start":
		return runStart(ctx, arguments[1:], output, errorOutput)
	case "status":
		return runStatus(ctx, arguments[1:], output, errorOutput)
	case "reload":
		return runReload(ctx, arguments[1:], output, errorOutput)
	case "stop":
		return runStop(ctx, arguments[1:], output, errorOutput)
	case "restart":
		return runRestart(ctx, arguments[1:], output, errorOutput)
	case "resolver":
		return runResolver(ctx, arguments[1:], output, errorOutput)
	case "tls":
		return runTLS(ctx, arguments[1:], output, errorOutput)
	case "provider":
		return runProvider(ctx, arguments[1:], output, errorOutput)
	case "help", "--help", "-h":
		printUsage(output)
		return 0
	default:
		fmt.Fprintf(errorOutput, "未知命令 %q。使用 drg help 查看可用命令。\n", arguments[0])
		return 2
	}
}

func runTLS(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(errorOutput, "用法：drg tls <reconcile|rotate-root|clear-previous-root> --config <路径>")
		return 2
	}
	switch arguments[0] {
	case "reconcile":
		return runTLSReconcile(ctx, arguments[1:], output, errorOutput)
	case "rotate-root":
		return runTLSRotateRoot(ctx, arguments[1:], output, errorOutput)
	case "clear-previous-root":
		return runTLSClearPreviousRoot(arguments[1:], output, errorOutput)
	default:
		fmt.Fprintln(errorOutput, "用法：drg tls <reconcile|rotate-root|clear-previous-root> --config <路径>")
		return 2
	}
}

func runTLSReconcile(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("tls reconcile", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	skipTrustInstall := flags.Bool("skip-trust-install", false, "跳过本次 Docker 信任安装")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "tls reconcile 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	if !loaded.Server.TLS.LocalCA {
		if loaded.Server.TLS.CertFile == "" {
			fmt.Fprintln(output, "local_ca 已关闭且未配置外部证书；纯 HTTP 后端没有可对账的证书材料。")
			return 0
		}
		if _, err := tls.LoadX509KeyPair(loaded.Server.TLS.CertFile, loaded.Server.TLS.KeyFile); err != nil {
			fmt.Fprintf(errorOutput, "外部 TLS 证书检查失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(output, "外部 TLS 证书可用：cert=%s，key=%s；本地 CA 对账不管理其续签或信任。\n", loaded.Server.TLS.CertFile, loaded.Server.TLS.KeyFile)
		return 0
	}
	result, err := reconcileTLS(ctx, loaded, *skipTrustInstall, output)
	if err != nil {
		fmt.Fprintf(errorOutput, "TLS 对账失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(output, "TLS 对账完成：CA=%s，证书=%s，本次新建根 CA=%t，本次签发叶子证书=%t\n", result.CAPath, result.Certificate, result.RootCreated, result.LeafIssued)
	return 0
}

func runTLSRotateRoot(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("tls rotate-root", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	skipTrustInstall := flags.Bool("skip-trust-install", false, "跳过本次 Docker 信任安装")
	activate := flags.Bool("activate", false, "确认新根已安装到 Docker 信任后，激活已准备的根轮换")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "tls rotate-root 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	if !loaded.Server.TLS.LocalCA {
		fmt.Fprintln(errorOutput, "tls rotate-root 只适用于 local_ca: true；外部证书应由其签发方轮换。")
		return 2
	}
	options := localca.Options{DataDir: loaded.DataDir, AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint}
	if *activate {
		result, err := localca.ActivateRootRotation(ctx, options)
		if err != nil {
			fmt.Fprintf(errorOutput, "本地 CA 轮换激活失败: %v\n", err)
			return 1
		}
		fmt.Fprintf(output, "根 CA 已轮换：新根=%s，旧根保留=%s。你已显式确认 Docker 已信任新根；旧根信任仅可通过 drg tls clear-previous-root 后清理。\n", result.CAPath, result.PreviousCAPath)
		printRotationRestartNotice(ctx, loaded, output)
		return 0
	}
	prepared, err := localca.PrepareRootRotation(ctx, options)
	if err != nil {
		fmt.Fprintf(errorOutput, "本地 CA 轮换准备失败: %v\n", err)
		return 1
	}
	if !loaded.Server.TLS.InstallTrust || *skipTrustInstall {
		fmt.Fprintf(output, "已准备新根 CA：%s。当前 Gateway 与旧根保持不变；请先将该证书作为额外 Docker 信任根安装，再执行 drg tls rotate-root --activate --config %s。\n", prepared.PendingCAPath, *configPath)
		return 0
	}
	trustResult, err := installRootTrust(loaded, prepared.PendingCAPath, "drg-ca-next.crt", output)
	if err != nil {
		fmt.Fprintf(errorOutput, "安装待激活 Docker 信任根失败: %v\n", err)
		return 1
	}
	if len(trustResult.Installed) == 0 {
		fmt.Fprintf(output, "新根仍处于待激活状态：请按上面的部署说明安装 %s，确认完成后执行 drg tls rotate-root --activate --config %s。\n", prepared.PendingCAPath, *configPath)
		return 0
	}
	result, err := localca.ActivateRootRotation(ctx, options)
	if err != nil {
		fmt.Fprintf(errorOutput, "Docker 已信任新根，但本地 CA 激活失败；当前 Gateway 继续使用旧根: %v\n", err)
		return 1
	}
	// The pending trust file keeps the new root valid throughout promotion. Add
	// stable current/previous names afterwards; a failure here is non-fatal to
	// trust continuity and is reported as a concrete manual follow-up.
	if _, trustErr := installRootTrust(loaded, result.PreviousCAPath, "drg-ca-previous.crt", output); trustErr != nil {
		fmt.Fprintf(output, "TLS 提示：旧根仍由现有 Docker 信任材料覆盖；未能写入稳定 previous 名称: %v\n", trustErr)
	}
	if _, trustErr := installRootTrust(loaded, result.CAPath, "", output); trustErr != nil {
		fmt.Fprintf(output, "TLS 提示：新根仍由待激活 Docker 信任材料覆盖；未能写入稳定 current 名称: %v\n", trustErr)
	}
	fmt.Fprintf(output, "根 CA 已轮换：新根=%s，旧根保留=%s。旧根信任仅可通过 drg tls clear-previous-root 后清理。\n", result.CAPath, result.PreviousCAPath)
	printRotationRestartNotice(ctx, loaded, output)
	return 0
}

func printRotationRestartNotice(ctx context.Context, loaded config.Config, output io.Writer) {
	statusContext, cancel := context.WithTimeout(ctx, time.Second)
	_, runningErr := control.StatusRequest(statusContext, loaded.DataDir)
	cancel()
	if runningErr == nil {
		fmt.Fprintln(output, "正在运行的 Gateway 仍可能使用旧叶证书；请执行 drg restart 完成安全切换。")
		return
	}
	fmt.Fprintln(output, "下次启动将使用新叶证书。")
}

func runTLSClearPreviousRoot(arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("tls clear-previous-root", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		if err == nil {
			fmt.Fprintln(errorOutput, "tls clear-previous-root 不接受位置参数")
		}
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	if !loaded.Server.TLS.LocalCA {
		fmt.Fprintln(errorOutput, "tls clear-previous-root 只适用于 local_ca: true")
		return 2
	}
	if err := localca.ClearPreviousRoot(loaded.DataDir); err != nil {
		fmt.Fprintf(errorOutput, "清理上一根本地 CA 失败: %v\n", err)
		return 1
	}
	fmt.Fprintln(output, "已显式清理本地旧根标记。请同时按部署平台从 Docker 信任库清理 drg-ca-previous.crt（或对应旧根），随后才可再次轮换。")
	return 0
}

func runProvider(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(errorOutput, "用法：drg provider <list|add|remove> ...")
		return 2
	}
	switch arguments[0] {
	case "list":
		return runProviderList(arguments[1:], output, errorOutput)
	case "add":
		return runProviderAdd(ctx, arguments[1:], output, errorOutput)
	case "remove":
		return runProviderRemove(ctx, arguments[1:], output, errorOutput)
	default:
		fmt.Fprintf(errorOutput, "未知 Provider 命令 %q。可用命令：list、add、remove。\n", arguments[0])
		return 2
	}
}

func runProviderList(arguments []string, output, errorOutput io.Writer) int {
	loaded, exitCode := loadControlConfiguration("provider list", arguments, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	for _, provider := range loaded.Providers {
		roles := make([]string, 0, 2)
		if provider.Resolver {
			roles = append(roles, "resolver")
		}
		if provider.PullProvider {
			roles = append(roles, "pull")
		}
		priority := ""
		if provider.Priority != nil {
			priority = fmt.Sprintf("；priority=%d", *provider.Priority)
		}
		fmt.Fprintf(output, "%s：%s；角色=%s%s\n", provider.Name, provider.URL, strings.Join(roles, ","), priority)
	}
	return 0
}

func runProviderAdd(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("provider add", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	name := flags.String("name", "", "Provider 名称")
	address := flags.String("url", "", "Provider Registry URL")
	resolver := flags.Bool("resolver", false, "作为 manifest 解析源")
	pullProvider := flags.Bool("pull-provider", true, "作为 blob 下载源")
	priority := flags.String("priority", "", "可选解析优先级（非负整数）")
	username := flags.String("username", "", "上游用户名")
	password := flags.String("password", "", "上游密码或 PAT（不推荐明文）")
	secretFile := flags.String("secret-file", "", "含单行密码或 PAT 的文件")
	caFile := flags.String("ca-file", "", "上游 HTTPS 私有根证书")
	allowInsecureHTTP := flags.Bool("allow-insecure-http", false, "允许 HTTP Provider")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		if err == nil {
			fmt.Fprintln(errorOutput, "provider add 不接受位置参数")
		}
		return 2
	}
	if strings.TrimSpace(*name) == "" || strings.TrimSpace(*address) == "" {
		fmt.Fprintln(errorOutput, "provider add 必须提供 --name 和 --url")
		return 2
	}
	if !*resolver && !*pullProvider {
		fmt.Fprintln(errorOutput, "Provider 至少必须承担 resolver 或 pull-provider 之一")
		return 2
	}
	loaded, resolvedConfigPath, exitCode := loadConfigAtPath(*configPath, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	provider := config.Provider{
		Name:              strings.TrimSpace(*name),
		URL:               strings.TrimSpace(*address),
		Resolver:          *resolver,
		PullProvider:      *pullProvider,
		AllowInsecureHTTP: *allowInsecureHTTP,
		Auth: config.Auth{
			Username: strings.TrimSpace(*username),
			Password: strings.TrimSpace(*password),
		},
	}
	if *secretFile != "" {
		provider.Auth.SecretFile = resolveCLIPath(resolvedConfigPath, *secretFile)
	}
	if *caFile != "" {
		provider.CAFile = resolveCLIPath(resolvedConfigPath, *caFile)
	}
	if *priority != "" {
		value, err := strconv.Atoi(*priority)
		if err != nil || value < 0 {
			fmt.Fprintln(errorOutput, "--priority 必须是非负整数")
			return 2
		}
		provider.Priority = &value
	}
	candidate := loaded
	candidate.Providers = append(append([]config.Provider(nil), loaded.Providers...), provider)
	if err := candidate.Validate(); err != nil {
		fmt.Fprintf(errorOutput, "Provider 配置无效，未进行准入探测: %v\n", err)
		return 2
	}
	probeResult, err := probeProviderAdmissionWithGuard(ctx, provider, candidate.ProbeRef, candidate.AllowNonRangeProviders, routeguard.New(externalInstanceID(candidate.DataDir), 3))
	if err != nil {
		fmt.Fprintf(errorOutput, "Provider %s 准入探测失败，未写入配置: %v\n", provider.Name, err)
		return 1
	}
	if probeResult.RangeSupported {
		fmt.Fprintf(output, "Provider %s 准入探测通过：支持 Range 续传。\n", provider.Name)
	} else {
		fmt.Fprintf(output, "Provider %s 准入探测通过但不支持 Range：将作为降级下载源。\n", provider.Name)
	}
	return applyProviderConfiguration(ctx, resolvedConfigPath, candidate, "已添加 Provider "+provider.Name, output, errorOutput)
}

func probeProviderAdmission(parent context.Context, configured config.Provider, probeRef string, allowNonRange bool) (provider.ProbeResult, error) {
	return probeProviderAdmissionWithGuard(parent, configured, probeRef, allowNonRange, routeguard.Guard{})
}

func probeProviderAdmissionWithGuard(parent context.Context, configured config.Provider, probeRef string, allowNonRange bool, guard routeguard.Guard) (provider.ProbeResult, error) {
	username, password, err := configured.Auth.Credentials()
	if err != nil {
		return provider.ProbeResult{}, fmt.Errorf("读取上游凭据: %w", err)
	}
	client, err := provider.New(provider.Options{
		URL:        configured.URL,
		Username:   username,
		Password:   password,
		CAFile:     configured.CAFile,
		RouteGuard: guard,
	})
	if err != nil {
		return provider.ProbeResult{}, err
	}
	probeContext, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	result, err := client.Probe(probeContext, probeRef)
	if err != nil {
		return provider.ProbeResult{}, err
	}
	if !result.RangeSupported && !allowNonRange {
		return provider.ProbeResult{}, errors.New("上游不支持 Range，且 allow_non_range_providers 已关闭")
	}
	return result, nil
}

func runProviderRemove(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("provider remove", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 1 || strings.TrimSpace(flags.Arg(0)) == "" {
		fmt.Fprintln(errorOutput, "用法：drg provider remove --config <路径> <名称>")
		return 2
	}
	loaded, resolvedConfigPath, exitCode := loadConfigAtPath(*configPath, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	name := strings.TrimSpace(flags.Arg(0))
	candidate := loaded
	candidate.Providers = make([]config.Provider, 0, len(loaded.Providers)-1)
	removed := false
	for _, provider := range loaded.Providers {
		if provider.Name == name {
			removed = true
			continue
		}
		candidate.Providers = append(candidate.Providers, provider)
	}
	if !removed {
		fmt.Fprintf(errorOutput, "Provider %q 不存在。\n", name)
		return 1
	}
	return applyProviderConfiguration(ctx, resolvedConfigPath, candidate, "已删除 Provider "+name, output, errorOutput)
}

func loadConfigAtPath(path string, errorOutput io.Writer) (config.Config, string, int) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	loaded, err := config.LoadFile(absPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return config.Config{}, "", 1
	}
	return loaded, absPath, 0
}

func applyProviderConfiguration(ctx context.Context, configPath string, candidate config.Config, message string, output, errorOutput io.Writer) int {
	if err := candidate.Validate(); err != nil {
		fmt.Fprintf(errorOutput, "Provider 配置无效，未写入配置: %v\n", err)
		return 2
	}
	backupPath, original, err := writeConfigurationWithBackup(configPath, candidate)
	if err != nil {
		fmt.Fprintf(errorOutput, "保存 Provider 配置失败: %v\n", err)
		return 1
	}
	if _, infoErr := control.LoadInfo(candidate.DataDir); infoErr == nil {
		if reloadErr := control.ReloadRequest(ctx, candidate.DataDir); reloadErr != nil {
			if restoreErr := activateConfiguration(configPath, original); restoreErr != nil {
				fmt.Fprintf(errorOutput, "热加载失败且无法恢复旧配置: %v；恢复错误: %v\n", reloadErr, restoreErr)
			} else {
				fmt.Fprintf(errorOutput, "热加载失败，已恢复旧配置: %v\n", reloadErr)
			}
			return 1
		}
		fmt.Fprintf(output, "%s；已热加载；备份=%s\n", message, backupPath)
		return 0
	}
	fmt.Fprintf(output, "%s；服务未运行，已保存配置；下次 start 或手动 reload 生效；备份=%s\n", message, backupPath)
	return 0
}

func writeConfigurationWithBackup(path string, candidate config.Config) (string, []byte, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	localCA := candidate.Server.TLS.LocalCA
	candidate.Server.TLS.LocalCASpecified = &localCA
	installTrust := candidate.Server.TLS.InstallTrust
	candidate.Server.TLS.InstallTrustSpecified = &installTrust
	allowNonRange := candidate.AllowNonRangeProviders
	candidate.AllowNonRangeProvidersSpecified = &allowNonRange
	contents, err := yaml.Marshal(candidate)
	if err != nil {
		return "", nil, err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".drg-provider-*.yaml")
	if err != nil {
		return "", nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", nil, err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return "", nil, err
	}
	if err := temporary.Close(); err != nil {
		return "", nil, err
	}
	if _, err := config.LoadFile(temporaryPath); err != nil {
		return "", nil, fmt.Errorf("完整校验候选配置: %w", err)
	}
	backupPath := path + ".bak"
	if err := os.WriteFile(backupPath, original, 0o600); err != nil {
		return "", nil, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", nil, err
	}
	return backupPath, original, nil
}

func activateConfiguration(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".drg-restore-*.yaml")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func resolveCLIPath(configPath, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(filepath.Dir(configPath), value)
}

func reconcileTLS(ctx context.Context, loaded config.Config, skipTrustInstall bool, output io.Writer) (localca.Result, error) {
	result, err := localca.Reconcile(ctx, localca.Options{
		DataDir:           loaded.DataDir,
		AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
	})
	if err != nil {
		return localca.Result{}, err
	}
	if !loaded.Server.TLS.InstallTrust || skipTrustInstall {
		return result, nil
	}
	if _, err := installRootTrust(loaded, result.CAPath, "", output); err != nil {
		return localca.Result{}, err
	}
	return result, nil
}

func installRootTrust(loaded config.Config, caPath, managedFileName string, output io.Writer) (trust.Result, error) {
	trustResult, err := trust.Install(trust.Options{
		CAPath:            caPath,
		AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
		ManagedFileName:   managedFileName,
		IsContainer:       trust.InContainer(),
	})
	if err != nil {
		return trust.Result{}, fmt.Errorf("安装 Docker 信任根: %w", err)
	}
	for _, path := range trustResult.Installed {
		fmt.Fprintf(output, "Docker 信任根已安装：%s\n", path)
	}
	for _, notice := range trustResult.Notices {
		fmt.Fprintf(output, "TLS 提示：%s\n", notice)
	}
	for _, instruction := range trustResult.Instructions {
		fmt.Fprintf(output, "TLS 操作：%s\n", instruction)
	}
	return trustResult, nil
}

const (
	providerProbeInterval        = 15 * time.Minute
	certificateReconcileInterval = 24 * time.Hour
)

func runServe(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "serve 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	eventRetention, healthRetention, err := retentionConfiguration(loaded)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取诊断文件保留配置失败: %v\n", err)
		return 1
	}
	events := eventlog.New(loaded.DataDir, time.Now, eventRetention)
	serviceLogs := newServiceLogger(events, output)
	for _, warning := range loaded.SecurityWarnings() {
		serviceLogs.log("warning", "security_warning", warning.Message)
	}

	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		absConfigPath = *configPath
	}
	var certificateManager *certmanager.Manager
	instanceID := externalInstanceID(loaded.DataDir)
	if loaded.Server.TLS.LocalCA {
		tlsResult, reconcileErr := reconcileTLS(ctx, loaded, false, serviceLogs)
		if reconcileErr != nil {
			serviceLogs.log("error", "tls_reconcile_failed", "TLS 对账失败；Gateway 未启动")
			fmt.Fprintf(errorOutput, "TLS 对账失败: %v\n", reconcileErr)
			return 1
		}
		manager, loadErr := certmanager.New(tlsResult.Certificate, tlsResult.PrivateKey)
		if loadErr != nil {
			serviceLogs.log("error", "tls_certificate_load_failed", "加载服务端证书失败；Gateway 未启动")
			fmt.Fprintf(errorOutput, "加载服务端证书失败: %v\n", loadErr)
			return 1
		}
		certificateManager = manager
		instanceID = tlsResult.InstanceID
	} else if loaded.Server.TLS.CertFile != "" {
		manager, loadErr := certmanager.New(loaded.Server.TLS.CertFile, loaded.Server.TLS.KeyFile)
		if loadErr != nil {
			serviceLogs.log("error", "tls_certificate_load_failed", "加载外部服务端证书失败；Gateway 未启动")
			fmt.Fprintf(errorOutput, "加载外部服务端证书失败: %v\n", loadErr)
			return 1
		}
		certificateManager = manager
	} else {
		serviceLogs.log("warning", "tls_http_backend", "local_ca 已关闭且未配置 cert_file/key_file，Gateway 使用纯 HTTP 后端监听")
	}
	routeGuard := routeguard.New(instanceID, 3)
	admitProvider := func(parent context.Context, configured config.Provider, probeRef string, allowNonRange bool) (provider.ProbeResult, error) {
		return probeProviderAdmissionWithGuard(parent, configured, probeRef, allowNonRange, routeGuard)
	}
	if err := requireRangeProviderAdmission(ctx, loaded, admitProvider); err != nil {
		serviceLogs.log("error", "provider_admission_failed", "Provider Range 准入失败；Gateway 未启动")
		fmt.Fprintf(errorOutput, "Provider Range 准入失败: %v\n", err)
		return 1
	}
	tracker := router.NewHealth()
	healthStore := healthhistory.Open(filepath.Join(loaded.DataDir, "provider-health.json"), time.Now, healthRetention)
	if snapshots, loadErr := healthStore.Load(healthRetention); loadErr != nil {
		serviceLogs.log("warning", "health_history_load_failed", "读取 Provider 健康历史失败；将以空历史启动")
		fmt.Fprintf(errorOutput, "读取 Provider 健康历史失败，将以空历史启动: %v\n", loadErr)
	} else {
		tracker.Restore(snapshots)
	}
	temporaryDiskQuota, err := config.ParseByteSize(loaded.Resources.TemporaryDiskQuota)
	if err != nil {
		serviceLogs.log("error", "temporary_disk_quota_invalid", "读取临时磁盘配额失败；Gateway 未启动")
		fmt.Fprintf(errorOutput, "读取临时磁盘配额失败: %v\n", err)
		return 1
	}
	tempBudget := router.NewTempBudget(temporaryDiskQuota)
	temporaryWorkspace, err := tempstate.Prepare(loaded.Resources.TempDir, loaded.DataDir)
	if err != nil {
		serviceLogs.log("error", "temporary_workspace_prepare_failed", "初始化分片临时目录失败；Gateway 未启动")
		fmt.Fprintf(errorOutput, "初始化分片临时目录失败: %v\n", err)
		return 1
	}
	defer func() {
		if cleanupErr := temporaryWorkspace.Close(); cleanupErr != nil {
			serviceLogs.log("warning", "temporary_workspace_cleanup_failed", "清理分片临时目录失败；下次启动将安全重试")
			fmt.Fprintf(errorOutput, "清理分片临时目录失败（下次启动将安全重试）: %v\n", cleanupErr)
		}
	}()
	eventObserver := router.ObserverFunc(func(event router.Event) {
		_ = events.Write(eventlog.Event{
			Level:        event.Level,
			Code:         event.Code,
			Provider:     event.Provider,
			Repository:   event.Repository,
			Reference:    event.Reference,
			Digest:       event.Digest,
			ResumeOffset: event.ResumeOffset,
			Message:      event.Message,
		})
	})
	if certificateManager != nil {
		stopCertificateMaintenance := startCertificateMaintenance(ctx, certificateReconcileInterval, func() error {
			if loaded.Server.TLS.LocalCA {
				result, err := reconcileTLS(ctx, loaded, true, io.Discard)
				if err != nil {
					return err
				}
				if !result.LeafIssued {
					return nil
				}
			}
			return certificateManager.Reload()
		}, func(err error) {
			serviceLogs.log("warning", "tls_maintenance_failed", "TLS 定期维护失败；当前已加载的证书继续服务")
			fmt.Fprintf(errorOutput, "TLS 定期维护失败；当前已加载的证书继续服务，新连接不会使用未验证的新证书: %v\n", err)
		})
		defer stopCertificateMaintenance()
	}
	runtimeRouter, err := buildRouter(loaded, []byte(absConfigPath), tracker, tempBudget, temporaryWorkspace.Dir, routeGuard, eventObserver)
	if err != nil {
		serviceLogs.log("error", "router_initialize_failed", "初始化 Provider 路由失败；Gateway 未启动")
		fmt.Fprintf(errorOutput, "初始化 Provider 路由失败: %v\n", err)
		return 1
	}
	backend := gateway.New(runtimeRouter, gateway.Options{
		MaxConcurrentPulls: loaded.Resources.MaxConcurrentPulls,
		MaxQueuedPulls:     loaded.Resources.MaxQueuedPulls,
	})
	server := &http.Server{
		Handler: gateway.LimitRequests(registry.NewHandlerWithOptions(backend, registry.HandlerOptions{
			RouteGuard: routeGuard,
			OnEvent: func(event registry.HandlerEvent) {
				_ = events.Write(eventlog.Event{Level: event.Level, Code: event.Code, Message: event.Message})
			},
		}), loaded.Resources.MaxInflightRequests),
	}
	if certificateManager != nil {
		server.TLSConfig = &tls.Config{GetCertificate: certificateManager.GetCertificate, MinVersion: tls.VersionTLS12}
	}

	listeners := make([]net.Listener, 0, len(loaded.Server.Listeners))
	for _, address := range loaded.Server.Listeners {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, opened := range listeners {
				opened.Close()
			}
			serviceLogs.log("error", "listener_open_failed", "监听地址失败；Gateway 未启动")
			fmt.Fprintf(errorOutput, "监听 %s 失败: %v\n", address, err)
			return 1
		}
		if server.TLSConfig != nil {
			listener = tls.NewListener(listener, server.TLSConfig)
		}
		listeners = append(listeners, listener)
	}
	listenersForStatus := append([]string(nil), loaded.Server.Listeners...)
	var reloadMu sync.Mutex
	currentConfig := loaded
	probeContext, stopProbing := context.WithCancel(ctx)
	serviceLogs.log("info", "gateway_started", "Gateway 已启动；监听："+strings.Join(loaded.Server.Listeners, ", ")+"；本地控制面正在初始化")
	var probeMu sync.Mutex
	var probeGroup sync.WaitGroup
	probesStopping := false
	probesRunning := false
	probeOutput := &lockedWriter{writer: output}
	persistHealth := func() {
		if err := healthStore.Save(tracker.Snapshot()); err != nil {
			serviceLogs.log("warning", "health_history_save_failed", "保存 Provider 健康历史失败")
			fmt.Fprintf(probeOutput, "保存 Provider 健康历史失败: %v\n", err)
		}
	}
	healthStopping := make(chan struct{})
	var healthGroup sync.WaitGroup
	healthGroup.Add(1)
	go func() {
		defer healthGroup.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-healthStopping:
				return
			case <-ticker.C:
				persistHealth()
			}
		}
	}()
	defer func() {
		close(healthStopping)
		healthGroup.Wait()
		persistHealth()
	}()
	mayProbe := func() bool {
		return backend.ActivePulls() == 0 && backend.QueuedPulls() == 0 && !tracker.HasRecentPullActivity(providerProbeInterval)
	}
	launchProbe := func(configuration config.Config) {
		probeMu.Lock()
		if probesStopping || probesRunning || !mayProbe() {
			probeMu.Unlock()
			return
		}
		probesRunning = true
		probeGroup.Add(1)
		probeMu.Unlock()
		go func() {
			defer func() {
				probeMu.Lock()
				probesRunning = false
				probeMu.Unlock()
				probeGroup.Done()
			}()
			probeProviders(probeContext, configuration, events, routeGuard, tracker)
		}()
	}
	defer func() {
		probeMu.Lock()
		probesStopping = true
		stopProbing()
		probeMu.Unlock()
		probeGroup.Wait()
	}()
	stopPeriodicProbes := startPeriodicProviderProbes(probeContext, providerProbeInterval, func() config.Config {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		return currentConfig
	}, mayProbe, launchProbe)
	defer stopPeriodicProbes()
	localControl, err := control.Start(loaded.DataDir, control.Callbacks{
		Status: func() control.Status {
			return control.Status{
				State:       "running",
				Listeners:   append([]string(nil), listenersForStatus...),
				ActivePulls: backend.ActivePulls(),
				QueuedPulls: backend.QueuedPulls(),
				Providers:   providerHealthStatuses(tracker.Snapshot()),
			}
		},
		Reload: func(_ context.Context) error {
			reloadMu.Lock()
			defer reloadMu.Unlock()
			candidate, err := config.LoadFile(absConfigPath)
			if err != nil {
				return fmt.Errorf("读取或校验新配置: %w", err)
			}
			if !sameServeConfiguration(currentConfig, candidate) || resourceConfigurationChanged(currentConfig, candidate) {
				return errors.New("监听地址、访问地址、TLS 模式、data_dir 或资源上限已改变，需要使用 drg restart")
			}
			if resolverConfigurationChanged(currentConfig, candidate) {
				store, storeErr := lease.Open(filepath.Join(currentConfig.DataDir, "decision-leases.json"), time.Now())
				if storeErr == nil {
					if err := store.Clear(); err != nil {
						return fmt.Errorf("清空旧解析租约: %w", err)
					}
				}
			}
			if err := requireRangeProviderAdmission(probeContext, candidate, admitProvider); err != nil {
				return fmt.Errorf("Provider Range 准入失败: %w", err)
			}
			replacement, err := buildRouter(candidate, []byte(absConfigPath), tracker, tempBudget, temporaryWorkspace.Dir, routeGuard, eventObserver)
			if err != nil {
				return err
			}
			backend.Replace(replacement)
			currentConfig = candidate
			launchProbe(candidate)
			return nil
		},
		Stop: func(_ context.Context, force bool) error {
			backend.StopAccepting()
			if force {
				return server.Close()
			}
			shutdownContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownContext); err != nil {
				return server.Close()
			}
			return nil
		},
	})
	if err != nil {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		serviceLogs.log("error", "local_control_start_failed", "启动本地控制面失败；Gateway 未启动")
		fmt.Fprintf(errorOutput, "启动本地控制面失败: %v\n", err)
		return 1
	}
	defer localControl.Close()
	serviceLogs.log("info", "gateway_ready", "Gateway 已就绪；可使用 drg status、drg reload、drg stop 或 drg logs --follow")
	launchProbe(loaded)

	serveErrors := make(chan error, len(listeners))
	var group sync.WaitGroup
	for _, listener := range listeners {
		group.Add(1)
		go func(listener net.Listener) {
			defer group.Done()
			serveErrors <- server.Serve(listener)
		}(listener)
	}
	select {
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		group.Wait()
		serviceLogs.log("info", "gateway_stopped", "Gateway 已停止")
		return 0
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			serviceLogs.log("error", "gateway_stopped_unexpected", "Gateway 因监听服务错误停止")
			fmt.Fprintf(errorOutput, "服务停止: %v\n", serveErr)
			_ = server.Close()
			group.Wait()
			return 1
		}
		group.Wait()
		serviceLogs.log("info", "gateway_stopped", "Gateway 已停止")
		return 0
	}
}

func probeProviders(parent context.Context, loaded config.Config, events *eventlog.Log, routeGuard routeguard.Guard, tracker *router.Health) {
	for _, configured := range loaded.Providers {
		if parent.Err() != nil {
			return
		}
		probeContext, cancel := context.WithTimeout(parent, 15*time.Second)
		username, password, err := configured.Auth.Credentials()
		if err == nil {
			var client *provider.Client
			client, err = provider.New(provider.Options{
				URL:        configured.URL,
				Username:   username,
				Password:   password,
				CAFile:     configured.CAFile,
				RouteGuard: routeGuard,
			})
			if err == nil {
				result, probeErr := client.Probe(probeContext, loaded.ProbeRef)
				if probeErr == nil {
					if result.RangeSupported {
						tracker.RecordProbeSuccess(configured.Name)
						_ = events.Write(eventlog.Event{Level: "info", Code: "provider_probe_ok", Provider: configured.Name, Message: "准入探测通过：支持 Range 续传"})
					} else if loaded.AllowNonRangeProviders {
						tracker.RecordProbeSuccess(configured.Name)
						_ = events.Write(eventlog.Event{Level: "info", Code: "provider_probe_ok", Provider: configured.Name, Message: "准入探测通过但不支持 Range；仅作为降级下载源"})
					} else {
						tracker.RecordRangeUnsupported(configured.Name)
						_ = events.Write(eventlog.Event{Level: "warning", Code: "provider_range_unsupported", Provider: configured.Name, Message: "准入探测不通过：不支持 Range，当前配置已禁用无 Range Provider"})
					}
					cancel()
					continue
				}
				err = probeErr
			}
		}
		cancel()
		if parent.Err() != nil {
			return
		}
		tracker.RecordProviderFailure(configured.Name, err)
		_ = events.Write(eventlog.Event{Level: "warning", Code: "provider_probe_failed", Provider: configured.Name, Message: "Provider 主动探测失败；服务将继续运行，并在下一次主动探测或后续拉取中恢复"})
	}
}

// requireRangeProviderAdmission keeps hand-edited configuration from bypassing
// the same Range requirement enforced by `drg provider add`. A Provider used
// only for manifest resolution never serves blob bytes, so it does not need a
// Range capability check.
func requireRangeProviderAdmission(parent context.Context, loaded config.Config, probe func(context.Context, config.Provider, string, bool) (provider.ProbeResult, error)) error {
	if loaded.AllowNonRangeProviders {
		return nil
	}
	if probe == nil {
		return errors.New("Provider Range 准入器不可用")
	}
	for _, configured := range loaded.Providers {
		if !configured.PullProvider {
			continue
		}
		result, err := probe(parent, configured, loaded.ProbeRef, false)
		if err != nil {
			return fmt.Errorf("Provider %s: %w", configured.Name, err)
		}
		if !result.RangeSupported {
			return fmt.Errorf("Provider %s 不支持 Range", configured.Name)
		}
	}
	return nil
}

// startPeriodicProviderProbes runs low-frequency, bounded admission probes so
// an idle or previously unavailable Provider can recover without waiting for a
// user pull. The current configuration is fetched on every tick, which keeps
// successful hot reloads visible without mutating in-flight transfers.
func startPeriodicProviderProbes(parent context.Context, interval time.Duration, current func() config.Config, idle func() bool, launch func(config.Config)) func() {
	if interval <= 0 || current == nil || idle == nil || launch == nil {
		return func() {}
	}
	stopping := make(chan struct{})
	var once sync.Once
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-parent.Done():
				return
			case <-stopping:
				return
			case <-ticker.C:
				select {
				case <-parent.Done():
					return
				case <-stopping:
					return
				default:
				}
				if idle() {
					launch(current())
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(stopping)
			group.Wait()
		})
	}
}

// startCertificateMaintenance reconciles local CA leaf certificates, or
// reloads externally managed files, without interrupting active TLS sessions.
// A failed pass deliberately leaves the last known-good certificate active.
func startCertificateMaintenance(parent context.Context, interval time.Duration, maintain func() error, report func(error)) func() {
	if interval <= 0 || maintain == nil {
		return func() {}
	}
	stopping := make(chan struct{})
	var once sync.Once
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-parent.Done():
				return
			case <-stopping:
				return
			case <-ticker.C:
				if err := maintain(); err != nil && report != nil {
					report(err)
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(stopping)
			group.Wait()
		})
	}
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *lockedWriter) Write(contents []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.writer.Write(contents)
}

func buildRouter(loaded config.Config, salt []byte, tracker *router.Health, tempBudget *router.TempBudget, temporaryDir string, routeGuard routeguard.Guard, observer router.Observer) (*router.Router, error) {
	sources := make([]router.Source, 0, len(loaded.Providers))
	for _, configured := range loaded.Providers {
		username, password, err := configured.Auth.Credentials()
		if err != nil {
			return nil, fmt.Errorf("读取 Provider %q 凭据: %w", configured.Name, err)
		}
		client, err := provider.New(provider.Options{
			URL:        configured.URL,
			Username:   username,
			Password:   password,
			CAFile:     configured.CAFile,
			RouteGuard: routeGuard,
		})
		if err != nil {
			return nil, fmt.Errorf("初始化 Provider %q: %w", configured.Name, err)
		}
		sources = append(sources, router.Source{
			Name:         configured.Name,
			Resolver:     configured.Resolver,
			PullProvider: configured.PullProvider,
			Priority:     configured.Priority,
			Backend:      client,
		})
	}
	maxNoRangeRestartDiscard, err := config.ParseByteSize(loaded.Resources.MaxNoRangeRestartDiscard)
	if err != nil {
		return nil, fmt.Errorf("读取无 Range 重拉预算: %w", err)
	}
	minSegmentSize, err := config.ParseByteSize(loaded.Resources.MinSegmentSize)
	if err != nil {
		return nil, fmt.Errorf("读取最小分片大小: %w", err)
	}
	decisionLease, err := time.ParseDuration(loaded.Resolution.DecisionLease)
	if err != nil {
		return nil, fmt.Errorf("读取解析租约时长: %w", err)
	}
	leaseStore, err := lease.Open(filepath.Join(loaded.DataDir, "decision-leases.json"), time.Now())
	if err != nil {
		// A damaged historical lease must not prevent image pulls. The Router
		// continues with a process-local lease until an operator can inspect
		// or replace the malformed file.
		leaseStore, _ = lease.Open("", time.Now())
	}
	return router.New(sources, router.Options{
		ConflictStrategy:         loaded.Resolution.ConflictStrategy,
		TieBreaker:               loaded.Resolution.TieBreaker,
		Salt:                     salt,
		NoRangeRestartEnabled:    &loaded.AllowNonRangeProviders,
		MaxNoRangeRestartDiscard: maxNoRangeRestartDiscard,
		DecisionLease:            decisionLease,
		LeaseStore:               leaseStore,
		Health:                   tracker,
		MaxSegmentsPerBlob:       loaded.Resources.MaxSegmentsPerBlob,
		MinSegmentSize:           minSegmentSize,
		TemporaryDir:             temporaryDir,
		TempBudget:               tempBudget,
		Observer:                 observer,
	}), nil
}

func resolverConfigurationChanged(current, candidate config.Config) bool {
	if current.Resolution.ConflictStrategy != candidate.Resolution.ConflictStrategy ||
		current.Resolution.TieBreaker != candidate.Resolution.TieBreaker ||
		current.Resolution.DecisionLease != candidate.Resolution.DecisionLease {
		return true
	}
	leftResolvers := resolverSignature(current.Providers)
	rightResolvers := resolverSignature(candidate.Providers)
	if len(leftResolvers) != len(rightResolvers) {
		return true
	}
	for index := range leftResolvers {
		if leftResolvers[index] != rightResolvers[index] {
			return true
		}
	}
	return false
}

func resolverSignature(providers []config.Provider) []string {
	result := make([]string, 0, len(providers))
	for _, provider := range providers {
		if provider.Resolver {
			result = append(result, strings.Join([]string{provider.Name, provider.URL, priorityValue(provider.Priority)}, "\x00"))
		}
	}
	return result
}

func priorityValue(value *int) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func sameServeConfiguration(current, candidate config.Config) bool {
	if current.DataDir != candidate.DataDir ||
		current.Server.TLS.LocalCA != candidate.Server.TLS.LocalCA ||
		current.Server.TLS.AdvertiseEndpoint != candidate.Server.TLS.AdvertiseEndpoint ||
		current.Server.TLS.CertFile != candidate.Server.TLS.CertFile ||
		current.Server.TLS.KeyFile != candidate.Server.TLS.KeyFile ||
		len(current.Server.Listeners) != len(candidate.Server.Listeners) {
		return false
	}
	for index := range current.Server.Listeners {
		if current.Server.Listeners[index] != candidate.Server.Listeners[index] {
			return false
		}
	}
	return true
}

func externalInstanceID(dataDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dataDir)))
	return fmt.Sprintf("drg:%x", sum[:])
}

func retentionConfiguration(loaded config.Config) (eventlog.Options, time.Duration, error) {
	eventRetention, err := time.ParseDuration(loaded.Retention.EventRetention)
	if err != nil || eventRetention <= 0 {
		return eventlog.Options{}, 0, errors.New("event_retention must be a positive Go duration")
	}
	eventMaxBytes, err := config.ParseByteSize(loaded.Retention.EventMaxBytes)
	if err != nil || eventMaxBytes <= 0 {
		return eventlog.Options{}, 0, errors.New("event_max_bytes must be a positive byte quantity")
	}
	healthRetention, err := time.ParseDuration(loaded.Retention.HealthRetention)
	if err != nil || healthRetention <= 0 {
		return eventlog.Options{}, 0, errors.New("health_retention must be a positive Go duration")
	}
	return eventlog.Options{Retention: eventRetention, MaxBytes: eventMaxBytes}, healthRetention, nil
}

func admissionConfigurationChanged(current, candidate config.Config) bool {
	return current.Resources.MaxConcurrentPulls != candidate.Resources.MaxConcurrentPulls ||
		current.Resources.MaxInflightRequests != candidate.Resources.MaxInflightRequests ||
		current.Resources.MaxQueuedPulls != candidate.Resources.MaxQueuedPulls
}

func resourceConfigurationChanged(current, candidate config.Config) bool {
	return admissionConfigurationChanged(current, candidate) ||
		current.Resources.MaxSegmentsPerBlob != candidate.Resources.MaxSegmentsPerBlob ||
		current.Resources.TemporaryDiskQuota != candidate.Resources.TemporaryDiskQuota ||
		current.Resources.MinSegmentSize != candidate.Resources.MinSegmentSize ||
		current.Resources.MaxNoRangeRestartDiscard != candidate.Resources.MaxNoRangeRestartDiscard ||
		current.Resources.TempDir != candidate.Resources.TempDir
}

func runStatus(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	loaded, exitCode := loadControlConfiguration("status", arguments, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	status, err := control.StatusRequest(ctx, loaded.DataDir)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取运行状态失败: %v\n", err)
		return 1
	}
	fmt.Fprint(output, formatStatus(status))
	return 0
}

func formatStatus(status control.Status) string {
	var output strings.Builder
	output.WriteString("Gateway\n")
	writeStatusSummary(&output, [][2]string{
		{"状态", status.State},
		{"PID", strconv.Itoa(status.PID)},
		{"监听地址", strings.Join(status.Listeners, ", ")},
		{"活跃拉取", strconv.Itoa(status.ActivePulls)},
		{"排队拉取", strconv.Itoa(status.QueuedPulls)},
	})
	output.WriteString("\nProviders\n")
	if len(status.Providers) == 0 {
		output.WriteString("  无\n")
		return output.String()
	}

	headers := []string{"Provider", "状态", "吞吐", "首字节", "失败", "最近成功", "最近失败"}
	rows := make([][]string, 0, len(status.Providers))
	for _, provider := range status.Providers {
		rows = append(rows, []string{
			provider.Name,
			formatProviderState(provider),
			fmt.Sprintf("%.2f MiB/s", provider.ThroughputBytesPerSecond/(1<<20)),
			fmt.Sprintf("%.0f ms", provider.FirstByteMillis),
			strconv.Itoa(provider.Failures),
			formatHealthTime(provider.LastSuccess),
			formatHealthTime(provider.LastFailure),
		})
	}
	writeStatusTable(&output, headers, rows)
	return output.String()
}

func writeStatusSummary(output *strings.Builder, entries [][2]string) {
	rows := make([][]string, 0, len(entries))
	for index := range entries {
		rows = append(rows, []string{entries[index][0], entries[index][1]})
	}
	writeStatusBoxTable(output, nil, rows)
}

func writeStatusTable(output *strings.Builder, headers []string, rows [][]string) {
	writeStatusBoxTable(output, headers, rows)
}

func writeStatusBoxTable(output *strings.Builder, headers []string, rows [][]string) {
	for index := range headers {
		headers[index] = sanitizeStatusCell(headers[index])
	}
	for rowIndex := range rows {
		for columnIndex := range rows[rowIndex] {
			rows[rowIndex][columnIndex] = sanitizeStatusCell(rows[rowIndex][columnIndex])
		}
	}
	columnCount := len(headers)
	if columnCount == 0 && len(rows) > 0 {
		columnCount = len(rows[0])
	}
	widths := make([]int, columnCount)
	for index, header := range headers {
		widths[index] = max(widths[index], displayWidth(header))
	}
	for _, row := range rows {
		for index, value := range row {
			widths[index] = max(widths[index], displayWidth(value))
		}
	}
	writeStatusBoxBorder(output, widths, "┌", "┬", "┐")
	if len(headers) > 0 {
		writeStatusBoxRow(output, headers, widths)
		if len(rows) > 0 {
			writeStatusBoxBorder(output, widths, "├", "┼", "┤")
		}
	}
	for _, row := range rows {
		writeStatusBoxRow(output, row, widths)
	}
	writeStatusBoxBorder(output, widths, "└", "┴", "┘")
}

func writeStatusBoxBorder(output *strings.Builder, widths []int, left, middle, right string) {
	output.WriteString(left)
	for index, width := range widths {
		if index > 0 {
			output.WriteString(middle)
		}
		output.WriteString(strings.Repeat("─", width+2))
	}
	output.WriteString(right)
	output.WriteByte('\n')
}

func writeStatusBoxRow(output *strings.Builder, values []string, widths []int) {
	output.WriteString("│")
	for index, value := range values {
		fmt.Fprintf(output, " %s │", padDisplay(value, widths[index]))
	}
	output.WriteByte('\n')
}

func padDisplay(value string, width int) string {
	return value + strings.Repeat(" ", max(0, width-displayWidth(value)))
}

func displayWidth(value string) int {
	return runewidth.StringWidth(value)
}

func sanitizeStatusCell(value string) string {
	var sanitized strings.Builder
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			fmt.Fprintf(&sanitized, `\u%04X`, character)
			continue
		}
		sanitized.WriteRune(character)
	}
	return sanitized.String()
}

func providerHealthStatuses(snapshots []router.HealthSnapshot) []control.ProviderHealth {
	result := make([]control.ProviderHealth, 0, len(snapshots))
	for _, snapshot := range snapshots {
		result = append(result, control.ProviderHealth{
			Name:                     snapshot.Provider,
			ThroughputBytesPerSecond: snapshot.ThroughputBytesPerSecond,
			FirstByteMillis:          float64(snapshot.FirstByte) / float64(time.Millisecond),
			Failures:                 snapshot.Failures,
			LastSuccess:              snapshot.LastSuccess,
			LastFailure:              snapshot.LastFailure,
			RateLimitedUntil:         snapshot.RateLimitedUntil,
			AuthenticationInvalid:    snapshot.AuthenticationInvalid,
			IntegrityInvalid:         snapshot.IntegrityInvalid,
		})
	}
	return result
}

func formatProviderState(provider control.ProviderHealth) string {
	switch {
	case provider.IntegrityInvalid:
		return "完整性隔离"
	case provider.AuthenticationInvalid:
		return "认证失效"
	case provider.RateLimitedUntil.After(time.Now()):
		return "限流至 " + provider.RateLimitedUntil.Local().Format(time.RFC3339)
	default:
		return "可用"
	}
}

func formatHealthTime(value time.Time) string {
	if value.IsZero() {
		return "无"
	}
	return value.Local().Format("2006-01-02 15:04:05 -07:00")
}

func runStart(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	loaded, configPath, exitCode := loadControlConfigurationWithPath("start", arguments, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	printSecurityWarnings(output, loaded)
	probeContext, cancel := context.WithTimeout(ctx, time.Second)
	_, statusErr := control.StatusRequest(probeContext, loaded.DataDir)
	cancel()
	if statusErr == nil {
		fmt.Fprintln(errorOutput, "Gateway 已在运行；请使用 drg status、drg reload 或 drg restart。")
		return 1
	}
	if err := os.MkdirAll(loaded.DataDir, 0o700); err != nil {
		fmt.Fprintf(errorOutput, "创建数据目录失败: %v\n", err)
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(errorOutput, "定位 drg 可执行文件失败: %v\n", err)
		return 1
	}
	command := exec.Command(executable, "serve", "--config", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		fmt.Fprintf(errorOutput, "启动 Gateway 子进程失败: %v\n", err)
		return 1
	}
	go func() { _ = command.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		probeContext, cancel := context.WithTimeout(ctx, time.Second)
		status, err := control.StatusRequest(probeContext, loaded.DataDir)
		cancel()
		if err == nil && status.PID == command.Process.Pid {
			fmt.Fprintf(output, "DRG 已在后台启动（PID %d）。使用 drg logs --follow --config %s 查看统一日志。\n", status.PID, configPath)
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(errorOutput, "Gateway 未在 10 秒内就绪；请执行 drg logs --limit 100 --config %s，或以前台 serve 查看启动错误。\n", configPath)
	return 1
}

func runReload(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	loaded, exitCode := loadControlConfiguration("reload", arguments, errorOutput)
	if exitCode != 0 {
		return exitCode
	}
	if err := control.ReloadRequest(ctx, loaded.DataDir); err != nil {
		fmt.Fprintf(errorOutput, "热加载失败；运行中的旧配置保持生效: %v\n", err)
		return 1
	}
	fmt.Fprintln(output, "热加载完成：仅新请求使用新配置，进行中的拉取继续使用原配置。")
	return 0
}

func runStop(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("stop", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	force := flags.Bool("force", false, "立即取消活跃传输")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "stop 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	statusContext, cancel := context.WithTimeout(ctx, time.Second)
	status, statusErr := control.StatusRequest(statusContext, loaded.DataDir)
	cancel()
	if statusErr == nil {
		fmt.Fprintf(output, "当前状态：活跃拉取 %d，排队拉取 %d。\n", status.ActivePulls, status.QueuedPulls)
	}
	if *force {
		fmt.Fprintln(output, "正在强制停止：活跃 Docker 拉取会中断，并由 Docker 按其重试策略处理。")
	} else {
		fmt.Fprintln(output, "正在平滑停止：停止接收新请求，活跃拉取最多排空 30 秒；排空期间会持续报告进度。若无法继续等待，可另行执行 drg stop --force。")
	}
	if err := control.StopRequest(ctx, loaded.DataDir, *force); err != nil {
		fmt.Fprintf(errorOutput, "停止请求失败: %v\n", err)
		return 1
	}
	if *force {
		fmt.Fprintln(output, "强制停止请求已被 Gateway 接受。")
		return 0
	}
	return waitForGatewayStop(ctx, loaded.DataDir, output, errorOutput)
}

func waitForGatewayStop(ctx context.Context, dataDir string, output, errorOutput io.Writer) int {
	const (
		stopWaitLimit      = 35 * time.Second
		stopProgressPeriod = 5 * time.Second
	)
	started := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(stopWaitLimit)
	defer timeout.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(errorOutput, "等待 Gateway 停止被取消: %v\n", ctx.Err())
			return 1
		case <-timeout.C:
			fmt.Fprintln(errorOutput, "Gateway 未在 35 秒内停止；它可能仍在排空连接。请运行 drg status 查看状态，确认后可使用 drg stop --force。")
			return 1
		case <-ticker.C:
			statusContext, cancel := context.WithTimeout(context.Background(), time.Second)
			status, err := control.StatusRequest(statusContext, dataDir)
			cancel()
			if err != nil {
				fmt.Fprintln(output, "Gateway 已停止。")
				return 0
			}
			if time.Since(started) >= stopProgressPeriod {
				fmt.Fprintf(output, "仍在排空：活跃拉取 %d，排队拉取 %d，已等待 %s。\n", status.ActivePulls, status.QueuedPulls, time.Since(started).Round(time.Second))
			}
		}
	}
}

func runRestart(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("restart", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	force := flags.Bool("force", false, "立即取消活跃传输后重启")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "restart 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	stopArguments := []string{"--config", *configPath}
	if *force {
		stopArguments = append(stopArguments, "--force")
	}
	if exitCode := runStop(ctx, stopArguments, output, errorOutput); exitCode != 0 {
		return exitCode
	}
	fmt.Fprintln(output, "正在等待原服务完全退出…")
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		probeContext, cancel := context.WithTimeout(ctx, time.Second)
		_, statusErr := control.StatusRequest(probeContext, loaded.DataDir)
		cancel()
		if statusErr != nil {
			return runStart(ctx, []string{"--config", *configPath}, output, errorOutput)
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(errorOutput, "原服务未在 35 秒内退出；未启动新实例。可检查 drg status，或使用 drg restart --force。")
	return 1
}

func runResolver(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	if len(arguments) == 0 || arguments[0] != "invalidate" {
		fmt.Fprintln(errorOutput, "用法：drg resolver invalidate [--all | <镜像:tag>] --config <路径>")
		return 2
	}
	flags := flag.NewFlagSet("resolver invalidate", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	all := flags.Bool("all", false, "清空全部解析租约")
	if err := flags.Parse(arguments[1:]); err != nil {
		return 2
	}
	if (*all && flags.NArg() != 0) || (!*all && flags.NArg() != 1) {
		fmt.Fprintln(errorOutput, "用法：drg resolver invalidate [--all | <镜像:tag>] --config <路径>")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	store, err := lease.Open(filepath.Join(loaded.DataDir, "decision-leases.json"), time.Now())
	if err != nil {
		fmt.Fprintf(errorOutput, "读取解析租约失败: %v\n", err)
		return 1
	}
	if *all {
		err = store.Clear()
	} else {
		repository, tag, parseErr := splitMutableReference(flags.Arg(0))
		if parseErr != nil {
			fmt.Fprintf(errorOutput, "镜像引用无效: %v\n", parseErr)
			return 2
		}
		err = store.DeletePrefix(repository + "\x00" + tag + "\x00")
	}
	if err != nil {
		fmt.Fprintf(errorOutput, "写入解析租约失败: %v\n", err)
		return 1
	}
	if err := control.ReloadRequest(ctx, loaded.DataDir); err != nil {
		fmt.Fprintf(errorOutput, "租约文件已清空，但运行中服务尚未切换到新状态: %v\n", err)
		return 1
	}
	if *all {
		fmt.Fprintln(output, "全部解析租约已失效，运行中服务已热加载。")
	} else {
		fmt.Fprintf(output, "镜像 %s 的解析租约已失效，运行中服务已热加载。\n", flags.Arg(0))
	}
	return 0
}

func splitMutableReference(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "@") {
		return "", "", errors.New("需要一个可变 tag 引用，例如 library/nginx:latest")
	}
	lastSlash := strings.LastIndex(value, "/")
	lastColon := strings.LastIndex(value, ":")
	if lastColon > lastSlash {
		if lastColon == 0 || lastColon == len(value)-1 {
			return "", "", errors.New("tag 引用格式不完整")
		}
		return value[:lastColon], value[lastColon+1:], nil
	}
	return value, "latest", nil
}

func loadControlConfiguration(command string, arguments []string, errorOutput io.Writer) (config.Config, int) {
	loaded, _, exitCode := loadControlConfigurationWithPath(command, arguments, errorOutput)
	return loaded, exitCode
}

func loadControlConfigurationWithPath(command string, arguments []string, errorOutput io.Writer) (config.Config, string, int) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil {
		return config.Config{}, "", 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(errorOutput, "%s 不接受位置参数\n", command)
		return config.Config{}, "", 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return config.Config{}, "", 1
	}
	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}
	return loaded, absPath, 0
}

func runConfig(arguments []string, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(errorOutput, "用法：drg config <validate|migrate> --config <路径>")
		return 2
	}
	switch arguments[0] {
	case "validate":
		return runConfigValidate(arguments[1:], output, errorOutput)
	case "migrate":
		return runConfigMigrate(arguments[1:], output, errorOutput)
	default:
		fmt.Fprintln(errorOutput, "用法：drg config <validate|migrate> --config <路径>")
		return 2
	}
}

func runConfigValidate(arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "config validate 不接受位置参数")
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}
	fmt.Fprintf(output, "配置有效：%s\n", absPath)
	printSecurityWarnings(output, loaded)
	return 0
}

func runConfigMigrate(arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("config migrate", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		if err == nil {
			fmt.Fprintln(errorOutput, "config migrate 不接受位置参数")
		}
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	if loaded.Version != 1 {
		fmt.Fprintf(errorOutput, "不支持从配置版本 %d 迁移\n", loaded.Version)
		return 1
	}
	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}
	fmt.Fprintf(output, "配置已是当前 V1 格式，无需改写：%s\n", absPath)
	return 0
}

func runDoctor(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	skipProviders := flags.Bool("skip-providers", false, "跳过 Provider 联网探测")
	skipDocker := flags.Bool("skip-docker", false, "跳过本机 Docker daemon 只读检查")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		if err == nil {
			fmt.Fprintln(errorOutput, "doctor 不接受位置参数")
		}
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "配置检查失败: %v\n", err)
		return 1
	}
	absPath, _ := filepath.Abs(*configPath)
	fmt.Fprintf(output, "配置：正常（%s）\n", absPath)
	printSecurityWarnings(output, loaded)
	failed := false
	for _, listener := range loaded.Server.Listeners {
		if _, err := net.ResolveTCPAddr("tcp", listener); err != nil {
			fmt.Fprintf(output, "监听地址 %s：异常（%v）\n", listener, err)
			failed = true
		} else {
			fmt.Fprintf(output, "监听地址 %s：可解析\n", listener)
		}
	}
	if err := diagnoseTLS(loaded, output); err != nil {
		fmt.Fprintf(output, "TLS：异常（%v）；可执行 drg tls reconcile 处理\n", err)
		failed = true
	}
	if loaded.Server.TLS.LocalCA {
		if !loaded.Server.TLS.InstallTrust {
			fmt.Fprintln(output, "Docker 根证书信任：配置已关闭自动安装，未做宿主机信任检查。")
		} else {
			diagnosis, trustErr := trust.Diagnose(trust.Options{
				CAPath:            filepath.Join(loaded.DataDir, "pki", "ca.crt"),
				AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
				IsContainer:       trust.InContainer(),
			})
			if trustErr != nil {
				fmt.Fprintf(output, "Docker 根证书信任：异常（%v）\n", trustErr)
				failed = true
			} else if !diagnosis.Checked {
				fmt.Fprintf(output, "Docker 根证书信任：无法自动核验（%s）\n", diagnosis.Details)
			} else if !diagnosis.Trusted {
				fmt.Fprintf(output, "Docker 根证书信任：异常（%s）；可执行 drg tls reconcile。\n", diagnosis.Details)
				failed = true
			} else {
				fmt.Fprintf(output, "Docker 根证书信任：正常（%s）\n", diagnosis.Details)
			}
		}
	}
	if !*skipProviders {
		for _, configured := range loaded.Providers {
			probeContext, cancel := context.WithTimeout(ctx, 15*time.Second)
			username, password, credentialErr := configured.Auth.Credentials()
			client, createErr := provider.New(provider.Options{URL: configured.URL, Username: username, Password: password, CAFile: configured.CAFile, RouteGuard: routeguard.New(externalInstanceID(loaded.DataDir), 3)})
			if credentialErr == nil && createErr == nil {
				result, probeErr := client.Probe(probeContext, loaded.ProbeRef)
				cancel()
				if probeErr == nil {
					fmt.Fprintf(output, "Provider %s：正常（Range=%t，manifest=%s）\n", configured.Name, result.RangeSupported, result.ManifestDigest)
					continue
				}
				fmt.Fprintf(output, "Provider %s：异常（%v）\n", configured.Name, probeErr)
			} else {
				cancel()
				if credentialErr != nil {
					fmt.Fprintf(output, "Provider %s：异常（%v）\n", configured.Name, credentialErr)
				} else {
					fmt.Fprintf(output, "Provider %s：异常（%v）\n", configured.Name, createErr)
				}
			}
			failed = true
		}
	}
	if *skipDocker {
		fmt.Fprintln(output, "Docker daemon：已按参数跳过检查。")
	} else {
		dockerContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		version, dockerErr := exec.CommandContext(dockerContext, "docker", "version", "--format", "{{.Server.Version}}").Output()
		cancel()
		if dockerErr != nil {
			fmt.Fprintf(output, "Docker daemon：异常（%v）\n", dockerErr)
			failed = true
		} else {
			fmt.Fprintf(output, "Docker daemon：可达（Server %s）\n", strings.TrimSpace(string(version)))
		}
	}
	fmt.Fprintln(output, "Docker 镜像源配置属于部署边界，doctor 不读取或修改 Docker 配置；根证书仅在可识别的本机信任位置只读核验。")
	if failed {
		return 1
	}
	return 0
}

func diagnoseTLS(loaded config.Config, output io.Writer) error {
	if !loaded.Server.TLS.LocalCA && loaded.Server.TLS.CertFile == "" {
		fmt.Fprintln(output, "TLS：纯 HTTP 后端（未配置 local_ca 或外部 cert_file/key_file）")
		return nil
	}
	certificatePath := loaded.Server.TLS.CertFile
	keyPath := loaded.Server.TLS.KeyFile
	caPath := ""
	if loaded.Server.TLS.LocalCA {
		certificatePath = filepath.Join(loaded.DataDir, "pki", "server.crt")
		keyPath = filepath.Join(loaded.DataDir, "pki", "server.key")
		caPath = filepath.Join(loaded.DataDir, "pki", "ca.crt")
	}
	if _, err := tls.LoadX509KeyPair(certificatePath, keyPath); err != nil {
		return err
	}
	if loaded.Server.TLS.LocalCA {
		if err := localca.VerifyPrivateKeyPermissions(filepath.Join(loaded.DataDir, "pki", "ca.key")); err != nil {
			return err
		}
		if err := localca.VerifyPrivateKeyPermissions(keyPath); err != nil {
			return err
		}
	}
	contents, err := os.ReadFile(certificatePath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return errors.New("server.crt 不是 PEM 证书")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Until(certificate.NotAfter) <= 0 {
		return errors.New("服务端证书已过期")
	}
	host, _, err := net.SplitHostPort(loaded.Server.TLS.AdvertiseEndpoint)
	if err != nil {
		return err
	}
	if caPath != "" {
		contents, err := os.ReadFile(caPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(contents)
		if block == nil {
			return errors.New("本地 CA 不是 PEM 证书")
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if !root.IsCA || time.Until(root.NotAfter) <= 0 {
			return errors.New("本地 CA 无效或已过期")
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: time.Now()}); err != nil {
			return fmt.Errorf("服务端证书未通过本地 CA 或访问地址校验: %w", err)
		}
		if time.Until(root.NotAfter) <= 90*24*time.Hour {
			return fmt.Errorf("本地 CA 将在 %s 到期；请执行 drg tls rotate-root", root.NotAfter.Local().Format(time.RFC3339))
		}
		fmt.Fprintf(output, "TLS：正常（叶证书到期时间 %s；本地 CA 到期时间 %s；链路与访问地址已校验）\n", certificate.NotAfter.Local().Format(time.RFC3339), root.NotAfter.Local().Format(time.RFC3339))
	} else {
		if err := certificate.VerifyHostname(host); err != nil {
			return fmt.Errorf("外部证书不匹配 advertise_endpoint: %w", err)
		}
		fmt.Fprintf(output, "TLS：正常（外部叶证书到期时间 %s；cert=%s）\n", certificate.NotAfter.Local().Format(time.RFC3339), certificatePath)
	}
	return nil
}

func runLogs(ctx context.Context, command string, arguments []string, input io.Reader, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	limit := flags.Int("limit", 50, "最多显示的事件数量")
	follow := flags.Bool("follow", false, "先显示最近事件，再持续跟随新事件")
	colorMode := flags.String("color", "auto", "颜色：auto、always 或 never")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *limit < 1 {
		if err == nil {
			fmt.Fprintf(errorOutput, "%s 不接受位置参数，且 limit 必须大于零\n", command)
		}
		return 2
	}
	color, colorErr := eventColorEnabled(*colorMode, output)
	if colorErr != nil {
		fmt.Fprintf(errorOutput, "%s 颜色模式无效: %v\n", command, colorErr)
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	eventRetention, _, err := retentionConfiguration(loaded)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取日志保留配置失败: %v\n", err)
		return 1
	}
	log := eventlog.New(loaded.DataDir, time.Now, eventRetention)
	if *follow {
		followContext, cancelFollow := context.WithCancel(ctx)
		printer := &followEventPrinter{output: output, color: color}
		waitForInput := startFollowSeparators(followContext, input, printer)
		err := log.Follow(followContext, *limit, printer.print)
		printer.close()
		cancelFollow()
		waitForInput()
		if err != nil {
			fmt.Fprintf(errorOutput, "跟随日志失败: %v\n", err)
			return 1
		}
		return 0
	}
	events, err := log.Read(*limit)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取日志失败: %v\n", err)
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(output, "暂无日志。")
		return 0
	}
	for _, event := range events {
		printEvent(output, event, color)
	}
	return 0
}

type followEventPrinter struct {
	mu     sync.Mutex
	output io.Writer
	color  bool
	closed bool
}

func (printer *followEventPrinter) print(event eventlog.Event) {
	printer.mu.Lock()
	defer printer.mu.Unlock()
	if printer.closed {
		return
	}
	printEvent(printer.output, event, printer.color)
}

func (printer *followEventPrinter) separator() {
	printer.mu.Lock()
	defer printer.mu.Unlock()
	if printer.closed {
		return
	}
	fmt.Fprintln(printer.output)
}

func (printer *followEventPrinter) close() {
	printer.mu.Lock()
	defer printer.mu.Unlock()
	printer.closed = true
}

func startFollowSeparators(ctx context.Context, input io.Reader, printer *followEventPrinter) func() {
	if input == nil || printer == nil {
		return func() {}
	}
	done := make(chan struct{})
	waitForScanner := false
	if closer, closable := input.(io.Closer); closable && !isProcessStdin(input) {
		waitForScanner = true
		context.AfterFunc(ctx, func() { _ = closer.Close() })
	}
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			if scanner.Text() == "" {
				printer.separator()
			}
		}
	}()
	if !waitForScanner {
		return func() {}
	}
	return func() { <-done }
}

func isProcessStdin(input io.Reader) bool {
	file, isFile := input.(*os.File)
	return isFile && file == os.Stdin
}

// serviceLogger is the single seam between Gateway lifecycle output and the
// bounded diagnostic history. It intentionally records only caller-supplied,
// non-secret messages, never raw upstream errors.
type serviceLogger struct {
	mu     sync.Mutex
	events *eventlog.Log
	output io.Writer
}

func newServiceLogger(events *eventlog.Log, output io.Writer) *serviceLogger {
	return &serviceLogger{events: events, output: output}
}

func (logger *serviceLogger) log(level, code, message string) {
	if logger == nil {
		return
	}
	event := eventlog.Event{Level: level, Code: code, Message: message}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if logger.events != nil {
		_ = logger.events.Write(event)
	}
	if logger.output != nil {
		printEvent(logger.output, event, false)
	}
}

func (logger *serviceLogger) Write(contents []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(contents), "\r\n"), "\n") {
		if message := strings.TrimSpace(line); message != "" {
			logger.log("info", "server_notice", message)
		}
	}
	return len(contents), nil
}

func eventColorEnabled(mode string, output io.Writer) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		if os.Getenv("NO_COLOR") != "" {
			return false, nil
		}
		file, isFile := output.(*os.File)
		if !isFile {
			return false, nil
		}
		info, err := file.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0, nil
	default:
		return false, fmt.Errorf("%q（可选 auto、always、never）", mode)
	}
}

const (
	ansiReset   = "\x1b[0m"
	ansiDim     = "\x1b[2m"
	ansiCyan    = "\x1b[36m"
	ansiYellow  = "\x1b[33m"
	ansiRed     = "\x1b[31m"
	ansiMagenta = "\x1b[35m"
	ansiBold    = "\x1b[1m"
)

func printEvent(output io.Writer, event eventlog.Event, color bool) {
	var details []string
	if event.Provider != "" {
		details = append(details, formatEventDetail("Provider", event.Provider, ansiMagenta, color))
	}
	if event.Repository != "" {
		details = append(details, formatEventDetail("Repository", event.Repository, ansiCyan, color))
	}
	if event.Reference != "" {
		details = append(details, formatEventDetail("Reference", event.Reference, ansiCyan, color))
	}
	if event.Digest != "" {
		details = append(details, formatEventDetail("Digest", event.Digest, ansiDim, color))
	}
	if event.ResumeOffset != nil {
		details = append(details, formatEventDetail("ResumeOffset", strconv.FormatInt(*event.ResumeOffset, 10)+"B", ansiBold, color))
	}
	context := ""
	if len(details) > 0 {
		context = " " + strings.Join(details, " ")
	}
	levelStyle := eventLevelStyle(event.Level)
	fmt.Fprintf(output, "%s [%s] %s%s：%s\n",
		colorize(event.Time.Local().Format(time.RFC3339), ansiDim, color),
		colorize(event.Level, levelStyle, color),
		colorize(event.Code, ansiBold+levelStyle, color),
		context,
		event.Message,
	)
}

func eventLevelStyle(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return ansiRed
	case "warning":
		return ansiYellow
	default:
		return ansiCyan
	}
}

func formatEventDetail(key, value, style string, color bool) string {
	return key + "=" + colorize(value, style, color)
}

func colorize(value, style string, enabled bool) string {
	if !enabled || value == "" {
		return value
	}
	return style + value + ansiReset
}

func printSecurityWarnings(output io.Writer, loaded config.Config) {
	for _, warning := range loaded.SecurityWarnings() {
		fmt.Fprintf(output, "[高优先级安全警告] %s\n", warning.Message)
	}
}

func runOnboard(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("onboard", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	noStart := flags.Bool("no-start", false, "仅生成配置和证书，不启动服务")
	skipTrustInstall := flags.Bool("skip-trust-install", false, "跳过本次 Docker 信任安装")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errorOutput, "onboard 不接受位置参数")
		return 2
	}

	reader := bufio.NewReader(input)
	listeners, err := prompt(reader, output, "监听地址（逗号分隔）", "127.0.0.1:5443,[::1]:5443")
	if err != nil {
		fmt.Fprintf(errorOutput, "读取监听地址: %v\n", err)
		return 1
	}
	advertiseEndpoint, err := prompt(reader, output, "访问地址", "drg.localhost:5443")
	if err != nil {
		fmt.Fprintf(errorOutput, "读取访问地址: %v\n", err)
		return 1
	}
	tlsMode, err := prompt(reader, output, "TLS 模式（local_ca/external/http）", "local_ca")
	if err != nil {
		fmt.Fprintf(errorOutput, "读取 TLS 模式: %v\n", err)
		return 1
	}
	tlsMode = strings.ToLower(strings.TrimSpace(tlsMode))
	if tlsMode != "local_ca" && tlsMode != "external" && tlsMode != "http" {
		fmt.Fprintln(errorOutput, "TLS 模式只能是 local_ca、external 或 http")
		return 2
	}
	certificateFile, privateKeyFile := "", ""
	if tlsMode == "external" {
		certificateFile, err = prompt(reader, output, "外部证书 cert_file 路径", "")
		if err != nil || strings.TrimSpace(certificateFile) == "" {
			fmt.Fprintln(errorOutput, "external TLS 必须提供 cert_file")
			return 2
		}
		privateKeyFile, err = prompt(reader, output, "外部私钥 key_file 路径", "")
		if err != nil || strings.TrimSpace(privateKeyFile) == "" {
			fmt.Fprintln(errorOutput, "external TLS 必须提供 key_file")
			return 2
		}
	}
	providers, err := promptAdditionalProviders(reader, output)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取 Provider 配置: %v\n", err)
		return 1
	}
	resources, err := promptResources(reader, output)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取资源上限: %v\n", err)
		return 1
	}

	answers := onboard.Answers{
		Listeners:         splitListeners(listeners),
		AdvertiseEndpoint: advertiseEndpoint,
		TLSMode:           tlsMode,
		CertificateFile:   certificateFile,
		PrivateKeyFile:    privateKeyFile,
		Providers:         providers,
		Resources:         resources,
	}
	if err := onboard.Run(ctx, onboard.Options{ConfigPath: *configPath, Answers: answers}); err != nil {
		fmt.Fprintf(errorOutput, "创建配置失败: %v\n", err)
		return 1
	}

	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}
	fmt.Fprintf(output, "已生成配置：%s\n", absPath)
	tlsArguments := []string{"reconcile", "--config", *configPath}
	if *skipTrustInstall {
		tlsArguments = append(tlsArguments, "--skip-trust-install")
	}
	if exitCode := runTLS(ctx, tlsArguments, output, errorOutput); exitCode != 0 {
		return exitCode
	}
	if *noStart {
		fmt.Fprintln(output, "已按 --no-start 跳过启动；请自行将 Docker 的 registry-mirrors 指向访问地址。")
		return 0
	}
	fmt.Fprintln(output, "证书已就绪，正在后台启动服务；Docker 镜像源配置仍由你自行完成。")
	return runStart(ctx, []string{"--config", *configPath}, output, errorOutput)
}

func prompt(reader *bufio.Reader, output io.Writer, label, defaultValue string) (string, error) {
	fmt.Fprintf(output, "%s [%s]: ", label, defaultValue)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func splitListeners(value string) []string {
	parts := strings.Split(value, ",")
	listeners := make([]string, 0, len(parts))
	for _, part := range parts {
		listeners = append(listeners, strings.TrimSpace(part))
	}
	return listeners
}

func promptAdditionalProviders(reader *bufio.Reader, output io.Writer) ([]config.Provider, error) {
	add, err := promptYesNo(reader, output, "是否添加第三方 Provider", false)
	if err != nil || !add {
		return nil, err
	}
	var providers []config.Provider
	for index := 1; ; index++ {
		name, err := prompt(reader, output, fmt.Sprintf("Provider %d 名称", index), "")
		if err != nil || strings.TrimSpace(name) == "" {
			return nil, errors.New("Provider 名称不能为空")
		}
		endpoint, err := prompt(reader, output, fmt.Sprintf("Provider %d URL", index), "")
		if err != nil || strings.TrimSpace(endpoint) == "" {
			return nil, errors.New("Provider URL 不能为空")
		}
		resolver, err := promptYesNo(reader, output, "作为 Resolver", false)
		if err != nil {
			return nil, err
		}
		pullProvider, err := promptYesNo(reader, output, "作为 Pull Provider", true)
		if err != nil {
			return nil, err
		}
		username, err := prompt(reader, output, "上游用户名（留空代表匿名）", "")
		if err != nil {
			return nil, err
		}
		provider := config.Provider{Name: name, URL: endpoint, Resolver: resolver, PullProvider: pullProvider}
		if strings.TrimSpace(username) != "" {
			credentialMode, promptErr := prompt(reader, output, "上游凭据保存方式（secret_file/password）", "secret_file")
			if promptErr != nil {
				return nil, promptErr
			}
			switch strings.ToLower(strings.TrimSpace(credentialMode)) {
			case "secret_file":
				secretFile, secretErr := prompt(reader, output, "上游 secret_file 路径（单行密码或 PAT）", "")
				if secretErr != nil || strings.TrimSpace(secretFile) == "" {
					return nil, errors.New("配置用户名时 secret_file 不能为空")
				}
				provider.Auth = config.Auth{Username: username, SecretFile: secretFile}
			case "password":
				password, passwordErr := prompt(reader, output, "上游密码或 PAT（将明文写入配置，不推荐）", "")
				if passwordErr != nil || strings.TrimSpace(password) == "" {
					return nil, errors.New("配置用户名时 password 不能为空")
				}
				provider.Auth = config.Auth{Username: username, Password: password}
			default:
				return nil, fmt.Errorf("上游凭据保存方式只能是 secret_file 或 password，得到 %q", credentialMode)
			}
		}
		providers = append(providers, provider)
		more, promptErr := promptYesNo(reader, output, "继续添加 Provider", false)
		if promptErr != nil || !more {
			return providers, promptErr
		}
	}
}

func promptResources(reader *bufio.Reader, output io.Writer) (config.Resources, error) {
	adjust, err := promptYesNo(reader, output, "是否调整资源上限", false)
	if err != nil || !adjust {
		return config.Resources{}, err
	}
	values := []struct {
		label, fallback string
		target          *string
	}{
		{"并发拉取数", "4", nil}, {"每层最大分片数", "4", nil}, {"临时磁盘配额", "2GiB", nil},
		{"最小分片大小", "16MiB", nil}, {"无 Range 重拉丢弃上限", "64MiB", nil}, {"最大在途请求数", "32", nil}, {"最大排队拉取数", "16", nil},
	}
	answers := make([]string, len(values))
	for index := range values {
		value, promptErr := prompt(reader, output, values[index].label, values[index].fallback)
		if promptErr != nil {
			return config.Resources{}, promptErr
		}
		answers[index] = value
	}
	parseInt := func(value string) (int, error) {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed <= 0 {
			return 0, fmt.Errorf("必须是正整数，得到 %q", value)
		}
		return parsed, nil
	}
	concurrent, err := parseInt(answers[0])
	if err != nil {
		return config.Resources{}, err
	}
	segments, err := parseInt(answers[1])
	if err != nil {
		return config.Resources{}, err
	}
	inflight, err := parseInt(answers[5])
	if err != nil {
		return config.Resources{}, err
	}
	queued, err := parseInt(answers[6])
	if err != nil {
		return config.Resources{}, err
	}
	return config.Resources{MaxConcurrentPulls: concurrent, MaxSegmentsPerBlob: segments, TemporaryDiskQuota: answers[2], MinSegmentSize: answers[3], MaxNoRangeRestartDiscard: answers[4], MaxInflightRequests: inflight, MaxQueuedPulls: queued}, nil
}

func promptYesNo(reader *bufio.Reader, output io.Writer, label string, defaultValue bool) (bool, error) {
	defaultText := "y/N"
	if defaultValue {
		defaultText = "Y/n"
	}
	value, err := prompt(reader, output, label, defaultText)
	if err != nil {
		return false, err
	}
	if value == defaultText {
		return defaultValue, nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes", "是", "true", "1":
		return true, nil
	case "n", "no", "否", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("请输入 y 或 n，得到 %q", value)
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "用法：drg <命令>")
	fmt.Fprintln(output, "\n命令：")
	fmt.Fprintln(output, "  onboard  交互式生成首次部署配置")
	fmt.Fprintln(output, "  config validate|migrate  严格校验或检查配置迁移")
	fmt.Fprintln(output, "  doctor  只读诊断配置、TLS、Docker 根信任、监听和 Provider")
	fmt.Fprintln(output, "  tls reconcile|rotate-root|clear-previous-root  对账、两阶段轮换或显式清理本地 CA")
	fmt.Fprintln(output, "  provider list|add|remove  查看或维护上游 Provider")
	fmt.Fprintln(output, "  logs [--follow] [--color auto|always|never]  查看统一日志；跟随时按回车插入空白分隔行")
	fmt.Fprintln(output, "  events  兼容别名，等同于 logs")
	fmt.Fprintln(output, "  serve  启动前台 Gateway 服务")
	fmt.Fprintln(output, "  start  启动后台 Gateway 服务")
	fmt.Fprintln(output, "  status  查看本地 Gateway 运行状态")
	fmt.Fprintln(output, "  reload  校验并热加载主配置")
	fmt.Fprintln(output, "  stop [--force]  平滑或强制停止本地 Gateway")
	fmt.Fprintln(output, "  restart [--force]  停止并重新启动本地 Gateway")
	fmt.Fprintln(output, "  resolver invalidate  使一个或全部 tag 解析租约失效")
}
