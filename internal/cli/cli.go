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
	case "events":
		return runEvents(arguments[1:], output, errorOutput)
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
	if len(arguments) == 0 || arguments[0] != "reconcile" {
		fmt.Fprintln(errorOutput, "用法：drg tls reconcile --config <路径>")
		return 2
	}
	flags := flag.NewFlagSet("tls reconcile", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	skipTrustInstall := flags.Bool("skip-trust-install", false, "跳过本次 Docker 信任安装")
	if err := flags.Parse(arguments[1:]); err != nil {
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
	return applyProviderConfiguration(ctx, resolvedConfigPath, candidate, "已添加 Provider "+provider.Name, output, errorOutput)
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
	trustResult, err := trust.Install(trust.Options{
		CAPath:            result.CAPath,
		AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
		IsContainer:       trust.InContainer(),
	})
	if err != nil {
		return localca.Result{}, fmt.Errorf("安装 Docker 信任根: %w", err)
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
	return result, nil
}

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
	printSecurityWarnings(output, loaded)

	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		absConfigPath = *configPath
	}
	var certificate *tls.Certificate
	instanceID := externalInstanceID(loaded.DataDir)
	if loaded.Server.TLS.LocalCA {
		tlsResult, reconcileErr := reconcileTLS(ctx, loaded, false, output)
		if reconcileErr != nil {
			fmt.Fprintf(errorOutput, "TLS 对账失败: %v\n", reconcileErr)
			return 1
		}
		loadedCertificate, loadErr := tls.LoadX509KeyPair(tlsResult.Certificate, tlsResult.PrivateKey)
		if loadErr != nil {
			fmt.Fprintf(errorOutput, "加载服务端证书失败: %v\n", loadErr)
			return 1
		}
		certificate = &loadedCertificate
		instanceID = tlsResult.InstanceID
	} else if loaded.Server.TLS.CertFile != "" {
		loadedCertificate, loadErr := tls.LoadX509KeyPair(loaded.Server.TLS.CertFile, loaded.Server.TLS.KeyFile)
		if loadErr != nil {
			fmt.Fprintf(errorOutput, "加载外部服务端证书失败: %v\n", loadErr)
			return 1
		}
		certificate = &loadedCertificate
	} else {
		fmt.Fprintln(output, "TLS 提示：local_ca 已关闭且未配置 cert_file/key_file，Gateway 将使用纯 HTTP 后端监听。")
	}
	routeGuard := routeguard.New(instanceID, 3)

	tracker := router.NewHealth()
	healthStore := healthhistory.Open(filepath.Join(loaded.DataDir, "provider-health.json"), time.Now)
	if snapshots, loadErr := healthStore.Load(healthhistory.Retention); loadErr != nil {
		fmt.Fprintf(errorOutput, "读取 Provider 健康历史失败，将以空历史启动: %v\n", loadErr)
	} else {
		tracker.Restore(snapshots)
	}
	temporaryDiskQuota, err := config.ParseByteSize(loaded.Resources.TemporaryDiskQuota)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取临时磁盘配额失败: %v\n", err)
		return 1
	}
	tempBudget := router.NewTempBudget(temporaryDiskQuota)
	events := eventlog.New(loaded.DataDir, time.Now)
	eventObserver := router.ObserverFunc(func(event router.Event) {
		_ = events.Write(eventlog.Event{
			Level:      event.Level,
			Code:       event.Code,
			Provider:   event.Provider,
			Repository: event.Repository,
			Reference:  event.Reference,
			Digest:     event.Digest,
			Message:    event.Message,
		})
	})
	runtimeRouter, err := buildRouter(loaded, []byte(absConfigPath), tracker, tempBudget, routeGuard, eventObserver)
	if err != nil {
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
	if certificate != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12}
	}

	listeners := make([]net.Listener, 0, len(loaded.Server.Listeners))
	for _, address := range loaded.Server.Listeners {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, opened := range listeners {
				opened.Close()
			}
			fmt.Fprintf(errorOutput, "监听 %s 失败: %v\n", address, err)
			return 1
		}
		if server.TLSConfig != nil {
			listener = tls.NewListener(listener, server.TLSConfig)
		}
		listeners = append(listeners, listener)
	}
	listenersForStatus := append([]string(nil), loaded.Server.Listeners...)
	currentConfig := loaded
	probeContext, stopProbing := context.WithCancel(ctx)
	_ = events.Write(eventlog.Event{Level: "info", Code: "gateway_started", Message: "Gateway 已启动"})
	var probeMu sync.Mutex
	var probeGroup sync.WaitGroup
	probesStopping := false
	probeOutput := &lockedWriter{writer: output}
	persistHealth := func() {
		if err := healthStore.Save(tracker.Snapshot()); err != nil {
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
	launchProbe := func(configuration config.Config) {
		probeMu.Lock()
		defer probeMu.Unlock()
		if probesStopping {
			return
		}
		probeGroup.Add(1)
		go func() {
			defer probeGroup.Done()
			probeProviders(probeContext, configuration, probeOutput, events, routeGuard, tracker)
		}()
	}
	defer func() {
		probeMu.Lock()
		probesStopping = true
		stopProbing()
		probeMu.Unlock()
		probeGroup.Wait()
	}()
	var reloadMu sync.Mutex
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
			replacement, err := buildRouter(candidate, []byte(absConfigPath), tracker, tempBudget, routeGuard, eventObserver)
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
		fmt.Fprintf(errorOutput, "启动本地控制面失败: %v\n", err)
		return 1
	}
	defer localControl.Close()
	fmt.Fprintf(output, "DRG 已启动：%s\n", strings.Join(loaded.Server.Listeners, ", "))
	fmt.Fprintln(output, "本地控制面已就绪：可使用 drg status、drg reload、drg stop。")
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
		return 0
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintf(errorOutput, "服务停止: %v\n", serveErr)
			_ = server.Close()
			group.Wait()
			return 1
		}
		group.Wait()
		return 0
	}
}

func probeProviders(parent context.Context, loaded config.Config, output io.Writer, events *eventlog.Log, routeGuard routeguard.Guard, tracker *router.Health) {
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
					tracker.RecordProbeSuccess(configured.Name)
					_ = events.Write(eventlog.Event{Level: "info", Code: "provider_probe_ok", Provider: configured.Name, Message: fmt.Sprintf("Range=%t", result.RangeSupported)})
					if result.RangeSupported {
						fmt.Fprintf(output, "Provider %s 准入探测通过：支持 Range 续传。\n", configured.Name)
					} else if loaded.AllowNonRangeProviders {
						fmt.Fprintf(output, "Provider %s 准入探测通过但不支持 Range：仅作为降级下载源。\n", configured.Name)
					} else {
						fmt.Fprintf(output, "Provider %s 准入探测不通过：不支持 Range，当前配置已禁用无 Range Provider。\n", configured.Name)
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
		fmt.Fprintf(output, "Provider %s 初始准入探测失败：%v；服务将继续运行并在后续拉取中恢复。\n", configured.Name, err)
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

func buildRouter(loaded config.Config, salt []byte, tracker *router.Health, tempBudget *router.TempBudget, routeGuard routeguard.Guard, observer router.Observer) (*router.Router, error) {
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
		TemporaryDir:             loaded.Resources.TempDir,
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
	fmt.Fprintf(output, "状态：%s；PID：%d；活跃拉取：%d；排队拉取：%d；监听：%s\n", status.State, status.PID, status.ActivePulls, status.QueuedPulls, strings.Join(status.Listeners, ", "))
	for _, provider := range status.Providers {
		fmt.Fprintf(output, "Provider %s：状态 %s；近期吞吐 %.2f MiB/s；首字节 %.0f ms；本进程失败 %d；最近成功 %s；最近失败 %s\n",
			provider.Name,
			formatProviderState(provider),
			provider.ThroughputBytesPerSecond/(1<<20),
			provider.FirstByteMillis,
			provider.Failures,
			formatHealthTime(provider.LastSuccess),
			formatHealthTime(provider.LastFailure),
		)
	}
	return 0
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
	return value.Local().Format(time.RFC3339)
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
	logPath := filepath.Join(loaded.DataDir, "serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(errorOutput, "打开服务日志失败: %v\n", err)
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		logFile.Close()
		fmt.Fprintf(errorOutput, "定位 drg 可执行文件失败: %v\n", err)
		return 1
	}
	command := exec.Command(executable, "serve", "--config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		logFile.Close()
		fmt.Fprintf(errorOutput, "启动 Gateway 子进程失败: %v\n", err)
		return 1
	}
	_ = logFile.Close()
	go func() { _ = command.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		probeContext, cancel := context.WithTimeout(ctx, time.Second)
		status, err := control.StatusRequest(probeContext, loaded.DataDir)
		cancel()
		if err == nil && status.PID == command.Process.Pid {
			fmt.Fprintf(output, "DRG 已在后台启动（PID %d）。日志：%s\n", status.PID, logPath)
			return 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(errorOutput, "Gateway 未在 10 秒内就绪；请检查日志：%s\n", logPath)
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
	if *force {
		fmt.Fprintln(output, "正在强制停止：活跃 Docker 拉取会中断，并由 Docker 按其重试策略处理。")
	} else {
		fmt.Fprintln(output, "已请求平滑停止：停止接收新请求，活跃拉取最多等待 30 秒后才会被关闭。")
	}
	if err := control.StopRequest(ctx, loaded.DataDir, *force); err != nil {
		fmt.Fprintf(errorOutput, "停止请求失败: %v\n", err)
		return 1
	}
	return 0
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
	if len(arguments) == 0 || arguments[0] != "validate" {
		fmt.Fprintln(errorOutput, "用法：drg config validate --config <路径>")
		return 2
	}
	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments[1:]); err != nil {
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

func runDoctor(ctx context.Context, arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	skipProviders := flags.Bool("skip-providers", false, "跳过 Provider 联网探测")
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
	if !*skipProviders {
		for _, configured := range loaded.Providers {
			probeContext, cancel := context.WithTimeout(ctx, 15*time.Second)
			username, password, credentialErr := configured.Auth.Credentials()
			client, createErr := provider.New(provider.Options{URL: configured.URL, Username: username, Password: password, CAFile: configured.CAFile})
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
	fmt.Fprintln(output, "Docker 镜像源和根证书信任属于部署边界，doctor 不读取或修改 Docker 配置。")
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
	if caPath != "" {
		if _, err := os.Stat(caPath); err != nil {
			return err
		}
		fmt.Fprintf(output, "TLS：正常（叶证书到期时间 %s；本地 CA=%s）\n", certificate.NotAfter.Local().Format(time.RFC3339), caPath)
	} else {
		fmt.Fprintf(output, "TLS：正常（外部叶证书到期时间 %s；cert=%s）\n", certificate.NotAfter.Local().Format(time.RFC3339), certificatePath)
	}
	return nil
}

func runEvents(arguments []string, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("events", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	limit := flags.Int("limit", 50, "最多显示的事件数量")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *limit < 1 {
		if err == nil {
			fmt.Fprintln(errorOutput, "events 不接受位置参数，且 limit 必须大于零")
		}
		return 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	events, err := eventlog.New(loaded.DataDir, time.Now).Read(*limit)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取事件日志失败: %v\n", err)
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(output, "暂无事件。")
		return 0
	}
	for _, event := range events {
		provider := ""
		if event.Provider != "" {
			provider = " Provider=" + event.Provider
		}
		fmt.Fprintf(output, "%s [%s] %s%s：%s\n", event.Time.Local().Format(time.RFC3339), event.Level, event.Code, provider, event.Message)
	}
	return 0
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
			secretFile, promptErr := prompt(reader, output, "上游 secret_file 路径（单行密码或 PAT）", "")
			if promptErr != nil || strings.TrimSpace(secretFile) == "" {
				return nil, errors.New("配置用户名时 secret_file 不能为空")
			}
			provider.Auth = config.Auth{Username: username, SecretFile: secretFile}
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
	fmt.Fprintln(output, "  config validate  严格校验主配置")
	fmt.Fprintln(output, "  doctor  只读诊断配置、TLS、监听和 Provider")
	fmt.Fprintln(output, "  tls reconcile  对账本地 CA 与服务端证书")
	fmt.Fprintln(output, "  serve  启动前台 Gateway 服务")
	fmt.Fprintln(output, "  start  启动后台 Gateway 服务")
	fmt.Fprintln(output, "  status  查看本地 Gateway 运行状态")
	fmt.Fprintln(output, "  reload  校验并热加载主配置")
	fmt.Fprintln(output, "  stop [--force]  平滑或强制停止本地 Gateway")
	fmt.Fprintln(output, "  restart [--force]  停止并重新启动本地 Gateway")
	fmt.Fprintln(output, "  resolver invalidate  使一个或全部 tag 解析租约失效")
}
