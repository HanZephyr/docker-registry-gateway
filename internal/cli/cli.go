// Package cli implements the user-facing drg command contract.
package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hjx/docker-registry-gateway/internal/config"
	"github.com/hjx/docker-registry-gateway/internal/control"
	"github.com/hjx/docker-registry-gateway/internal/gateway"
	"github.com/hjx/docker-registry-gateway/internal/localca"
	"github.com/hjx/docker-registry-gateway/internal/onboard"
	"github.com/hjx/docker-registry-gateway/internal/provider"
	"github.com/hjx/docker-registry-gateway/internal/registry"
	"github.com/hjx/docker-registry-gateway/internal/router"
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
	case "serve":
		return runServe(ctx, arguments[1:], output, errorOutput)
	case "status":
		return runStatus(ctx, arguments[1:], output, errorOutput)
	case "reload":
		return runReload(ctx, arguments[1:], output, errorOutput)
	case "stop":
		return runStop(ctx, arguments[1:], output, errorOutput)
	case "tls":
		return runTLS(ctx, arguments[1:], output, errorOutput)
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
		fmt.Fprintln(errorOutput, "local_ca 已关闭，无法执行本地 CA 对账")
		return 1
	}
	result, err := localca.Reconcile(ctx, localca.Options{
		DataDir:           loaded.DataDir,
		AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
	})
	if err != nil {
		fmt.Fprintf(errorOutput, "TLS 对账失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(output, "TLS 对账完成：CA=%s，证书=%s，本次新建根 CA=%t，本次签发叶子证书=%t\n", result.CAPath, result.Certificate, result.RootCreated, result.LeafIssued)
	return 0
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
	if !loaded.Server.TLS.LocalCA {
		fmt.Fprintln(errorOutput, "当前首版 serve 仅支持 local_ca: true")
		return 1
	}

	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		absConfigPath = *configPath
	}
	tlsResult, err := localca.Reconcile(ctx, localca.Options{
		DataDir:           loaded.DataDir,
		AdvertiseEndpoint: loaded.Server.TLS.AdvertiseEndpoint,
	})
	if err != nil {
		fmt.Fprintf(errorOutput, "TLS 对账失败: %v\n", err)
		return 1
	}
	certificate, err := tls.LoadX509KeyPair(tlsResult.Certificate, tlsResult.PrivateKey)
	if err != nil {
		fmt.Fprintf(errorOutput, "加载服务端证书失败: %v\n", err)
		return 1
	}

	runtimeRouter, err := buildRouter(loaded, []byte(absConfigPath))
	if err != nil {
		fmt.Fprintf(errorOutput, "初始化 Provider 路由失败: %v\n", err)
		return 1
	}
	backend := gateway.New(runtimeRouter)
	server := &http.Server{
		Handler:   registry.NewHandler(backend),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
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
		listeners = append(listeners, tls.NewListener(listener, server.TLSConfig))
	}
	listenersForStatus := append([]string(nil), loaded.Server.Listeners...)
	var reloadMu sync.Mutex
	localControl, err := control.Start(loaded.DataDir, control.Callbacks{
		Status: func() control.Status {
			return control.Status{State: "running", Listeners: append([]string(nil), listenersForStatus...), ActivePulls: backend.ActivePulls()}
		},
		Reload: func(_ context.Context) error {
			reloadMu.Lock()
			defer reloadMu.Unlock()
			candidate, err := config.LoadFile(absConfigPath)
			if err != nil {
				return fmt.Errorf("读取或校验新配置: %w", err)
			}
			if !sameServeConfiguration(loaded, candidate) {
				return errors.New("监听地址、访问地址、TLS 模式或 data_dir 已改变，需要使用 drg restart")
			}
			replacement, err := buildRouter(candidate, []byte(absConfigPath))
			if err != nil {
				return err
			}
			backend.Replace(replacement)
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

func buildRouter(loaded config.Config, salt []byte) (*router.Router, error) {
	sources := make([]router.Source, 0, len(loaded.Providers))
	for _, configured := range loaded.Providers {
		username, password, err := configured.Auth.Credentials()
		if err != nil {
			return nil, fmt.Errorf("读取 Provider %q 凭据: %w", configured.Name, err)
		}
		client, err := provider.New(provider.Options{
			URL:      configured.URL,
			Username: username,
			Password: password,
			CAFile:   configured.CAFile,
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
	return router.New(sources, router.Options{
		ConflictStrategy:         loaded.Resolution.ConflictStrategy,
		TieBreaker:               loaded.Resolution.TieBreaker,
		Salt:                     salt,
		NoRangeRestartEnabled:    &loaded.AllowNonRangeProviders,
		MaxNoRangeRestartDiscard: maxNoRangeRestartDiscard,
	}), nil
}

func sameServeConfiguration(current, candidate config.Config) bool {
	if current.DataDir != candidate.DataDir ||
		current.Server.TLS.LocalCA != candidate.Server.TLS.LocalCA ||
		current.Server.TLS.AdvertiseEndpoint != candidate.Server.TLS.AdvertiseEndpoint ||
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
	fmt.Fprintf(output, "状态：%s；PID：%d；活跃拉取：%d；监听：%s\n", status.State, status.PID, status.ActivePulls, strings.Join(status.Listeners, ", "))
	return 0
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

func loadControlConfiguration(command string, arguments []string, errorOutput io.Writer) (config.Config, int) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	if err := flags.Parse(arguments); err != nil {
		return config.Config{}, 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(errorOutput, "%s 不接受位置参数\n", command)
		return config.Config{}, 2
	}
	loaded, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return config.Config{}, 1
	}
	return loaded, 0
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
	if _, err := config.LoadFile(*configPath); err != nil {
		fmt.Fprintf(errorOutput, "读取或校验配置失败: %v\n", err)
		return 1
	}
	absPath, err := filepath.Abs(*configPath)
	if err != nil {
		absPath = *configPath
	}
	fmt.Fprintf(output, "配置有效：%s\n", absPath)
	return 0
}

func runOnboard(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer) int {
	flags := flag.NewFlagSet("onboard", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	configPath := flags.String("config", "drg.yaml", "主配置文件路径")
	noStart := flags.Bool("no-start", false, "仅生成配置和证书，不启动服务")
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

	answers := onboard.Answers{
		Listeners:         splitListeners(listeners),
		AdvertiseEndpoint: advertiseEndpoint,
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
	if exitCode := runTLS(ctx, []string{"reconcile", "--config", *configPath}, output, errorOutput); exitCode != 0 {
		return exitCode
	}
	if *noStart {
		fmt.Fprintln(output, "已按 --no-start 跳过启动；请自行将 Docker 的 registry-mirrors 指向访问地址。")
		return 0
	}
	fmt.Fprintln(output, "证书已就绪，正在启动服务；Docker 镜像源配置仍由你自行完成。")
	return runServe(ctx, []string{"--config", *configPath}, output, errorOutput)
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

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "用法：drg <命令>")
	fmt.Fprintln(output, "\n命令：")
	fmt.Fprintln(output, "  onboard  交互式生成首次部署配置")
	fmt.Fprintln(output, "  config validate  严格校验主配置")
	fmt.Fprintln(output, "  tls reconcile  对账本地 CA 与服务端证书")
	fmt.Fprintln(output, "  serve  启动前台 Gateway 服务")
	fmt.Fprintln(output, "  status  查看本地 Gateway 运行状态")
	fmt.Fprintln(output, "  reload  校验并热加载主配置")
	fmt.Fprintln(output, "  stop [--force]  平滑或强制停止本地 Gateway")
}
