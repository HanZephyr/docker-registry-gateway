# Docker Registry Gateway（DRG）

DRG 是面向 Docker Hub 拉取的多上游代理路由器。它不实现传统 Registry 的存储、推送或删除功能；它在多个可信 Provider 间解析 manifest、按实时健康和速度选择下载源，并在可续传时进行透明切换。

## V1 能力边界

- 仅处理 Docker Hub 的镜像拉取；不改写 `docker` 的使用习惯。
- Provider 可分别承担 manifest 解析和 blob 下载角色，支持上游 Bearer 登录。
- Manifest 多源交叉校验、租约固定、健康/限流/鉴权/完整性状态、Range 续传、分片下载。
- 默认本地 CA、`drg.localhost`、IPv4/IPv6 回环监听；也支持外部 TLS 或纯 HTTP。
- 不支持 push、删除、catalog、tag 列表、referrers、客户端 `docker login` 或跨客户端下载合并。
- 不缓存完整镜像层，也不依赖数据库；状态为受上限约束的本地文件。

## 快速开始

先构建或下载适合平台的 `drg` 单文件二进制，再运行：

```powershell
drg onboard
```

引导会生成 `drg.yaml`、默认本地 CA 和服务端证书，并启动服务。Docker 的镜像源配置始终由部署者自行维护；DRG 不会修改它。默认本机部署可在 Docker daemon 配置中手工加入：

```json
{
  "registry-mirrors": ["https://drg.localhost:5443"]
}
```

重启或重载 Docker daemon 后执行 `docker pull busybox` 验证。使用本地 CA 时，`drg onboard`/`drg tls reconcile` 会按平台尝试安装信任；若 DRG 在容器中运行，命令会输出应在 Docker 宿主机执行的说明。

## 常用维护命令

```powershell
drg doctor --skip-providers       # 只读诊断配置、TLS、监听和 Docker daemon
drg provider list
drg provider add --name mirror-a --url https://example.invalid --pull-provider
drg reload                         # 校验后热加载；仅影响新请求
drg status
drg events --limit 50
drg stop                           # 显示排空进度，最长等待 30 秒
drg stop --force                   # 立即中断活跃拉取
drg tls reconcile
drg tls rotate-root                # 保留旧根的信任材料后轮换本地 CA
```

## 容器部署

使用 [docker-compose.example.yml](docker-compose.example.yml) 前，将配置中的 `data_dir` 设置为 `/var/lib/drg`，并把 `server.tls.advertise_endpoint` 改为 Docker daemon 实际可访问的主机名和端口。容器不会猜测或改写宿主机 Docker 配置、hosts 或证书目录；启动输出会给出相应平台的信任步骤。

## 构建与验证

Windows PowerShell：

```powershell
./scripts/build-release.ps1
go test ./...
```

脚本会产出 Windows、Linux、macOS 的 amd64 与 arm64 原生二进制到 `dist/`。发布前还应在目标平台执行 `drg doctor`，并用真实 Docker daemon 完成 `docker pull` 验收。
