# Docker Registry Gateway（DRG）

DRG 是面向 Docker Hub 拉取的多上游代理路由器。它不实现传统 Registry 的存储、推送或删除功能；它在多个可信 Provider 间解析 manifest、按实时健康和速度选择下载源，并在可续传时进行透明切换。

## V1 能力边界

- 仅处理 Docker Hub 的镜像拉取；不改写 `docker` 的使用习惯。
- Provider 可分别承担 manifest 解析和 blob 下载角色，支持上游 Bearer 登录。
- Manifest 多源交叉校验、租约固定、健康/限流/鉴权/完整性状态、Range 续传、分片下载。
- 默认本地 CA、`drg.localhost`、IPv4/IPv6 回环监听；也支持外部 TLS 或纯 HTTP。
- 不支持 push、删除、catalog、tag 列表、referrers、客户端 `docker login` 或跨客户端下载合并。
- 不缓存完整镜像层，也不依赖数据库；状态为受上限约束的本地文件。

## 部署前先确定访问地址

`server.tls.advertise_endpoint` 必须是 **Docker daemon 实际访问 DRG 的 `主机名:端口`**，并且该名称应与 `registry-mirrors` 中的地址一致。它不是 DRG 根据当前网络自动猜测的地址。

| Docker daemon 所在位置 | 推荐监听地址 | 推荐访问地址 / mirror 地址 |
| --- | --- | --- |
| Linux 原生 Docker，DRG 同机原生或容器部署 | `127.0.0.1:5443`（或容器场景的 `0.0.0.0:5443`） | `drg.localhost:5443` |
| Windows Docker Desktop，DRG 在 Windows 宿主机或容器中 | `0.0.0.0:5443` | `host.docker.internal:5443` |
| macOS Docker Desktop，DRG 在 macOS 宿主机或容器中 | `0.0.0.0:5443` | `host.docker.internal:5443` |
| 远程或多机 Docker daemon | 显式的内网监听地址 | 每个 daemon 都能解析到的稳定内网域名，例如 `drg.intra.example:5443` |

Windows/macOS 的 Docker Desktop daemon 位于虚拟机中，默认的 `127.0.0.1`/`drg.localhost` 只指向 daemon 自己，通常到不了宿主机上的 DRG。因此在 Desktop 场景应使用 `host.docker.internal`，并让 DRG 监听 `0.0.0.0:5443`。DRG 签发的本地 CA 叶证书已包含该名称。

不要把 Provider 凭据、`drg.yaml` 或 `.drg/` 目录提交到 Git；其中可能包含本地控制面材料、证书和上游认证信息。

## 原生部署

原生模式是一个单文件 `drg` 进程。发布构建的文件名分别为 `drg-windows-amd64.exe`、`drg-linux-amd64`、`drg-darwin-arm64` 等；从源码构建需要 Go 1.26，仓库已包含 `vendor/`，构建不需要另行拉取 Go 依赖。

### Windows（Docker Desktop）

在 PowerShell 中构建，或将对应 Windows 二进制放入工作目录：

```powershell
./scripts/build-release.ps1
$drg = .\dist\drg-windows-amd64.exe
& $drg onboard --config .\drg.yaml
```

引导时输入 `0.0.0.0:5443` 作为监听地址、`host.docker.internal:5443` 作为访问地址，并选择默认的 `local_ca`。DRG 会生成 `drg.yaml`、`.drg\` 和证书，尝试安装当前用户的根证书；随后重启 Docker Desktop，使其同步新根证书。

在 Docker Desktop 的 **Settings → Docker Engine** 中，将下面字段与现有 JSON 合并后点击 **Apply & restart**，不要覆盖其他已有配置：

```json
{
  "registry-mirrors": ["https://host.docker.internal:5443"]
}
```

验证与日常维护：

```powershell
docker pull hello-world:latest
& $drg status --config .\drg.yaml
& $drg logs --follow --color always --config .\drg.yaml
```

### macOS（Docker Desktop）

在 Terminal 中构建目标二进制，Apple Silicon 使用 `arm64`，Intel 使用 `amd64`：

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -mod=vendor -trimpath -ldflags='-s -w' -o ./drg ./cmd/drg
chmod +x ./drg
./drg onboard --config ./drg.yaml
```

引导时同样选择 `0.0.0.0:5443` 与 `host.docker.internal:5443`。若自动写入系统钥匙串因权限不足而失败，按 `drg tls reconcile` 输出的命令执行；通常形式如下：

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./.drg/pki/ca.crt
```

重启 Docker Desktop 后，在 **Settings → Docker Engine** 合并以下镜像源配置并应用：

```json
{
  "registry-mirrors": ["https://host.docker.internal:5443"]
}
```

```bash
docker pull hello-world:latest
./drg status --config ./drg.yaml
./drg logs --follow --color always --config ./drg.yaml
```

### Linux（原生 Docker Engine）

构建并执行引导：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -trimpath -ldflags='-s -w' -o ./drg ./cmd/drg
chmod +x ./drg
./drg onboard --config ./drg.yaml
```

同机部署可接受默认的 `127.0.0.1:5443` 与 `drg.localhost:5443`。若本地 CA 自动安装因权限不足失败，使用生成的根证书为 Docker 配置信任目录：

```bash
sudo install -D -m 0644 ./.drg/pki/ca.crt /etc/docker/certs.d/drg.localhost:5443/drg-ca.crt
```

将镜像源字段与 `/etc/docker/daemon.json` 中现有 JSON 合并，然后重启 Docker：

```json
{
  "registry-mirrors": ["https://drg.localhost:5443"]
}
```

```bash
sudo systemctl restart docker
docker pull hello-world:latest
./drg status --config ./drg.yaml
./drg logs --follow --color always --config ./drg.yaml
```

`drg start --config ./drg.yaml` 是跨平台的本地后台运行方式；Linux 的长期服务部署可由 systemd 托管 `drg serve --config /etc/drg/drg.yaml`。Windows/macOS 的长期运行同样应交给各自的服务管理器或登录项管理，而不是依赖打开的终端。

## Docker 部署

Docker 部署通过 [docker-compose.example.yml](docker-compose.example.yml) 运行 Linux 容器。它挂载 `drg.yaml` 和 `.drg/`，因此容器重建不会丢失本地 CA、证书、控制面信息或统一日志。

### 1. 生成容器配置

先构建镜像，再通过一次性容器运行交互引导。Windows PowerShell：

```powershell
docker build -t docker-registry-gateway:local .
docker run --rm -it -v "${PWD}:/workspace" docker-registry-gateway:local onboard --config /workspace/drg.yaml --no-start --skip-trust-install
```

Linux/macOS Shell：

```bash
docker build -t docker-registry-gateway:local .
docker run --rm -it -v "$PWD:/workspace" docker-registry-gateway:local onboard --config /workspace/drg.yaml --no-start --skip-trust-install
```

Linux 的 bind mount 还需处理容器内非 root 用户的文件权限：在上述 Linux 命令中加上 `--user "$(id -u):$(id -g)"`，让引导先以当前宿主机用户生成 `drg.yaml` 与 `.drg/`；在启动 Compose 前，再将数据目录交给镜像内 `drg` 用户：

```bash
DRG_UID=$(docker run --rm --entrypoint sh docker-registry-gateway:local -c 'id -u drg')
DRG_GID=$(docker run --rm --entrypoint sh docker-registry-gateway:local -c 'id -g drg')
sudo chown -R "$DRG_UID:$DRG_GID" ./.drg
```

只调整 `.drg/`，不要把整个源码目录改为容器用户所有。

选择地址时遵循上表：Linux 同机 Docker 用 `0.0.0.0:5443` / `drg.localhost:5443`，Windows/macOS Docker Desktop 用 `0.0.0.0:5443` / `host.docker.internal:5443`。引导完成后，将生成的 `drg.yaml` 中：

```yaml
data_dir: .drg
```

改为：

```yaml
data_dir: /var/lib/drg
```

这是必需步骤：Compose 将宿主机的 `./.drg` 挂载到容器内 `/var/lib/drg`。不要删除宿主机已经生成的 `./.drg` 目录。

### 2. 安装 Docker daemon 对本地 CA 的信任

容器不能安全修改 Docker 宿主机的证书库。根证书始终在宿主机工作目录的 `./.drg/pki/ca.crt`；按 **运行 Docker daemon 的平台** 安装，而不是按容器内 Linux 安装：

| Docker daemon 平台 | 安装根证书 | 后续动作 |
| --- | --- | --- |
| Linux | `sudo install -D -m 0644 ./.drg/pki/ca.crt /etc/docker/certs.d/<访问地址>/drg-ca.crt` | 重启 Docker |
| Windows Docker Desktop | `certutil -user -addstore Root .\.drg\pki\ca.crt` | 重启 Docker Desktop |
| macOS Docker Desktop | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./.drg/pki/ca.crt` | 重启 Docker Desktop |

将 Linux 示例中的 `<访问地址>` 替换为配置的完整 `advertise_endpoint`，例如 `drg.localhost:5443`。如果地址或端口变更，执行 `drg tls reconcile`（容器内通过下文的 `docker compose exec`）以重新签发相应 SAN 的叶证书，并为新访问地址安装根证书。

### 3. 启动、配置 mirror 与验收

```bash
docker compose -f docker-compose.example.yml up -d --build --force-recreate
docker compose -f docker-compose.example.yml ps
docker compose -f docker-compose.example.yml exec drg drg doctor --config /etc/drg/drg.yaml
docker compose -f docker-compose.example.yml exec drg drg logs --follow --color always --config /etc/drg/drg.yaml
```

Docker daemon 的镜像源配置仍由部署者维护：Linux 合并到 `/etc/docker/daemon.json`，Windows/macOS 合并到 Docker Desktop 的 Docker Engine JSON。镜像源 URL 必须等于本机配置的 `advertise_endpoint`，例如：

```json
{
  "registry-mirrors": ["https://drg.localhost:5443"]
}
```

或 Docker Desktop 场景：

```json
{
  "registry-mirrors": ["https://host.docker.internal:5443"]
}
```

应用 Docker 配置并重启 daemon 后，拉取一个未存在的镜像验证完整路径：

```bash
docker pull hello-world:latest
docker compose -f docker-compose.example.yml exec drg drg status --config /etc/drg/drg.yaml
```

`docker compose logs -f drg` 适合查看容器生命周期输出；DRG 的路由、切换、分片与 Provider 诊断应统一通过 `drg logs` 查看。容器停止或升级前可执行 `docker compose -f docker-compose.example.yml exec drg drg stop --config /etc/drg/drg.yaml`；紧急情况下才使用 `--force`。

## 常用维护命令

```powershell
drg doctor --skip-providers       # 只读诊断配置、TLS、Docker 根信任、监听和 Docker daemon
drg config migrate                # 检查是否需要迁移配置格式
drg provider list
drg provider add --name mirror-a --url https://example.invalid --pull-provider
drg reload                        # 校验后热加载；仅影响新请求
drg status
drg logs --limit 50
drg logs --follow --limit 50      # 先显示最近日志，再持续跟随；回车分隔，Ctrl+C 退出
drg logs --follow --color always  # 强制彩色输出；默认 auto 仅在终端启用
drg stop                          # 显示排空进度，最长等待 30 秒
drg stop --force                  # 立即中断活跃拉取
drg tls reconcile
drg tls rotate-root               # 先准备新根并安装为额外 Docker 信任根，再安全激活
drg tls rotate-root --activate    # 容器部署时，在宿主机完成手动信任安装后的显式确认
drg tls clear-previous-root       # 完成旧根 Docker 信任清理后，显式解除下一次轮换锁定
```

大 blob 启动分片下载时，`drg logs --follow` 会输出 `segmented_download_started`，其中包含逻辑分片数量及各上游实际 Range；这可作为分片是否启用的直接诊断证据。`drg events` 暂时保留为兼容别名。

### 本地 CA 根轮换

`drg tls rotate-root` 绝不会先切换服务端证书再尝试安装 Docker 信任。它先将 `ca.next.crt` 作为额外信任根安装；成功后才激活新根和新叶证书，并保留旧根为 `ca.previous.crt`。容器内运行时，DRG 不会猜测宿主机路径：它会停在“待激活”状态、输出宿主机操作说明，用户完成信任安装后执行带 `--activate` 的同一命令。

旧根的本地标记会一直保留，避免下一次轮换误删迁移材料。仅当你已从 Docker 信任库显式移除旧根后，才执行 `drg tls clear-previous-root`。根轮换完成后重启 Gateway，使新连接使用新叶证书。

## 构建与验证

Windows PowerShell：

```powershell
./scripts/build-release.ps1
go test ./...
```

脚本会产出 Windows、Linux、macOS 的 amd64 与 arm64 原生二进制到 `dist/`。发布前还应在目标平台执行 `drg doctor`，并用真实 Docker daemon 完成 `docker pull` 验收。

## 无公网 Docker E2E fixture

[`scripts/docker-e2e-fixture.ps1`](scripts/docker-e2e-fixture.ps1) 提供一个只含 OCI config 的本地镜像源，配合 [`testdata/docker-e2e-local.yaml`](testdata/docker-e2e-local.yaml) 可在无法访问 Docker Hub 的环境中验收完整成功链路：Docker Client → DRG → Provider。该 fixture 仅用于测试，默认监听 `56999`，不属于 Gateway 运行时组件。
