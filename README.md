# Docker Registry Gateway（DRG）

DRG 是 Docker Hub 的多上游镜像拉取网关。将它配置为 Docker mirror 后，继续使用原本的 `docker pull` 命令即可；DRG 会在已配置的上游之间选择可用下载源，并在支持 Range 的上游之间透明续传。

> 当前版本只代理 Docker Hub 拉取，不是传统 Registry：不支持镜像推送、删除、镜像列表、`docker login` 或镜像层缓存。

## 适用场景

- Docker Hub 访问不稳定、限速或偶发中断。
- 希望统一使用多个可信镜像上游，并保留 Docker 原有使用方式。
- 希望在本机或内网部署一个轻量、无数据库的拉取网关。

DRG 会生成并维护本地运行数据、证书和日志；请不要将 `drg.yaml` 或 `.drg/` 提交到 Git。

## 先确定访问地址

`registry-mirrors` 中的 URL 必须与 DRG 引导时填写的“访问地址”一致，并且必须是 **Docker daemon 实际能访问到的地址**。以下六种本机部署组合可直接使用：

| Docker daemon 平台 | DRG 部署方式 | 引导时填写的监听地址 | 引导时填写的访问地址 | `registry-mirrors` 值 |
| --- | --- | --- | --- | --- |
| Linux | 原生进程 | `127.0.0.1:5443` | `drg.localhost:5443` | `https://drg.localhost:5443` |
| Linux | Docker 容器 | `0.0.0.0:5443` | `drg.localhost:5443` | `https://drg.localhost:5443` |
| Windows Docker Desktop | 原生进程 | `0.0.0.0:5443` | `host.docker.internal:5443` | `https://host.docker.internal:5443` |
| Windows Docker Desktop | Docker 容器 | `0.0.0.0:5443` | `host.docker.internal:5443` | `https://host.docker.internal:5443` |
| macOS Docker Desktop | 原生进程 | `0.0.0.0:5443` | `host.docker.internal:5443` | `https://host.docker.internal:5443` |
| macOS Docker Desktop | Docker 容器 | `0.0.0.0:5443` | `host.docker.internal:5443` | `https://host.docker.internal:5443` |

容器部署中的监听地址是 **容器内** DRG 的监听地址；`docker-compose.example.yml` 会将端口发布到宿主机。Windows 和 macOS 的 Docker Desktop daemon 运行在虚拟机中，通常不能通过 `127.0.0.1` 访问宿主机上的 DRG，因此应使用 `host.docker.internal`。

如果 Docker daemon 与 DRG 不在同一台机器，请使用双方都能解析和访问的稳定内网域名（例如 `drg.intra.example:5443`），并将该名称作为访问地址和 mirror 地址。

## 原生部署

从 [GitHub Releases](https://github.com/HanZephyr/docker-registry-gateway/releases) 下载对应平台和架构的单文件二进制：Windows 使用 `.exe`，Apple Silicon 选择 `darwin-arm64`，Intel Mac 选择 `darwin-amd64`。

### 1. 运行引导

Windows PowerShell：

```powershell
$drg = .\drg-windows-amd64.exe
& $drg onboard --config .\drg.yaml
```

Linux：

```bash
mv ./drg-linux-amd64 ./drg
chmod +x ./drg
./drg onboard --config ./drg.yaml
```

macOS：将 `darwin-arm64` 或 `darwin-amd64` 二进制改名为 `drg` 后执行同一命令：

```bash
mv ./drg-darwin-arm64 ./drg # Intel Mac 请使用 drg-darwin-amd64
chmod +x ./drg
./drg onboard --config ./drg.yaml
```

引导时按上表填写监听地址和访问地址；首次使用建议选择默认的 `local_ca`。至少配置一个既可解析又可下载的上游 Provider。引导默认会启动 DRG；只想先生成配置时加 `--no-start`。下文的 `drg` 表示已加入 `PATH` 的二进制；未加入时，请使用 Windows 的 `& $drg` 或 Linux/macOS 的 `./drg`。

DRG 会尝试自动安装本地根证书。若权限不足，它会输出对应平台的操作提示；完成后执行 `drg tls reconcile --config <配置文件>`，然后重启 Docker daemon 或 Docker Desktop。

### 2. 配置 Docker mirror

Windows / macOS：在 Docker Desktop 的 **Settings → Docker Engine** 中，将下面字段与现有 JSON 合并后点击 **Apply & restart**：

```json
{
  "registry-mirrors": ["https://host.docker.internal:5443"]
}
```

Linux：将以下字段与 `/etc/docker/daemon.json` 的现有 JSON 合并，然后重启 Docker：

```json
{
  "registry-mirrors": ["https://drg.localhost:5443"]
}
```

访问地址不是这两个示例时，请替换为引导时填写的完整地址。

### 3. 验证

```bash
docker pull hello-world:latest
drg status --config ./drg.yaml
drg logs --follow --color always --config ./drg.yaml
```

`logs --follow` 会持续显示路由、上游选择和切换信息；按回车可插入空行分隔，按 `Ctrl+C` 退出。

### 长期运行

`drg serve --config ./drg.yaml` 以前台方式运行，适合交由 systemd、Windows 服务或 macOS 登录项托管。仅在本机临时后台运行时使用：

```bash
drg start --config ./drg.yaml
```

## Docker 部署

Docker 部署适合已取得源码或已自行构建镜像的场景。网关容器不能替宿主机 Docker 安装证书，因此仍需在运行 Docker daemon 的主机上完成根证书信任。

### 1. 生成配置

在仓库目录执行：

```bash
docker build -t docker-registry-gateway:local .
docker run --rm -it -v "$PWD:/workspace" docker-registry-gateway:local \
  onboard --config /workspace/drg.yaml --no-start --skip-trust-install
```

Windows PowerShell 将挂载参数改为：

```powershell
docker run --rm -it -v "${PWD}:/workspace" docker-registry-gateway:local onboard --config /workspace/drg.yaml --no-start --skip-trust-install
```

Linux 宿主机需要让引导容器以当前用户写入工作目录；配置生成后，再将数据目录交给运行网关的容器用户：

```bash
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/workspace" docker-registry-gateway:local \
  onboard --config /workspace/drg.yaml --no-start --skip-trust-install
DRG_UID=$(docker run --rm --entrypoint sh docker-registry-gateway:local -c 'id -u drg')
DRG_GID=$(docker run --rm --entrypoint sh docker-registry-gateway:local -c 'id -g drg')
sudo chown -R "$DRG_UID:$DRG_GID" ./.drg
```

将生成的 `drg.yaml` 中 `data_dir: .drg` 改为 `data_dir: /var/lib/drg`，以便 Compose 持久化运行数据。

### 2. 信任本地根证书

根证书位于宿主机的 `./.drg/pki/ca.crt`。按 Docker daemon 所在平台安装：

| 平台 | 操作 |
| --- | --- |
| Linux | `sudo install -D -m 0644 ./.drg/pki/ca.crt /etc/docker/certs.d/<访问地址>/drg-ca.crt`，然后重启 Docker |
| Windows Docker Desktop | `certutil -user -addstore Root .\.drg\pki\ca.crt`，然后重启 Docker Desktop |
| macOS Docker Desktop | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./.drg/pki/ca.crt`，然后重启 Docker Desktop |

将 `<访问地址>` 替换为完整的访问地址，例如 `drg.localhost:5443` 或 `host.docker.internal:5443`。

### 3. 启动与验证

```bash
docker compose -f docker-compose.example.yml up -d --build --force-recreate
docker compose -f docker-compose.example.yml ps
docker compose -f docker-compose.example.yml exec drg drg logs --follow --color always --config /etc/drg/drg.yaml
```

随后按“配置 Docker mirror”的方式修改 Docker daemon 配置并重启，再执行：

```bash
docker pull hello-world:latest
docker compose -f docker-compose.example.yml exec drg drg status --config /etc/drg/drg.yaml
```

## 日常维护

```bash
drg doctor --config ./drg.yaml          # 只读检查配置、证书、Docker 信任与 Provider
drg provider list --config ./drg.yaml   # 查看上游
drg provider add --name mirror-a --url https://example.invalid --resolver --pull-provider --config ./drg.yaml
drg reload --config ./drg.yaml          # 校验后热加载配置，仅影响新请求
drg status --config ./drg.yaml
drg logs --limit 50 --config ./drg.yaml
drg logs --follow --color always --config ./drg.yaml
drg stop --config ./drg.yaml             # 等待当前拉取排空后停止
drg stop --force --config ./drg.yaml     # 立即中断活跃拉取
drg tls reconcile --config ./drg.yaml    # 对账、补齐或续签本地证书
```

上游需要认证时，优先将密码或 PAT 放入权限受限的文件，再通过 `--secret-file` 添加 Provider；`--password` 支持明文配置，但不建议使用。

## 常见问题

**配置 mirror 后日志没有新请求**

确认 Docker daemon 已重启，`registry-mirrors` 使用的是 DRG 的访问地址，并拉取一个本机尚不存在的镜像。Windows/macOS Docker Desktop 场景通常应使用 `host.docker.internal:5443`，而不是 `drg.localhost:5443`。

**Docker 报证书不受信任**

执行 `drg tls reconcile --config ./drg.yaml`，按输出提示安装根证书，并重启 Docker daemon 或 Docker Desktop。

**如何确认拉取经过 DRG**

在另一终端运行 `drg logs --follow --color always --config ./drg.yaml`，再执行 `docker pull`。出现 `resolution_selected`、`manifest_source_selected` 或 `blob_source_selected` 即表示请求已进入 DRG。

**如何查看全部命令和参数**

```bash
drg --help
drg <命令> --help
```

## 安全说明

Provider 的账号、密码、PAT、证书和运行状态都可能保存在 `drg.yaml`、密码文件或 `.drg/` 中。请限制这些文件的访问权限，不要提交到版本库，也不要将其上传到公开位置。

安全问题请参阅 [SECURITY.md](SECURITY.md)。
