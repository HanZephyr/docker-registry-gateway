# Docker Registry Gateway — 领域词汇

## 当前产品边界

第一期只透明适配 Docker Hub（`docker.io` / `registry-1.docker.io`）的镜像拉取。Docker 客户端对 Gateway 始终匿名；Gateway 保留对 Provider 的自动认证。`ghcr.io`、`quay.io` 等其他 Registry 的路由、认证与运行时接入不属于当前范围。

## Gateway

面向单一自托管使用者的 OCI 拉取代理。它保持既有 `docker pull` 使用方式，并在受信任的上游之间作出拉取决策。

Gateway 是拉取流量的路由器，不是传统 Registry 的替代品。它只提供拉取链路需要的 V2 探测、manifest/index 的 `GET`/`HEAD` 以及 blob 的 `GET`/`HEAD`/Range；tags、catalog、referrers、push、delete 和其他 Registry 管理接口不属于其职责。

除使用者显式配置的 Provider 外，Gateway 不发起任何外部网络连接：首版没有遥测、崩溃上报、自动更新检查或其他控制面服务。

## TLS Deployment（TLS 部署）

默认启用 `local_ca: true`。使用者必须显式配置 Docker daemon 实际访问的 `advertise_endpoint`（`host:port`，可为域名或 IP，不能由 Gateway 猜测）。首次启动时，Gateway 为该实例生成本地根 CA 和服务端叶子证书：配置域名写入 DNS SAN、配置 IP 写入 IP SAN，且叶子证书额外写入 `host.docker.internal` 的 DNS SAN；仅 CN 或 DNS SAN 均不能让 IP 访问通过校验。变更 `advertise_endpoint` 时重新签发叶子证书，根 CA 保持不变。

原生部署且具备相应文件权限时，CLI 自动将根证书安装到该 Docker 实例的信任位置；不改写 `daemon.json` 或镜像源配置。Docker 的信任位置按访问主机名和端口区分，故同一根证书会为 `advertise_endpoint`、`host.docker.internal` 及其他已签发的 Gateway 访问名分别安装。容器化部署不能越过容器边界改动宿主机信任库，因此 Gateway 将根证书保存在持久卷中，并输出按目标平台和全部访问名生成的复制/安装命令。使用外部受信证书或外部 TLS 终止时，可关闭 `local_ca` 并改用 `cert_file`、`key_file` 或纯后端监听。域名解析由部署者的 DNS 或 hosts 负责，Gateway 不擅自修改解析配置。

稳定部署优先使用本地域名作为 `advertise_endpoint`，并将该名称解析到当前 Gateway IP；地址迁移时只更新解析，不更换服务端证书或 Docker 信任根。hosts 规则必须在运行 Docker daemon 的解析环境中生效，而不只是执行 `docker` 命令的终端；Docker Desktop 等虚拟化 daemon 需按其实际解析环境处理。IP 端点仅适合静态 IP 场景。

`drg.localhost` 是默认的单机引导域名，对应同一 Docker 宿主机上的回环访问，并作为默认服务端证书的 DNS SAN。服务端叶子证书同时含有 `host.docker.internal` SAN，以覆盖 Docker Desktop 的常用宿主机访问名。Gateway 可同时监听多个显式地址；默认监听 `127.0.0.1:5443` 与 `[::1]:5443`，避免解析优先 IPv6 时无法连接。若使用 `host.docker.internal`，部署者还必须额外配置一个可被 Docker Desktop VM 访问的监听地址。配置校验拒绝重复或相互覆盖的监听地址（例如同端口的 `0.0.0.0` 与 `127.0.0.1`）。它不是多机或远程访问地址：此类部署必须显式替换为可在每个 Docker daemon 侧解析到 Gateway 的稳定内网域名和监听地址，并触发 TLS 对账以重签叶子证书。

## Platform Trust Flow（平台信任流程）

本地根 CA 的安装按运行 Docker daemon 的宿主平台处理，而不是按 Gateway 的运行环境处理。原生 Gateway 自动识别宿主平台并在权限允许时执行对应安装；权限不足时给出该平台的修复命令。Linux 为每个访问名写入 `/etc/docker/certs.d/<name>/drg-ca.crt`；Windows Docker Desktop 将根导入当前用户的 Trusted Root Certification Authorities，再由 Desktop 同步，不能把带端口的 `<name>:<port>` 当作 NTFS 目录名；macOS 尝试写入系统钥匙串的根信任，权限不足时输出 `security` 命令。容器中的 Linux 环境不能推断 Docker 宿主机是 Linux、Windows 还是 macOS，故只保存根证书并分别输出三套带有实际 `advertise_endpoint` 的宿主机操作提示，绝不猜测或改写宿主机文件。

## TLS Reconciliation（TLS 对账）

`drg tls reconcile` 是本地 CA 生命周期的幂等维护入口，服务启动时调用同一逻辑。它核对根 CA、服务端叶子证书、`advertise_endpoint` 的 SAN 和当前平台所需的 Docker 信任安装；可安全地补齐缺失的根证书安装并在到期预警窗口内续签叶子证书。它不静默轮换根 CA：根 CA 临近到期或已失效时必须明确要求使用者执行根 CA 轮换，并完成新根证书的信任安装后才切换服务端证书。

Gateway 在运行期每日执行同一 TLS 对账逻辑；叶子证书进入续签窗口时自动重签并热加载，根 CA 只产生到期告警，不自动轮换。

显式根 CA 轮换采用双信任根迁移：先生成并安装新根 CA，保留旧根 CA，同时确认新根已进入所有 Docker 信任位置后才切换服务端叶子证书。旧根 CA 仅能由使用者显式清理，Gateway 不自动删除。

首次签发后的根 CA 指纹是实例身份的一部分。若配置已记录该指纹而根 CA 证书或私钥丢失，Gateway 必须拒绝启动并要求使用者显式执行恢复/换根流程；不得通过自动生成新根 CA 继续运行。

Gateway 不对 CA 私钥或 Provider 凭据做应用层加密，以保持无人值守运行；其保护边界是操作系统文件权限或 ACL。CA 私钥权限不安全时拒绝启动；`secret_file` 权限不安全时产生高优先级告警。

## Control CLI（控制命令行）

Gateway 的本地维护入口。它通过受操作系统权限保护的本地控制套接字管理服务、验证和热加载配置、维护 Provider、查看状态与事件；不提供 Web 后台或用户角色。首版以 Linux、Windows、macOS 的原生单二进制交付。容器部署时使用 `docker exec <gateway-container> drg ...` 运行同一 CLI。Docker daemon 的 mirror 配置属于使用者的部署边界，CLI 不读取、生成、校验或修改它；本地 CA 的根证书安装是独立且明确的 TLS 信任操作。

维护 Provider 的 CLI 命令以主配置为唯一事实来源：先进行完整校验，再以原子替换写入配置、保留备份并触发热加载；手工改配置仍可通过 `drg reload` 生效。`drg doctor` 是只读诊断入口，检查配置、证书生命周期、Docker 信任文件、监听地址、Provider 能力与本机 Docker 环境可达性，但不改写 Docker 的镜像源配置。

热加载只影响新请求，进行中的拉取保留开始时的配置快照。常规 `drg stop` 或重启先停止新请求、显示活跃拉取数、排空进度与剩余等待时间，再在有限排空期后关闭未完成连接；`--force` 选项跳过排空并立即取消活跃传输，同时明确提示 Docker 将重试。

`drg onboard` 是首次安装的交互式引导入口：逐项收集监听地址、访问地址、本地 CA、Provider、资源预算与配置位置，生成并校验主配置、执行 TLS 对账，并在原生部署时启动服务。它不修改 Docker 的镜像源配置，完成后只输出按部署环境适用的 Docker 配置与证书信任说明；已有配置时默认拒绝覆盖。

## Provider（镜像源）

一条完整的上游配置，包含名称、URL、解析源开关、下载源开关、可选优先级和上游认证配置。一个 Provider 可以同时承担两种职责。优先级在 `provider_priority` 解析策略下是强制且唯一的排序；下载源侧仅作为冷启动或分数相近时的偏好，不能压过实时健康和速度。

Provider 的名称和规范化 URL 在同一份配置内唯一。仅当 Resolver 使用优先级策略时，所有 Resolver 必须配置合法且唯一的优先级。

`drg init` 的默认配置只包含匿名的官方 Docker Hub Provider（`https://registry-1.docker.io`），同时担任 Resolver 与 Pull Provider；任何第三方镜像源均由使用者显式添加。

## Startup Configuration Validation（启动配置校验）

Gateway 在启动前拒绝无解析源、无下载源、重复名称、重复规范化 URL、非法 URL 或不可读取凭据引用的配置。当 Resolver 使用优先级策略时，它还拒绝缺失、非法或重复优先级。Provider 的即时网络或认证失败只改变其健康状态并产生诊断，不阻止 Gateway 启动和后续自动恢复。

主配置从首版起带有明确版本号，并采用严格模式校验未知字段、拼写和类型错误。热更新校验失败时旧配置继续生效；未来配置结构演进通过显式 `drg config migrate` 处理，不静默猜测旧字段含义。

主配置中的相对文件路径一律相对该主配置文件所在目录解析，包括 `secret_file`、`ca_file`、`data_dir` 和 `temp_dir`；`drg validate` 与 `drg doctor` 显示最终解析的绝对路径。

## Provider Admission（镜像源准入）

Provider 首次加入或配置热更新时，Gateway 使用全局 `probe_ref`（默认 `library/busybox:latest`）对它执行 Registry V2、上游认证、manifest 获取和 blob Range 探测，并记录其下载续传能力。全局 `allow_non_range_providers` 默认 `true`；启用时，Range 不可用的下载源可参与从零开始的下载，但被标记为降级下载源。禁用时，Provider 准入失败。没有可 Range 续传的源时，Gateway 只能在有限恢复预算内从零重拉并丢弃已传字节后继续，超出预算则终止该下游连接。

Provider URL 不得与 Gateway 自身的对外地址相同。Gateway 间的上游请求携带仅用于路由防护的实例与跳数信息；请求回到自身或超过有限跳数时，Gateway 终止请求并记录路由环路事件。

## Mirror Client Authentication Constraint（Mirror 客户端认证约束）

经典 Docker Engine 的 `registry-mirrors` 拉取仍以逻辑镜像名 `docker.io/...` 选择客户端认证信息，而非实际 mirror 地址。因此 `docker login <gateway-host>` 的凭据不能透明用于 `docker pull nginx` 的 Gateway 身份校验。若未来提供该认证模式，Gateway 必须剥离自己的下游 token，避免它流向 Provider；但这不能弥补 Docker 未发送该 token 的限制。

## Resolver（解析源）

`resolver: true` 的 Provider。它被允许将可变镜像引用（例如 tag）解析为 manifest 或 index digest，是信任边界的一部分。

任何 Provider 都可以由使用者显式设为解析源；Gateway 不会因一次可用探测或下载成功而自动成为解析源。

## Pull Provider（下载源）

`pull_provider: true` 的 Provider。它只被允许按已确定的 digest 提供 manifest 引用的 config 与 layer blob，不决定 tag 指向的内容。

## Upstream Redirect（上游重定向）

Provider 返回的 blob 重定向由 Gateway 在内部跟随，Docker 客户端始终只连接 Gateway。Gateway 在最终响应上继续验证 Range 和完整性；跨源重定向不得转发 Provider 的认证信息，且默认拒绝向不安全 HTTP 降级。

## Byte-Preserving Transfer（原始字节传输）

Gateway 对 manifest 与 blob 只传递原始 OCI 字节：上游请求要求 `Accept-Encoding: identity`，禁用自动解压；下游不添加压缩、解压或任何转码。此规则不可配置，以保持 Range 偏移和 content digest 的语义。

manifest 显式声明的外部 layer URL 同样原样透传，由 Docker 依其原始语义获取；首版不改写 manifest 以强制这类少数内容经过 Gateway，因此不承诺对其路由或加速。

## Segmented Download（分片下载）

对已知大小且可 Range 的大 blob，Gateway 将未完成区间切成逻辑上互不重叠的分片，按 Provider 的实时性能并发下载，并依顺序转发给 Docker。跨 Provider 的相邻分片在物理请求中保留固定的小重叠区间，Gateway 比对重叠字节后只输出一次；整 blob digest 仍是最终完整性依据。分片仅在当前拉取期间暂存于受硬上限和背压控制的系统临时目录，传输结束即删除，不构成持久缓存；空间不足时降级为单流下载。

每个下游 Docker 拉取拥有独立的上游传输和临时状态。Gateway 不合并不同客户端对同一 blob 的并发请求；下游取消时，Gateway 取消其关联的上游请求、清理临时分片并释放资源预算。

## Provider Authentication（上游认证）

Gateway 代表使用者完成每个 Provider 的上游认证；Docker 客户端不需要登录任何上游。Gateway 使用 Provider 的本地凭据取得并缓存其短期 token，不把一个 Provider 的 token 转发给另一个 Provider。

当 Gateway 监听非回环地址且至少一个 Provider 配置了凭据时，`drg start` 与 `drg validate` 必须输出高优先级风险告警，但不阻止部署。

首版只支持标准 Registry Bearer challenge，以及用户名配合密码或 PAT 的无人值守认证；不支持浏览器 OAuth、MFA 交互、Docker credential helper、mTLS 客户端证书或其他交互式认证方式。

## Provider Transport Security（Provider 传输安全）

Provider 默认必须使用 HTTPS。使用私有根证书的 HTTPS Provider 通过其 `ca_file` 显式信任；Gateway 不提供跳过 HTTPS 证书校验的选项。仅 HTTP 的 Provider 必须显式声明 `allow_insecure_http: true`，并在 `drg start` 与 `drg validate` 中产生高优先级安全告警。

Gateway 访问 Provider 时固定直连，不继承宿主机的 `HTTP_PROXY` 或 `HTTPS_PROXY` 环境变量，首版也不提供上游代理配置。

## Source Credential（上游凭据）

使用者为一个需要认证的 Provider 提供的机器身份，例如用户名与访问令牌。首选方式是主配置中的用户名加上 `secret_file`：该文件只包含一行密码或 PAT。为兼容简单部署，Provider 也可使用主配置中的明文 `password`；`password` 与 `secret_file` 互斥，所有日志、状态和错误信息均须脱敏。明文密码不阻止运行，但 `drg start` 与 `drg validate` 必须给出高优先级安全告警。

## Resource Budget（资源预算）

Gateway 通过主配置定义全局并发拉取数、单 blob 最大并行分片数和分片临时磁盘额度，并提供保守默认值。预算耗尽时，Gateway 以排队、背压或降级为单流下载保护宿主机资源，不因正常资源竞争直接中断正在进行的 Docker 拉取。

分片下载的最小 blob 大小和无 Range 下载源的最大重拉丢弃字节预算也属于资源配置，并提供保守默认值；Provider 速度与切换判断仍保持内部自适应。

资源配置还定义全局下游在途请求数和排队拉取数上限。排队已满时，Gateway 返回带重试提示的临时不可用；首版不采用按 IP 的下游限流。

分片临时文件默认位于系统临时目录，使用者可通过资源配置指定可写的专用 `temp_dir`。该目录空间不足时，Gateway 停止新增分片并降级为单流下载，不写入未声明的替代位置。

分片数据以独立的 Gateway 专属临时目录保存。Gateway 正常完成时立即清理；启动恢复时只清理已确认不再被活动进程持有的自身临时目录，不扫描或删除系统临时目录的其他内容，也不恢复中断的拉取状态。

## File Retention（文件保留）

Gateway 不依赖数据库，持久诊断数据使用有界文件保留。统一日志按大小滚动，默认最多保留 7 天或 100 MB，任一上限达到即删除最旧文件；它同时记录服务生命周期、Provider 探测与拉取路由。健康历史按分钟聚合并默认保留 7 天。解析租约在到期时自动清理。所有保留上限可在主配置中调整。

## Resolution Decision（解析决策）

Gateway 对一个可变镜像引用选定的 manifest 或 index digest，以及作出该选择所使用的策略与候选结果。

解析决策保留 Docker 原始的媒体类型协商语义：Gateway 将请求的 `Accept` 头传给全部 Resolver，并以规范化的“镜像引用 + Accept 集合”作为决策与租约键。Gateway 不擅自选择镜像平台，Docker 的 `--platform` 仍决定其期望的 manifest 或 index。

带 content digest 的镜像引用是调用者明确指定的不可变内容；Gateway 跳过 Resolver、冲突策略和解析租约，直接由 Pull Provider 获取该 digest 对应内容，并继续执行 manifest/blob 完整性校验与下载源切换。

默认 Resolver 冲突策略为 `majority`。当不存在多数结果时，默认平局决胜器为 `rendezvous_hash`，对相同引用和候选 digest 产生稳定选择且不依赖 Provider 声明顺序；使用者可显式改为 `configured_order` 或 `fail`。

## Decision Lease（决策租约）

解析决策在有限有效期内保持不变的承诺。它使同一可变引用在租约内不会因平局选择而改变结果。默认有效期为 10 分钟。

任一 Resolver、Resolver 优先级、冲突策略或平局决胜器变更时，Gateway 立即清空全部决策租约；仅变更 Pull Provider 时保留租约。

控制命令 `drg resolver invalidate <reference>` 可主动清空一个引用的租约，`drg resolver invalidate --all` 可清空全部租约。

## Tie Breaker（平局决胜器）

当解析策略无法唯一选出 digest 时，在等价候选中产生唯一解析决策的规则。它不参与正常的 Resolver 健康或性能排序。

首版仅支持 `configured_order`、`rendezvous_hash` 和 `fail` 三种平局决胜器。

## Pull Notice（拉取提示）

Gateway 对本次拉取所作路由或解析决策的用户可见说明。`drg logs` 统一日志是权威诊断入口；Gateway 发送的 Docker Warning header 仅为尽力而为的补充，绝不改变已成功拉取的内容。

统一日志、健康历史和错误信息可记录镜像引用、digest、Provider 名称与脱敏后的上游 origin，以支持诊断；不得记录认证头、密码/PAT、Bearer token、Cookie、`secret_file` 内容或包含签名参数的完整重定向 URL。

Gateway 对下游响应使用 OCI 所需头部的白名单：保留 `Content-Type`、`Docker-Content-Digest`、`Content-Length`、`Content-Range`、`ETag`、`Last-Modified` 和适用的 `Retry-After`，并可自行增加尽力而为的 `Warning`。上游的认证挑战、Cookie、重定向、跳数及其他未允许头部不向下游转发。

## Health State（健康状态）

Provider 的近期探测和传输质量记录。Gateway 重启后保留历史指标供 CLI 查看，但不继承熔断状态；所有 Provider 进入待快速探测状态后再参与正常选路。

Gateway 使用首字节时间、连续无进度时间和近期吞吐的滑动统计自适应判断 Provider 的速度与卡顿，不向使用者暴露一组下载超时或最低速率阈值。只有存在明显更优且可 Range 续传的候选源时才发生中途切换；每次判断和切换原因记录到统一日志。

真实拉取产生的被动指标是健康判断的主要来源。主动探测仅用于启动后的快速确认、故障恢复与长期无真实流量时的低频保活，且只执行 V2、manifest 与 blob `Range: bytes=0-0` 验证；它遵守限流和资源预算，永不抢占真实拉取。

## Rate-Limited State（限流状态）

Provider 返回 `429 Too Many Requests` 时进入带恢复时间的限流状态，而非普通故障状态。Gateway 依据上游给出的重试或重置时间暂时避开该 Provider，并优先选择其他可用源；无替代源时将上游限流结果返回给 Docker 并记录事件。Provider 凭据可改善其对应上游的匿名限流，但不绕过上游自身规则。

## Provider Response Semantics（Provider 响应语义）

Resolver 对 tag 或镜像返回 `404` 是正常的未找到结果，不降低 Provider 健康分。已选定 manifest 后，Pull Provider 对某个 blob 返回 `404` 表示该 Provider 对该内容不完整或滞后：当前拉取改选其他源，但不触发全局熔断。收到 `401` 或 `403` 时，Gateway 先刷新一次该 Provider 的上游 token；仍失败则使该 Provider 进入认证失效状态、暂停选路并产生高优先级事件，直至凭据重载或后续探测恢复。

## Integrity Violation（完整性违规）

Gateway 按选定的 content digest 验证 manifest 和 blob。流式 blob 传输在完成前无法得到最终 digest；若最终校验不匹配，Gateway 立即中断下游响应、记录高优先级事件并隔离问题 Provider，使 Docker 将该层视为失败后重试。Gateway 不以缓存整个 layer 的方式修复已输出的错误字节；分片重叠校验只用于更早发现异常，不能替代最终 digest 校验。

## Pull Failure Semantics（拉取失败语义）

在下游响应开始前，Gateway 使用 OCI Registry 标准错误形式区分失败原因：全部 Resolver 返回 `404` 才表示镜像或 manifest 不存在；Resolver 冲突且策略为失败、所有 Provider 暂时不可用、认证失效或限流都表示临时不可用，并在适用时给出重试信息。开始流式输出 blob 后无法再安全地返回 Registry 错误对象，只能关闭下游连接。
