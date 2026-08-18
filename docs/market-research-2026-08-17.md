# docker-registry-gateway 市场与立项调研

> 调研日期：2026-08-17  
> 范围：面向个人、小团队和共用服务器的 OCI/Docker 镜像拉取可靠性。资料优先采用 Docker、CNCF/OCI、上游项目和厂商的官方文档。  
> 仓库状态说明：调研时工作区没有可读取的产品源码、既有 `docs/` 约定或 Git 仓库；因此以下产品定义来自关联会话，结论应在首批真实用户试点后复核。

## 结论摘要

**不建议现在从零开发新产品。先用 Zot v2.1.18 做基线 PoC；只有它在真实试点中无法满足“动态健康路由与可解释运维”时，才值得做一个很窄的扩展或独立网关。**

真正的缺口不是“Docker 改镜像源必须重启”，也不是“再造一个缓存 Registry”：

- 现代 Docker Engine 已将 `registry-mirrors` 列为可通过 Linux `SIGHUP` 热重载的运行中配置；把“免重启改镜像源”当作核心卖点是错误前提。 [Docker `dockerd` 配置热重载](https://docs.docker.com/reference/cli/dockerd/#configuration-reload-behavior)
- `registry-mirrors`/官方 pull-through cache 的适用面仍是 Docker Hub；Docker 官方文档明确说不能镜像另一个私有 Registry。 [Docker Hub mirror 文档](https://docs.docker.com/docker-hub/image-library/mirror/)
- 对纯 containerd/CRI/Kubernetes 用户，`hosts.toml` 已支持多个 host 按配置顺序尝试、全部失败后回退上游，且该目录更新无需重启 containerd。因此这部分不是本项目的首要市场。 [containerd Registry hosts 配置](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
- **Zot 已直接覆盖最接近的轻量需求**：它能按需 pull-through cache、一个逻辑 upstream 配多个 URL，主 URL 失败会按列表尝试下一个 URL；还能镜像多个上游 Registry。 [Zot v2.1.18 mirroring](https://zotregistry.dev/v2.1.18/articles/mirroring/)

现在唯一值得验证的细分需求是：**Zot 的静态 URL 顺序回退和重试仍不足以解决、且仍以 Docker Engine/普通 `docker pull` 为主的团队**。例如他们需要把若干经组织批准的同源端点做持续健康判定、熔断/半开恢复、延迟策略、实时变更与失败归因。这个范围还没有市场规模证据；它不是“找最快公网镜像”，而是受信任上游集的 Registry 可靠性控制面。

建议定位为：

> **Zot 之上的 Registry Reliability Control Plane（若 PoC 证明确有缺口）**  
> 对已批准、可证明内容等价的上游，提供拉取路由、缓存、可观测性和受控故障切换。

不建议定位为“所有 Docker 镜像源智能负载均衡器”：标签可变、身份认证、CDN 重定向和来源信任使这个承诺既不安全也不稳定。

## 先纠正关联会话中的关键前提

| 原判断 | 官方证据后的结论 | 对立项的影响 |
| --- | --- | --- |
| 改 `registry-mirrors` 必须重启 dockerd，Docker 没有 reload | 不准确。Docker 当前文档列出 Linux `SIGHUP` 热重载能力，并明确包含 `registry-mirrors`。若同一选项同时由启动 flag 指定，冲突时重配会失败。 [Docker 文档](https://docs.docker.com/reference/cli/dockerd/#configuration-reload-behavior) | “动态修改单个 Docker Hub mirror、避免重启”不构成独立购买理由。产品最多提供更好的控制面，而不是填补热更新空白。 |
| Docker 不支持失败切换 | 不准确（限 Docker Hub mirror 范围）。Moby `LookupPullEndpoints` 的公开 API 文档说明它会生成“按优先级尝试”的 v2 endpoint 列表，并优先 mirror、再实际 Registry、HTTPS 优先于 HTTP。 [Moby registry API](https://pkg.go.dev/github.com/Moby/moby/registry#Service.LookupPullEndpoints) | 已有的是静态 endpoint 顺序和出错后尝试下一端点，不能把它描述成没有 fallback；它没有承诺持续健康评分、时延重排、熔断/半开或按上游质量负载均衡。 |
| `registry:2` 可以解决多源路由 | 不准确。Distribution 的 `proxy` 配置以一个必填 `remoteurl` 定义 pull-through cache；它的任务是缓存一个上游，不是健康检查或多源调度。 [Distribution 配置参考](https://distribution.github.io/distribution/about/configuration/#proxy) | 仍有产品缺口，但只在多上游路由、策略与观测，而非普通缓存。 |
| Docker、containerd 都缺少 mirror/fallback | 不准确。containerd 的 `hosts.toml` 可按 host 声明顺序尝试，并回退 `server`；配置文件目录更新不需重启 daemon。它还明确要求把 `resolve` 视为受信任操作，公共 mirror 不应拥有该权限。 [containerd hosts 文档](https://github.com/containerd/containerd/blob/main/docs/hosts.md) | Kubernetes/containerd 是强替代方案市场；不要以它为第一目标。 |

Moby 在 2026-06 的 [#52890](https://github.com/moby/moby/issues/52890) 记录了与本项目高度相同的问题：调用者希望保持普通 `docker pull`/`docker run`，同时使用本地 cache/proxy 和上游 fallback；该 issue 被标为 `kind/question`、已关闭且没有关联实现或里程碑。它说明需求确实出现于 Docker Engine 用户，但**不是**官方承诺、路线图或市场规模证据。

## 现有方案与真实替代边界

| 方案 | 已覆盖的能力（官方/项目一手资料） | 与本项目的差距或适用结论 |
| --- | --- | --- |
| **Zot v2.1.18（优先试用）** | 轻量 OCI Registry；`sync.registries[].urls` 可列一个或多个上游 URL，主 URL 出错依次尝试下一个；`onDemand: true` 是按需 pull-through cache。它还能镜像多个上游 Registry，并可用 `preserveDigest: true` + `http.compat: ["docker2s2"]` 保留 Docker digest/签名。 [Zot mirroring](https://zotregistry.dev/v2.1.18/articles/mirroring/)；[Docker 使用指南](https://zotregistry.dev/v2.1.18/articles/docker/) | 这是本项目当前最直接的轻量替代，已经覆盖“单入口 + 缓存 + 静态 URL fallback + 多 Registry”。所查 v2.1.18 文档把 URL 列表、`maxRetries`、`retryDelay`列为 sync 配置，但**未把**持续健康探测、时延重排、熔断/半开或上游配置管理 API 列为能力；这是文档范围观察，非对源码能力的绝对否定。先以它为基线，不要重复实现其已有能力。 |
| Docker Distribution / `registry:2` | Docker 官方的 pull-through cache：首拉从上游取回并本地存储，后续从本地提供；官方示例要求 `proxy.remoteurl`。 [Docker](https://docs.docker.com/docker-hub/image-library/mirror/)；[Distribution](https://distribution.github.io/distribution/about/configuration/#proxy) | 最适合“只有 Docker Hub、主要追求复用缓存”。公开配置不是多上游健康路由。 |
| Docker Engine `registry-mirrors` | Docker Hub mirror 列表；现在可热重载。Moby 的 Registry API 说明 pull endpoint 会按静态优先级尝试并偏好 mirror。 [Docker](https://docs.docker.com/reference/cli/dockerd/#configuration-reload-behavior)；[Moby](https://pkg.go.dev/github.com/Moby/moby/registry#Service.LookupPullEndpoints) | 不应再声称 Docker “没有失败切换”；现有能力是 Docker Hub 范围内的静态、有错才切换。Zot 文档称 Docker Engine 25+ 启用 containerd image store 时可从 `/etc/docker/certs.d/hosts.toml` 读取多 Registry mirror 配置；而 Moby #52890 的 external-containerd 场景仍提出不使用该配置的疑问。两者覆盖的运行拓扑未在本次查到的 Docker 官方文档中统一说明，必须用目标 Engine 版本实测，不能把它当作产品立项前提。 [Zot Docker 文档](https://zotregistry.dev/v2.1.18/articles/docker/)；[Moby #52890](https://github.com/moby/moby/issues/52890) |
| containerd 原生配置 | 多个 host 先按顺序尝试、再 fallback；可为不同 Registry 配置；文件更新无需重启。 [containerd](https://github.com/containerd/containerd/blob/main/docs/hosts.md) | 对 CRI/`ctr`/containerd image clients，应直接用原生机制。它提供有序 fallback，不等价于基于实时时延的调度或跨端缓存控制面。 |
| Harbor Proxy Cache | Proxy cache project 连接一个配置的 registry endpoint；miss 时回源，已缓存内容在目标端点不可达时仍可服务；处理上游 `WWW-Authenticate` challenge。 [Harbor](https://goharbor.io/docs/main/administration/configure-proxy-cache/) | 是团队 Registry、RBAC、扫描、审计需求的成熟方案。其公开 proxy-cache 模型是“项目—目标 endpoint”，不是同一命名空间下多个公网镜像源的智能选择。 |
| Sonatype Nexus Repository | 可代理 Docker Hub；group repository 将多个 repository 合成一个 endpoint，并提供 path/subdomain/reverse-proxy 路由。 [Nexus](https://help.sonatype.com/en/docker-registry.html) | 已经覆盖“企业制品库 + 聚合”。用户若已有 Nexus，应先通过 repository group 试验，避免再引入一个网关。公开资料没有把它表述为低延迟探测、熔断式 mirror router。 |
| JFrog Artifactory | Docker local/remote/virtual repository；remote 是按需缓存代理，virtual 可聚合多个 local/remote。 [Docker repositories](https://docs.jfrog.com/artifactory/docs/docker-repositories)；[Remote repositories](https://docs.jfrog.com/artifactory/docs/remote-repositories) | 与 Nexus 同类：能力宽、适合已采购制品平台。若需要的是轻量 Compose 部署和面向不稳定网络的路由，其运维/采购边界不同；这是假设，需访谈验证。 |
| GitLab Dependency Proxy | 按 group 的 Docker Hub cache，缓存 manifest 和 blobs，并用 HEAD 检查 tag manifest 是否过期。 [GitLab](https://docs.gitlab.com/user/packages/dependency_proxy/) | GitLab CI 用户的好替代，问题仍是缓存 Docker Hub，而非多镜像端点调度。 |
| `rpardini/docker-registry-proxy` | 已是相当接近的轻量开源替代：缓存任意 Registry、集中管理认证；其方式是 HTTPS MITM，需要在各客户端信任自建根证书。 [项目 Docker Hub 页面](https://hub.docker.com/r/rpardini/docker-registry-proxy) | 不能简单声称“市场空白”。若目标只是多 Registry 缓存/认证，应直接评估它。MITM CA 分发与凭据集中化也说明透明代理的安全和运维成本很高。 |
| Spegel / Dragonfly 类集群分发 | Spegel 让 Kubernetes 节点互作本地 Registry mirror，peer 未命中会 fallback 上游；其官方文档明确“目前仅 containerd”。 [Spegel](https://spegel.dev/docs/)；[兼容性](https://spegel.dev/docs/getting-started/) | 是“大量节点重复拉取”的 P2P 分发替代，不是 Docker Engine 共用服务器的多公网源路由器。 |

**调研结论：并非没有类似产品，而是市场被分成三层。**

1. 缓存/制品管理层已很成熟：Distribution、Harbor、Nexus、Artifactory、GitLab。
2. runtime 配置层对 containerd 已较成熟：原生 ordered mirror/fallback。
3. Zot 已覆盖“轻量、非 MITM、多个 URL 的静态 fallback、按需缓存”。若仍有缺口，只能是其公开资料未列出的组合：**主动健康/熔断、策略性时延选择、上游热变更、按请求的路由可解释性**。这不是已证实市场空白，而是待用 Zot PoC 验证的候选差异点。

## 目标用户、需求与不做的用户

### 最值得访谈的三类

1. **国内或受限网络中的共用 Docker Engine 服务器**：CI runner、测试机、GPU/AI 训练机、内网部署机；先由平台管理员用 Zot 统一维护静态上游策略，业务人员仍用 `docker pull`。
2. **尚未采购 Harbor/Nexus/Artifactory 的 3–30 人团队**：痛点是某些允许的 Registry endpoint 间歇性失败、回源慢、重复下载和缺乏失败证据，而不是仓库 RBAC/漏洞扫描。
3. **需要可审计网络行为的运维团队**：要看到“哪个端点因 429、TLS、认证、超时或 5xx 被降级”，并能人工禁用，而不是让客户端随机重试。

### 不应优先服务

- 单机或仅 Docker Hub 且只需缓存：先用官方 pull-through cache 或 Zot。
- Kubernetes/containerd 为主：先用 `hosts.toml`；大集群先评估 Spegel/Dragonfly。
- 已运行 Harbor/Nexus/Artifactory：先验证现有 proxy/group/virtual repository 能否满足。
- 需要代理私有 Registry 凭据、push、镜像改写、扫描、签名治理：这会迅速变成完整 artifact platform，超出轻量网关边界。

## 为什么“多源负载均衡”比看上去难

Registry HTTP API 不是无状态文件下载。下面限制来自 OCI Distribution 规范与已在生产产品中出现的行为：

| 风险 | 规范/产品证据 | MVP 必须采取的约束 |
| --- | --- | --- |
| 标签不是不可变版本 | tag 指向的 manifest 会变化；GitLab 和 Harbor 都会以 HEAD/manifest 逻辑判断缓存是否过期。 [GitLab](https://docs.gitlab.com/user/packages/dependency_proxy/)；[Harbor](https://goharbor.io/docs/main/administration/configure-proxy-cache/) | **先由一个受信任 resolve 源取得 manifest digest**，再把同一 pull 会话钉到该 digest；不要让不同镜像源各自解析 `latest` 后混用。生产建议使用 digest 引用。 |
| Blob 允许断点续传，且须匹配 digest | OCI 规定 blob 应支持 `Range`；成功响应的 `Docker-Content-Digest` 必须匹配响应体，client 应校验。 [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) | 不能在一个已向 client 输出字节的连接中任意换源。只有新请求或严谨处理 `Range`/`Content-Range`、大小和最终 digest 后才可恢复；最佳第一版是网关完整转发/缓存后再服务。 |
| Registry/CDN 可以重定向 | 规范允许任何 Registry 请求重定向，并要求跨 host 不转发 `Authorization`。 [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) | 网关需选择“自己跟随并代理 3xx”或“安全地透传 Location”；前者保持路由/指标但要处理 CDN，后者会让 client 绕过网关，不能宣称 blob failover。 |
| Bearer token 和 credential 泄漏 | Harbor 明确提示 token realm 可与 registry host 不同；OCI 规定上游凭据不应未授权发送给 proxy。 [Harbor](https://goharbor.io/docs/main/administration/configure-proxy-cache/)；[OCI](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) | v0.1 仅支持匿名公共源，或每个上游单独配置最小权限 service credential，绝不把 client 的 `Authorization` 广播到备选源。 |
| 公共 mirror 不应决定“tag 是什么” | containerd 明确说明 `resolve` 是信任操作，公共 mirror 不应有 resolve 权限。 [containerd](https://github.com/containerd/containerd/blob/main/docs/hosts.md) | 把路由分成 **trusted resolver** 与 **blob provider**；health probe 不能只看 `/v2/` 200，401 challenge、429、限速、目标 repo HEAD 都要分级记录。 |

因此，“先请求 manifest 失败就换源、blob 下载失败随便续传”的几百行 demo 不足以上生产。它可能下载到不同 tag 的层、泄露 token，或在 CDN redirect 后失去控制面。

## 先验证 Zot，再决定是否需要差异化 MVP

第一阶段不写新 Gateway：用 Zot 的 on-demand sync 配置至少两个经授权、可确认内容等价的 URL，显式打开 `preserveDigest: true` 与 `http.compat: ["docker2s2"]`，并跑下述验收指标。Zot 官方特别说明若默认把 Docker-format manifest 转换为 OCI，manifest digest 会变化，digest-pinned pull 和签名验证会失效；这正是 PoC 必须验证的兼容性条件。 [Zot mirroring](https://zotregistry.dev/v2.1.18/articles/mirroring/)

只有同时满足下列条件才进入第二阶段：

1. URL 顺序 fallback/retry 在实际故障里仍不能达到可接受恢复时间；
2. 需要的健康、熔断、动态策略无法通过 Zot 配置、监控或外围 load balancer 安全实现；
3. 受访团队愿意为这组能力长期维护或付费；
4. 保持 digest/签名、认证、Range/redirect 兼容的回归矩阵能够通过。

### 第二阶段的产品边界（仅在上述条件成立时）

### 产品边界

- **只读 pull gateway**，先不做 push、删除、跨 Registry 重写、UI、用户级凭据代理和公开镜像列表。
- 首先支持 Docker Hub 兼容请求，或要求客户端显式使用网关命名空间，例如 `gateway.example/docker.io/library/alpine:3.20`；后者比 DNS 劫持或 HTTPS MITM 更安全、可解释。
- 上游必须由管理员配置，并按“同一可信来源的不同可达端点”分组；不承诺把任意第三方 mirror 视为内容等价。
- 策略为 **优先级 + 熔断 + 有界探测**，而不是每次按瞬时 latency 轮询。观察端点：DNS、TCP/TLS、`/v2/` challenge、目标 manifest HEAD/GET、429/5xx、首字节和完整 blob 成功率。
- 缓存 manifest 与 blob，key 至少包含 registry、repository、manifest digest、平台/`Accept` 协商结果；tag 的短 TTL 与 digest 的长缓存要分离。

### 最小验收指标

在 3 个真实试点各跑两周，与未使用网关的对照期比较：

- 非缓存镜像拉取的成功率与 p95 完成时间；
- 首个 manifest 成功率、blob 中途失败率、429/鉴权/TLS/超时的分类；
- 某端点连续故障时的恢复时间、是否错误切到不等价内容；
- cache hit 率和实际回源流量；
- 管理员能否在不改变业务镜像引用的情况下禁用端点并解释一次失败。

若无法把“失败率下降、诊断时间下降、缓存节省流量”量化，不应继续扩展 Web UI、P2P、扫描或商业化。

### 先做兼容性 spike，再写正式功能

测试每个计划支持的上游，保存可复现 HTTP trace，并覆盖：匿名/私有的 `401 WWW-Authenticate`、多架构 manifest 的 `Accept` 协商、tag 变更、blob `206 Range`、307/302 CDN redirect、429、连接首字节前失败与中断后的恢复。以 OCI 的 [conformance tooling](https://github.com/opencontainers/distribution-spec) 为基础补上网关路由场景。

## 最终立项建议

| 决策 | 建议 | 原因 |
| --- | --- | --- |
| 现在就做通用平台 | **否** | 缓存与制品管理替代品已经密集，Zot 还已提供多 URL 的 on-demand cache/fallback；协议和安全边界很容易超过小工具的维护能力。 |
| 做 2–4 周的受限技术验证 | **是，但以 Zot 为实现基线** | 验证 Docker Engine 共用服务器的真实可靠性收益及 Zot 的静态 fallback 边界，而不是先写 proxy。关联 Moby issue 也显示真实用户想保留 `docker pull` 工作流。 |
| 开源轻量产品 | **仅在 Zot 明确不足后有条件地是** | 前提是 3 个试点都能证明 Zot、Distribution、Harbor、Nexus/containerd 不能以更低成本满足，且 gateway 不需要 MITM 或托管用户私有凭据。 |
| 商业化/大规模推广 | **暂缓** | 本次调研没有找到可靠的一手市场规模、付费意愿或国内镜像端点长期 SLA 数据；这些必须通过用户访谈、试点留存和运维成本验证。 |

如果继续，README 的准确承诺应是：

> A policy-controlled, observable reliability layer for approved OCI registry endpoints — complementing, not duplicating Zot's pull-through cache and ordered fallback.

这会把产品从“脆弱的公网加速器”限定为“团队可控的镜像拉取可靠性层”，也与 OCI/containerd 对来源信任的要求一致。

## 一手来源索引

1. [Docker Engine: configuration reload behavior](https://docs.docker.com/reference/cli/dockerd/#configuration-reload-behavior)
2. [Docker: Mirror the Docker Hub library](https://docs.docker.com/docker-hub/image-library/mirror/)
3. [CNCF Distribution: proxy configuration](https://distribution.github.io/distribution/about/configuration/#proxy)
4. [containerd: Registry Configuration / hosts.toml](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
5. [Moby #52890: local registry proxy/cache and fallback to upstream](https://github.com/moby/moby/issues/52890)
6. [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
7. [Harbor: Configure Proxy Cache](https://goharbor.io/docs/main/administration/configure-proxy-cache/)
8. [Sonatype Nexus: Docker Registry](https://help.sonatype.com/en/docker-registry.html)
9. [JFrog Artifactory: Docker Repositories](https://docs.jfrog.com/artifactory/docs/docker-repositories)
10. [GitLab: Dependency proxy for container images](https://docs.gitlab.com/user/packages/dependency_proxy/)
11. [rpardini/docker-registry-proxy project page](https://hub.docker.com/r/rpardini/docker-registry-proxy)
12. [Spegel documentation](https://spegel.dev/docs/)
13. [Zot v2.1.18: OCI Registry Mirroring](https://zotregistry.dev/v2.1.18/articles/mirroring/)
14. [Zot v2.1.18: Using Docker with zot](https://zotregistry.dev/v2.1.18/articles/docker/)
15. [Moby Registry `LookupPullEndpoints` API](https://pkg.go.dev/github.com/Moby/moby/registry#Service.LookupPullEndpoints)
