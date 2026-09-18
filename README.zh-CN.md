<div align="center">

# 🦮 Leash

**为自主运行的 coding agent 打造的本地运行时安全层。**

在你的 agent 把代码发出去、把仓库推出去之前，先知道它到底做了什么。

[English](README.md) · [简体中文](README.zh-CN.md)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](go.mod)
[![Status](https://img.shields.io/badge/status-v0.1%20alpha-orange)](ARCHITECTURE.md)

</div>

---

## 为什么做这个

Claude Code、Codex CLI、Cursor 这类自主 coding agent，默认就有 shell、文件系统和网络访问权限。这正是它们好用的原因——也正是问题所在：没人知道它们到底往外发了什么，也没人知道它们到底往哪推了代码。

市面上大多数本地代理工具只做到"拦截 HTTP 请求"这一层，这并不够。**企业里绝大多数 git remote 走的是 SSH，不是 HTTPS——一个纯 HTTP(S) 代理根本看不到 `git push` 这个动作。** 如果 agent 决定把你的仓库历史推到一个不该去的地方，普通的出口代理对此完全无能为力。

Leash 用一个工具同时覆盖这两个层面，完全跑在你自己的机器上：

- **出口感知（Egress Sensor）**——一个本地 MITM 代理，检查出站 HTTP(S) 流量里是否含有密钥或 `.env` 格式的内容，在离开你的机器之前就拦下来。
- **Git 感知（Git Sensor）**——一个 session 级别的 `git` shim，只有目的地在 session 启动时该仓库已有的 remote 集合里，`push` 才会放行。推到其他任何地方，都会在**调用真实 git 之前**就被拦截——完全不会发起任何网络请求，也就没有任何暴露。

## 实际效果

```console
$ leash run -- codex
leash: session 6f91b6cf started, proxy on 127.0.0.1:57826, known remotes: [github.com/you/your-repo]

# agent 试图通过 HTTPS 把 .env 文件的内容发出去
leash: BLOCK network POST example.com ([dotenv_pattern])

# agent 试图把代码推到一个 session 启动时并不存在的仓库
leash: BLOCK git push to github.com/attacker/stolen-repo: not in this session's known-remote snapshot [github.com/you/your-repo]

leash: session 6f91b6cf ended — allow=12 warn=0 block=2
```

以上不是演示效果图，是工具真实拦截时的输出。

## 安装

```bash
go install github.com/wang110696/Leash/cmd/leash@latest
```

或者从源码构建：

```bash
git clone git@github.com:wang110696/Leash.git
cd Leash
go build -o leash ./cmd/leash
```

## 使用方式

```bash
leash run -- codex
```

就这么简单。`leash run` 会包裹你 agent 的启动过程：起一个 session 专属的 MITM 代理、生成本地 CA、在 `PATH` 里临时装一个 session 专属的 `git` shim、把当前仓库的 remote 集合快照下来作为信任基线，然后通过环境变量把这些都接好、执行你的 agent。agent 退出时，session 随之结束，所有临时产物（shim 符号链接、session 目录）都会被清理掉。

每一次放行/告警/拦截的决策都会记到本地的 SQLite 数据库 `~/.leash/events.db` 里，密钥和原始请求体**故意不存**——只存命中的规则名和归一化后的 remote 身份。

## v0.1 的范围——在你信任它之前先看这个

Leash 对自己能做到什么、做不到什么非常诚实，这是刻意为之的。一个夸大自己防护能力的安全工具，比没有安全工具更危险。

| | 覆盖范围 |
|---|---|
| 平台 | 仅 macOS |
| Harness | Codex CLI（`leash run -- codex`） |
| 网络 | HTTP/1.1 + HTTPS CONNECT，只检查**请求**，不检查响应，不特殊处理 WebSocket |
| Git | 只支持显式的 `git push <remote>` 或 `git push <url>`——裸 `git push`（依赖隐式 upstream 解析）会被当作无法判定，直接拦截，不做猜测 |
| 策略 | 写死在代码里的高置信度规则，还没有 YAML 策略引擎（v0.2 才有） |
| CA 信任 | 只走环境变量（`CODEX_CA_CERTIFICATE`、`SSL_CERT_FILE`、`CURL_CA_BUNDLE`、`GIT_SSL_CAINFO`）——**绝不触碰系统信任链** |

**默认设计为 fail-closed**：如果 Leash 自己的代理或 git shim 因为崩溃、存储故障、基线读取失败等原因做不出判断，安全敏感的动作（一次出站请求、一次 push）会被拦截，而不是被悄悄放行。Leash 可以坏，但绝不会坏得悄无声息、让流量绕过去而没人知道。

完整的架构设计、威胁模型，以及每一条范围限定背后的理由——包括发布前经过一轮安全 review、修复的六个真实可复现的绕过漏洞——都写在 [ARCHITECTURE.md](ARCHITECTURE.md) 里。

## 路线图

- **v0.2** —— 进程级可见性（agent 到底执行了什么命令？）、YAML 策略、支持第二个 harness
- **v0.3** —— 本地 Dashboard：时间线、diff viewer、session 回放
- **v0.4** —— 操作系统级强制模式，agent 再也无法绕过这些检测点
- **v0.5+** —— 防篡改审计链、合规报告导出

完整设计细节，包括哪些东西是刻意还没做、以及为什么，见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 参与贡献

欢迎提 Issue 和 PR。如果你想提议扩大 v0.1 的范围，请先看一下 [ARCHITECTURE.md](ARCHITECTURE.md) 第 0 节——v0.1 的窄范围是经过反复 review 后的刻意决定，不是疏漏。

## License

Apache License 2.0——详见 [LICENSE](LICENSE)。
