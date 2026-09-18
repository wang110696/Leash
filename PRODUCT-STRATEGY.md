# Leash 产品与商业策略

> 本文档记录技术架构之外的产品定位、买家结构、竞争格局和商业模式判断。与 [ARCHITECTURE.md](ARCHITECTURE.md) 分开维护，避免技术讨论和商业讨论互相稀释。
>
> 结论来自第五轮外部 review（2026-09-18），是目前唯一一轮聚焦产品/商业角度的碰撞。

## 1. 原始叙事已经不成立，需要重新定位

最初的创业假设是"ZCode 上传 Git 历史"这类事件带来几个月的恐慌窗口期，"没人做 coding-agent 安全向的出口代理"是空白。2026 年 9 月这个时间点，这个假设已经站不住：

- **CrowdStrike** 于 9 月 1 日发布 Falcon Guardian，明确定位"endpoint 是 AI agent security 的 control point"，直接对标 agent runtime visibility/enforcement。
- **Zscaler** 1 月起持续投入企业 AI 安全能力，6 月扩展到 Agentic AI，9 月推出 Agentic SOC，明确覆盖 AI developer tools。
- **Netskope** 2026 报告已经把 Claude Code、Codex、MCP、agentic execution 纳入安全治理模型。

这些不是一次性事件响应，而是连续产品投入。**"我们比传统 DLP/CASB 更懂 AI agent"不是护城河，最多只有 6-18 个月的 feature lead**——这类能力随时可能变成巨头的一个 feature。

**Leash 值得做的理由必须从"没人做"换成"现有安全巨头是横向安全平台，Leash 能否成为 coding-agent runtime 的开发者原生、跨 harness、语义级控制层"。**

## 2. 真正可能的护城河：Semantic Layer，不是 MITM 本身

MITM 代理、secret 正则、Git push 检测——这些技术能力全部可以被复制，不构成壁垒。CrowdStrike 能看到 `process X → SSH → github.com:22`；Leash 需要能看到的是：

```text
Codex session #821
被要求重构 auth 模块
→ 改了 13 个文件
→ 调用 git
→ 改了 remote
→ 尝试 push
→ 目的地不在企业允许的 GitHub org 内
→ push 的 commit 里包含 .env 变更
→ BLOCK
```

区别不是 telemetry 更多，而是**知道 agent 为什么在做什么、这个动作在 agent workflow 里是什么语义**。这需要持续积累对不同 harness（Claude Code / Codex / Cursor / OpenCode / MCP / skills / sub-agents）的语义理解，长期资产应该是：

> **Agent event ontology + harness integrations + policy ecosystem + session replay format。**

如果 Leash 的事件格式未来能成为其他 agent/security 工具愿意消费的事实标准，才是真正的壁垒。否则大概率最终只是巨头产品线里的一个 feature。**只做 coding-agent 本地 DLP 可以是不错的 OSS/security 产品，但作为独立大型商业公司的 thesis 偏弱**——如果目标是做大公司，最终必须扩展成 Agent Runtime Security，而不是一直停在 coding agent firewall。

## 3. 买家结构：不是"开发者 vs CISO"的二元对立，是三角关系

| 角色 | 在 Leash 里的实际角色 |
|---|---|
| Developer | 用户，但通常不是预算方 |
| Platform / DevEx / AI Enablement / DevSecOps | **最重要的内部 champion** |
| Security Engineering / CISO | **最终经济买家和政策 owner** |

如果直接走"CISO 买单 → 强装到所有开发者电脑"，这个产品大概率会失败——不是因为企业不会强装安全软件（EDR/DLP 本来就这么部署），而是因为 **Best-effort 模式下 Leash 的安全能力本身依赖开发者配合**：开发者如果把它当成监控工具，会绕过、抵制、抱怨性能，Security 买了也很难证明价值。

第一批目标客户不应该优先找传统 CISO，而是**有几百到几千研发人员、已经大规模允许 Claude Code/Codex/Cursor 使用、同时 Security 团队开始焦虑的公司里的 AI Platform / Developer Platform + Security Engineering 联合团队**。

### 3.1 关键产品策略：监控 agent，不监控 developer

这不是营销口号，必须落成明确的数据边界（应体现在 ARCHITECTURE.md 的 capture scope 里）：

```text
记录：                          不记录：
Codex → POST evil.com          人的键盘输入
Codex → git push attacker/repo  屏幕截图
Codex → exec gh gist create     鼠标活动
                                Slack/邮件内容
                                工作时长
                                "开发者效率评分"
```

Dashboard 默认应该叫 **"Agent Activity"**，不是 "User Activity"，且开发者本人能看到与 Security 团队同一份审计记录——目标是做一个"Developer 和 Security 一起看 Agent"的工具，而不是"Security 看 Developer"的工具。做到这一点，产品的心理模型更接近 Little Snitch / Falco / Wireshark，而不是 Teramind / ActivTrak 这类员工监控软件；员工对 productivity surveillance 的信任侵蚀是有据可查的风险，开发者群体对此尤其敏感。

## 4. 商业模式：Open Core

| 模式 | 判断 |
|---|---|
| 纯闭源 | 不推荐——对一个要求用户装 CA、代理所有 HTTPS 流量、审查源码和 Git 的新公司，信任门槛太高 |
| 纯 OSS + 咨询支持 | 不推荐作为主要商业模型 |
| **Open Core** | **推荐**——有可信先例：GitLab（open-core，收入主要来自付费订阅）、Sysdig（开源 Falco 建立 runtime security 社区，商业平台在其上销售，Falco 已是 CNCF graduated 项目）、Aqua（开源 Trivy 作为 adoption wedge，商业 CNAPP 变现）、Semgrep（免费能力做 adoption wedge，Teams/Enterprise 收费） |

切分建议：

```text
Leash OSS                          Leash Enterprise
────────────────                       ────────────────────
Best-effort Mode                       Enforced Mode
本地 MITM                              macOS/Linux/Windows 特权 provider
Git 审计（shim）                       Fleet management / 集中策略分发
本地 SQLite                            RBAC / SSO
单开发者时间线                          MDM 部署
基础规则                                Policy signing
CLI                                    SIEM 集成
本地 Dashboard                          中心化审计 / Trusted Evidence
                                        合规报告
                                        企业规则包
                                        支持/SLA
```

**本地部署不等于没有持续收入**：可以做到 data plane（事件数据）永远留在开发者本机/企业自己的存储，control plane（license、policy metadata、fleet health、版本更新）走年度订阅——GitLab/Elastic 等大量安全和基础设施产品都是这个模式，"最敏感的数据永远不出本地"反而可以是 selling point。

Open source core 的另一个价值是 bottom-up 分发：`brew install leash && leash run -- codex` 这种安装路径，加上开源社区贡献检测规则/harness 集成，是大厂最难直接复制的分发渠道。

## 5. 市场时机：事件窗口短，品类窗口长

"HN 头条热度只有几个月，所以必须几个月内卖出去"是错误的紧迫感来源。单条新闻的热度可能只持续几天到几周，但企业安全预算的采购流程（安全评审、PoC、法务、隐私、端点测试、采购、部署）通常需要几个月到一年以上，不会按新闻热度的节奏走。

更值得参考的是巨头连续的产品投入节奏（Zscaler 从 2026 年 1 月到 9 月持续加码，CrowdStrike 9 月才发布），这说明市场处在：

```text
2025–2026   企业意识到问题
2026–2027   品类定义 / vendor selection / 架构形成
2027+       整合 / 大厂开始吃掉零散 feature
```

**结论：8-12 天的 v0.1 MVP 完全不会把窗口耗光，再花一个月验证也不是核心风险。真正危险的是反过来——花 6 个月做 Enforced Mode / Windows driver / 企业合规能力，然后才第一次接触真实用户。** 现在把 MVP 压到两周左右反而是对的节奏。

## 6. 现阶段要验证的唯一问题

不是"能不能融资"或"能不能和 CrowdStrike/Zscaler 正面竞争"（现在的 thesis 还不足以支撑这两件事），而是一个具体到可以现场演示的问题：

> 开发者和 Security 团队同时看到一条
> `Codex tried to push these 6 commits to this unknown repository → Leash blocked it`
> 会不会都觉得"这个东西我想装"？

如果答案是 yes，才有下一步 wedge 可言。v0.1 demo（见 [ARCHITECTURE.md](ARCHITECTURE.md) 第 0 节）就是为了拿到这个问题的答案，不是为了做出一个完整产品。
