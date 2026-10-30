---
name: sqli-scan
description: 在已获授权的目标上做 SQL 注入检测与交付型报告（JSON/HTML/Markdown/SARIF），并可复测既有发现。当用户给出具体目标、声明已获授权、要求在授权范围内测 SQL 注入或为 CI 出报告时使用；不用于目标发现、批量探测或未授权扫描。
---

# SQL 注入检测（仅授权范围）

本技能把一个**检测引擎**接到对话里。它擅长的是：在**用户明确给出的目标**上跑完 9 条注入通道、
给出每条发现的 PoC 与受影响参数、把结论落成可进 CI 的报告。它不擅长也不做目标发现。

## 什么时候用，什么时候拒绝

用：

- 用户给出**具体目标**（一个 URL、一个请求文件、一个主机），并声明自己已获授权测试；
- 用户要复测某个参数/某条既有发现，或要一份能贴进工单/CI 的报告。

拒绝（直接说明原因，不要绕）：

- 「帮我找一些有注入的站」「扫一下这个网段」「批量测一批域名」——**只扫用户明确给出的目标**，
  不做目标发现，也不接搜索引擎/批量清单来源；
- 用户没有给出授权声明时，先问清楚授权范围与目标清单，再决定是否开扫。

## 推荐流程

1. **`preflight`** —— 零 payload 侦察：可达性 + 注入点发现 + 覆盖缺口（哪些面按当前配置没测）。
   先跑它，既能省请求，也能提前暴露「这个目标压根没参数」这类结论不成立的场景。
2. **`run_scan`** —— 异步启动，返回 `scanId`。高危 payload 池（`risk: 3`）**必须由用户本人同意**，
   你在工具调用里传 `confirmDestructive: true` 前要先问一句；不得替用户代开。
3. **`get_scan_status`** —— 轮询进度；长扫描不要阻塞式等待。
4. **`get_findings`** —— 取结论：CWE/CVSS、受影响参数、PoC curl，以及 `verdictNote` 与 `nextSteps`。
5. **`get_report`** —— 需要交付物时取 `json | markdown | html | csv | sarif | db-json`。
6. 需要收尾/让路：**`stop_scan`** / **`pause_scan`** / **`resume_scan`**；要列历史：**`list_scans`**。

## 9 个工具（与 `server/src/mcp/tools.js` 同源，名字不可改写）

| 工具 | 用途 |
|---|---|
| `preflight` | 零 payload 侦察：可达性 + 注入点 + 覆盖缺口 |
| `run_scan` | 启动扫描（异步，返回 scanId） |
| `get_scan_status` | 进度与阶段 |
| `get_findings` | 结论 + PoC + `nextSteps` |
| `get_report` | 导出 json/markdown/html/csv/sarif/db-json |
| `list_scans` | 历史扫描 |
| `stop_scan` / `pause_scan` / `resume_scan` | 收尾 / 让路 / 续跑 |

## 三条硬口径（引用任何结论时必须一起说）

1. **`verdict` = `inconclusive` / `session_expired` ≠ 「没有注入」。** 这表示会话失效、签名被拒、
   或请求被守卫拦下——是**没测成**，不是「测了没洞」。修认证（cookie / auth / refresh-url）后再扫。
2. **`unverifiedSurfaces` 不是「干净」。** 它列出**没能完成有效检测**的注入面（如「HTTP 请求头 2/2」），
   `uncoveredSurfaces` 列出**按当前配置压根没测**的面。引用阴性结论时必须同时声明它们；
   否则就是把「没测」说成了「没洞」。
3. **`risk: 3` 与利用面是两道门，代理不得代答。** 高危 payload 池需要用户同意后传
   `confirmDestructive: true`；利用面（SQL shell / 文件读写 / OS 命令）还需要服务端
   `EXPLOIT_ENABLED=1` 且请求带 `authorized: true`。**不要为了「跑通」自己补这两个开关。**

## 交代结论的模板

> 在 `<目标>`（授权范围：`<scope>`）上跑了 `<技术集合>`：`<N>` 条发现（`<等级分布>`），
> 其中 `unverifiedSurfaces`：`<列出>`，`uncoveredSurfaces`：`<列出>`。
> 结论可信度：`<verdict>`；不可信的原因：`<verdictNote>`（若有）。

## 常见错（都是本仓栽过的形态）

- 把 `vulns: []` 直接说成「这个站没有注入」——先看 `verdict` 与两个 surfaces 字段；
- 只测了 query 就说「全面检测」——默认覆盖 query + body，header/cookie/path 需要显式开关；
- 「报告里没写漏洞就算通过」——`manifest.json` 的 `gate` 与 `diff` 才是 CI 判红口径；
- 为了省事把 `--level`/`--risk` 拉满跑生产环境——高危池会产生写库/时延副作用，先确认授权。

## 边界

- 本技能不做目标发现、不做扫描器之间的编排、不替用户判断授权是否成立；
- 内网/回环目标默认被 SSRF 防护拒绝，属特性；需要时由用户自己在服务端设 `SSRF_ALLOW_PRIVATE=1`；
- 检测结论的完整边界见仓库 `AGENTS.md` §0 与 `docs/user-guide.md`。
