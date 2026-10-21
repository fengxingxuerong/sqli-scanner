# AGENTS.md —— AI 代理 / 自动化驱动指引

> 面向 AI 编码代理（Claude Code / Cursor / MCP 客户端等）与 CI 机器人的操作契约。
> 人读文档见 [README.md](README.md) 与 [docs/](docs)；本文件只写「代理该怎么安全、
> 正确地把这台扫描器跑起来」，与 README 同源核对（改 CLI 面 必须同步本文件）。

## 0. 授权红线（先读这个）

- 本工具是**授权渗透测试**用途。代理代人操作时，**只能扫用户明确给出的目标**；
  内网/回环目标默认被 SSRF 防护拒绝（`SSRF_ALLOW_PRIVATE=1` 才放行），这是特性不是故障。
- `--risk 3`（高危 payload 池）需要显式 `--confirm-destructive`；利用面（SQL shell /
  文件读写 / OS shell）需要服务端 `EXPLOIT_ENABLED=1` 且请求带 `authorized: true`。
  不要替用户「顺手」解锁这两道门。
- 扫描结论进报告前，先看 `summary.verdict`：`inconclusive`（会话失效/签名被拒等）**
  不等于**「未检出」，不要向上游汇报成"没有漏洞"。

## 1. 两种驱动方式

### 1.1 CLI（子进程，推荐）

```bash
node server/bin/cli.js --help          # 全部开关；README 的 API/参数表由 npm run readme:check 双向核对
node scripts/one-click-scan.mjs -u "http://target/page?id=1"   # 一条命令出全套报告
```

- **退出码即门禁**：`0` 未发现高危 / `2` 发现 Critical 或 High / `1` 执行失败。CI 里直接判码，
  不要去 parse stdout。
- 产出固定在 `reports/<主机名>-<时间戳>/`（`manifest.json` 是机器可读清单，先读它再读 report.json）。
- **配置档案**：`--config <file.json>` 预载参数（键=长参数名去前导 `--`，如 `{"level":5}`），
  `--save-config <file>` 把本次非默认参数写回。argv > 档案 > 内置默认；档案含未知键会**拒绝启动**。
- **定向复测**：`-p <param>` 只测指定参数、`--param-filter body` 只测某位置、
  `--param-exclude <regex>` 排除噪声参数（[D41] 对标 sqlmap）。筛选把点位删光时报错退出——
  这说明参数写错了，不是目标没洞。
- 代理超时预算紧张时：`--retries 1 --http-timeout 5000 --timeout <整场上限毫秒>` 收敛等待；
  `--skip-static` 与 `--smart` 可显著省请求（语义见 help）。

### 1.2 REST API（长扫描 / 面板形态）

服务：`npm run server`（默认 `http://127.0.0.1:4567`，非回环监听强制 `SCAN_API_TOKEN`）。
端点全集见 README「后端 API」表（与代码双向核对）。代理走 REST 的最小闭环：

1. `POST /api/scan/start`（config 白名单外的键会被丢弃并告警——看响应里 dropped 提示）
2. `GET /api/scan/:id/events`（SSE；EventSource 不能带 header，token 走 query）
3. `GET /api/scan/:id/report` / `GET /api/scan/:id/report/export?format=json|html|markdown|sarif|csv`
4. 异常路径：`POST /api/scan/:id/stop | pause | resume`；单点复测 `POST /api/scan/:id/point/:pointId/retest`

## 2. 结果判读（代理最容易读错的三件事）

| 现象 | 正确判读 |
|---|---|
| `vulns: []` 且 verdict=`no_vulnerability_detected` | 引擎按配置跑完且无命中。若你没配认证（`--auth`/`--cookie`/`--refresh-url`），先补认证再下结论。**⚠ 还要看 `summary.unverifiedSurfaces`**：目标整体健康 ≠ 每个注入面都测过（见下行） |
| 报告存在 `summary.unverifiedSurfaces` / `summary.unverifiedSentence` | **[D123]** 有注入点**没能完成有效检测**（被 WAF/守卫拦、或网络层失败），且已按注入面摊开（如「HTTP 请求头 2/2」）。这些点的「未检出」是**没测成**，不是「测了没洞」——引用阴性结论时必须同时声明它们是未验证面，且 `verdictNote` 已带有该提示 |
| 报告存在 `summary.uncoveredSurfaces` / `summary.crawlBrowserFallback` | **[D124]** `uncoveredSurfaces` = 这些注入面**按当前配置压根没测**（如默认 level=1 的 cookie/header/path/表单）；`crawlBrowserFallback` = 请求了 `--crawl-browser` 但降级成 HTTP 爬虫（SPA 的 XHR 面可能整体未发现）。两者都不影响已测面的结论，但引用「未检出」时必须同时声明覆盖缺口 |
| verdict=`session_expired` / `inconclusive` | 会话半途失效或签名/加密把请求拒了。修认证或配 `--request-script` 后重扫 |
| 报告 `summary.dbmsEvidence.caveat` 存在 | 命中的 DBMS 只有模板适配、未经真引擎验证——对外引用时必须带上该告警 |

## 3. 仓库工程纪律（改代码前必读）

- 每批改动走 **D 编号批次**（见 `TODO.md` 顶部），一次批次 = 代码 + 测试 + README/CHANGELOG 同步 + 门禁全绿。
- `npm run readme:check`：README 与代码**双向核对**。数字类口径（方言分层 / tamper 数 / payload / 端点表）自 D53 起核对；**CLI 旗标类（D68 的 ⑯ / D69 的 ⑰）自 2026-10-14 起才真正双向**——此前门禁只核数字，「加了开关不写文档」一直没人守，实测 CLI 168 个旗标里 README 曾漏 73 个、user-guide 漏 123 个、**`--help` 自己漏 11 个**。判据实现在 `scripts/readme-consistency.mjs`（⑯⑰ 在 `scripts/readme-flag-coverage.mjs`）。
- **收口清单已固化为一条命令：`npm run gate:close`（D71，22 项；`--quick` 跳最慢两项）。** 手写清单如下（漏一条都会被 CI 抓）：`npm run lint` + **`npm run typecheck`** + **六道门禁逐道跑**（`node scripts/{complexity,nesting,duplication,deadcode,debt,typecoverage}-guard.mjs`）+ **各门禁 `--selftest`** + **`node --test server/tests/（guard 与 wiring 类测试全量，判据见 scripts/gate-close.mjs 的 wiringTestFiles()，大小写不敏感）`** + `npm run readme:check` + `npm run facts:check` + `node scripts/ref-integrity.mjs` + `node scripts/e2e-wiring-check.mjs`（+`--selftest`）。**已漏六次**：D66 漏 typecheck、D70 漏五道门禁、D70b 漏 wiring（基线改完必须跑 wiring —— 防虚高判据在测试里，不在门禁输出里）、D94 前补 typecoverage（D87 起 JSDoc 覆盖跌破基线，pre-commit 被 SKIP_PRECOMMIT 绕过后收口清单里没有它，红到 push 才现——**跳过 pre-commit 的批次，收口清单是最后一道自留地**）、D95 补 e2e:wiring（D93 建的 param-name-lab 有入口从不执行，且该门禁只在 ci-local/CI、收口清单没有它——同一形态第二次重演；判据把注释当接线导致假阳性，一并修+自证）、**D97 修 wiring 收集（2026-10-18：wiringTestFiles() 用大小写敏感的 `includes('Guard')`，把 26 个 `*.guard.test.js`（含 D89 wafExternalParity.guard、wafSamples.guard 与新增 wafRealSamples.guard）漏在收口之外——它们只在 `cd server && npm test` 全量里被兜底跑，gate:close 看不见**）。
- `npm run acceptance`：17 套件验收门禁，提级提交前必跑。
- 引擎**有意零运行时 npm 依赖**（server 的 runtime deps 除外）；给引擎加能力请用 Node 内置能力。
- 检测判据/定库签名的测试是校准过的——不要为了让测试变绿而放宽断言；行为变化必须有靶场证据。

## 3.5 结论的永远质疑与推翻协议（2026-10-14 立规）

> **前提**：本仓所有对外结论（检出率 / 覆盖率 / 对标 sqlmap / WAF 绕过 / 数据库支持等级）
> 一律视为**未经证实的断言**，直到有**可复现命令 + 落盘产物**支撑。README 的门面数字不是证据，
> 门禁的绿灯也不是——门禁只保证「这条判据此刻没退化」，不保证「判据本身是对的」。

### 一、什么算「关键结论」

| 类别 | 例 |
|---|---|
| 能力声明 | 「检出 19/19」「误报 0/7」「747ms」（注：19/19 正是被 D91 推翻过的实例——见 §三 表与台账 `detect-benchmark-redteam-26`，示例保留缘于此） |
| 对标声明 | 「tamper 84/84」「字面一致 100/115」「6 种真引擎验证」 |
| 效果声明 | 「WAF 绕过 N/N」「某链是首选链」 |
| 安全声明 | 「0 误拦」「护栏不可绕过」 |

### 二、推翻协议（发现一条假数据时按序执行，**不许打补丁**）

1. **停用**：该结论立即标记为**待推翻**（`docs/_claims-ledger.json` 写 `status: refuted`），
   暂停一切对外引用；**禁止**"先留着以后再说"。
2. **列影响面**：grep 出所有引用它的地方——README / CHANGELOG / 报告模板 / 门禁基线 /
   提示词 / 对外话术。**引用它的地方全部作废**，包括"只在某段里顺口提一句"的地方。
3. **作废重做**：不是把数字改小，是**推翻结论本身、按新事实重做**。若新事实改变了某项能力
   的定性（如"绕过有效"变成"无可证增益"），相关实现 / 判据 / 基线一并重做。
4. **记推翻链**：CHANGELOG 写清「原结论 → 反证 → 新结论」，**保留旧数字**并标注作废——
   删掉历史等于把教训一起删了。
5. **补门禁**：能机器化的立即补成 selftest/门禁；不能机器化的进 `docs/_claims-ledger.json`
   的待复核队列，**每批 D 批次至少复核 1 条**。

### 三、已发生的推翻（不是口号，是本仓已执行过的先例）

| 原结论 | 反证 | 新结论 |
|---|---|---|
| 「tamper 挂链可有效绕过 CRS（2→8）」 | 执行器保真度实测只有 **60.7%**（`(?i)` 被吃、`TX/MATCHED_VARS` 未实现） | 保真度修到 **99.3%** 后同一批探针结论全变 → PL1 无增益、PL3/PL4 全零；**旧数字作废** |
| 「dash2hash+hexliterals 是 WAF 首选链」 | 真 ModSecurity 容器实测 **0/19 打穿** | 仅 unionvaluesrow 系 2/19；首选链推荐被 artifact-drift 门禁当场打回 |
| 「3 种数据库真实验证」 | 仓库里实际有 **7 种**引擎的真实验证记录 | 分层重列（真引擎/部分通道/模板适配），且等级写进每份报告的 `summary.dbmsEvidence` |
| 「D57 迁移后测试全绿即等价」 | A/B 快照对比抓出**旧状态机不复位**的真 bug（多字面量场景漏处理） | 迁移即修复；门禁绿 ≠ 行为等价，必须 A/B |
| 「红队检出 19/19、误报 0/7、中位 747ms」（10-05 三轮证据） | 10-17 全量 acceptance 实测 **18/19**：D11-cookie 静默假阴性——`--header "cookie:"` 双处存储 + axios 1.20.0 同名大小写头**后写赢**，服务端永远收到原值（124 探针全打在未注入值上，与「这个站没注入」同形） | D91 双层修复 + 6 例守卫（双向变异有牙）；复跑恢复 19/19。**旧证据 refuted、新证据另立**；`acceptance` 判据 ≥90% 曾把 18/19 判成 PASS ⇒ 判据阈值本身留观 |

### 四、常驻待复核队列（`docs/_claims-ledger.json`）

当前**已知为假、待推翻重做**的条目（发现即按二节协议处理，不得静默保留）：

| 结论 | 状态 | 证据 | 待办 |
|---|---|---|---|
| versioned 关键字族「与上游等价」 | **已修（T-6，2026-10-14）** | 上游 doctest 字面比对：本仓 `versionedkeywords` 输出漏包 `ALL`、`versionedmorekeywords` 漏 `CONCAT`（同族内不自洽） | T-6 已按上游形态重做（补 ALL + 22 个函数名，两件套收敛单一真源 `versionedKeywords.js`）；残留 3 条**形态差异**见下行 |
| modsecurityversioned / modsecurityzeroversioned / halfversionedmorekeywords 版本注释形态 | **已关闭（D102，2026-10-18）** | 上游整段包裹 / 不闭合 /*!0 形态由复刻件（modsecurityversionedblock / modsecurityzeroversionedblock / halfversionedmorekeywordsopen）承载，纳入对拍脚本 ALIAS 段机械比对（5/5 一致）；默认件形态保留 | 默认链是否切换仍待真机 A/B（差异行在 drift 账逐条点名，不再阻塞台账条目） |

> 复核命令：`node scripts/verify-tamper-upstream-examples.mjs`（读 `drift` / `excluded` 两字段，
> `drift` 里 `[variant]` = 已对齐、`[queued]` = **已知未修的真缺陷**）。

## 4. MCP（已落地，D43）

AI 代理宿主（Cursor / Claude Code / VS Code 等）可经 **MCP stdio** 直接驱动扫描器——
「MCP 是 CLI 的一个模式」（对标 dalfox `dalfox mcp` / semgrep `semgrep mcp`）：

```json
{ "command": "node", "args": ["<repo>/server/bin/cli.js", "mcp"] }
```

工具集（9 个）：`run_scan`（异步启动，返回 scanId；走与 REST 同一条 sanitizeStart 白名单 +
SSRF/scope 护栏）/ `get_scan_status` / `get_findings`（CWE·CVSS·受影响参数·PoC curl）/
`get_report`（json|markdown|html|csv|sarif）/ `list_scans` / `stop_scan` / `pause_scan` /
`resume_scan` / **`preflight`**（零 payload 侦察：可达性 + 注入点发现——**开打前先跑这个**）。

红线不变：`risk=3` 需显式 `confirmDestructive=true`（用户同意后才设）；`verdict=inconclusive`
不等于「未检出」（get_findings 的 verdictNote 会提示）。落地前请用 1.1/1.2 的两种方式驱动。
