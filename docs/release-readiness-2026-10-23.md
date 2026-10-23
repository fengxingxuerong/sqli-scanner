# 发布就绪度评估 · sqli-scanner（2026-10-23，v1.1.1 工作区）

> **方法**：不采信 README / CHANGELOG / 既有 e2e 报告里的任何数字。下面每条结论都对应本轮**实际执行的命令 + 退出码**，或代码 `file:line`。
> 凡本机**无法复跑**的，一律标注「未验证」，**不按通过计**（这是本仓 AGENTS.md §3.5 的要求，也是本评估的判据）。
>
> **环境**：Windows；node v24.18.0（已构建 sidecar 内为 22.22.2）；npm 11.16.0；cargo 1.98.0。
> **本机无 MySQL、无 Docker、无 PHP** ⇒ 25 套验收中 23 套本轮无法复跑。
>
> **2026-10-23 D133 复验更新**：本文 §0–§9 是 v1.1.1 工作区的历史评估。D127–D132 + D133
> 已把 6 项 P0 与 5 项 P1 的代码侧销账；四项能力未决已在真 MySQL 8.0.28/10.11 上复跑转绿；
> v1.2.0 外部裁判 187/187；全量 acceptance 17 PASS / 0 FAIL / 8 SKIP。当前结论：
> **本地 v1.2.0 具备对外技术发布条件；线上发布仍差推送/远端 tag/CI，以及 OOB 真机、
> 数据泄露实证、Docker/桌面打包等未验证项**。见 §11。

---

## 0. 结论（先看这张表）

| 发布形态 | 判断 | 依据 |
|---|---|---|
| **团队内部自用 / 授权项目交付**（CLI + 报告） | ✅ **现在就能用** | 端到端真扫通过（PGlite 靶场 3 条漏洞、exit 2、四件交付物）；22 项收口门禁全绿；报告达到可交付水准 |
| **GitHub 对外发版**（v1.2.0） | ❌ **现在不能发** | 6 项 P0 阻断（见 §3）：发布标识不可复现、sidecar 版本上报错误、发布门禁 CI 不真跑、D125 半提交、3 项验收未决、对外口径仍含被自我推翻的数字 |
| **商业产品 / 收费交付** | ⚠️ **暂不建议** | 上述 6 项 + 5 项 P1（依赖告警、认证后路径穿越、爬虫绕过 SSRF、版本号漂移、英文文档分叉） |

**一句话**：引擎能力与工程纪律已经超过多数同类开源项目；没做完的不是「能力」，而是**「发布」这件事本身**——可复现、可追溯、门禁真跑、口径自洽。补齐约需 **1–2 个工作日**。

---

## 1. 本轮实跑证据（可复现命令 → 退出码）

| # | 命令 | 本轮结果 | 判读 |
|---|---|---|---|
| 1 | `npm run gate:close` | **22/22 exit 0**，67s | 收口清单（6 道守卫 + 各 selftest + wiring + readme/facts/refs + typecheck + lint）真的全绿 |
| 2 | `npx vitest run` | **66 文件 / 574 用例全过**，exit 0 | 前端测试无虚高 |
| 3 | `cd server && npm test`（并发 3，同时跑 vitest+build） | 3730 用例：**3723 pass / 1 fail** / 6 skip | 唯一失败为 `tests/extractor.timeDrift.test.js:362`（墙钟敏感），**单独复跑 12/12 全过** ⇒ 负载敏感的 flaky，不是功能缺陷 |
| 4 | `node e2e/acceptance.mjs --only=unit`（并发 1，门禁口径） | **PASS** `tests=3730 pass=3724 fail=0 skipped=6` | 串行口径稳定；说明 3 的失败是环境负载，不是判据坏 |
| 5 | `node e2e/acceptance.mjs --only=report-contract` | **BLOCKED**（缺 MySQL）exit 1 | **fail-closed 正确**：缺依赖不冒充通过（这是本仓最值钱的设计之一） |
| 6 | `npm run build` | exit 0（MUI chunk 506 KB 告警） | 生产构建可用；包体偏大属优化项 |
| 7 | `cargo fmt --check` + `cargo check` | **0 / 0** | 桌面壳可编译、格式干净 |
| 8 | `e2e/real-world-lab` + `scripts/one-click-scan.mjs` | **3 条漏洞**（union/error/boolean）、exit **2**、`report.{html,json,md}`+`manifest.json` | 端到端真扫通过；报告含 CVSS、PoC、修复建议、裁决列、结论可信度 |
| 9 | `npm run tamper:parity` | 官方 84 个，**缺失 0**，exit 0 | 「tamper 全集」声明为真 |
| 10 | `npm run tamper:examples` | 字面一致 **100/115**、随机性跳过 11、复刻件 **5/5**、**无新增漂移**，exit 0 | 「同名 ≠ 同行为」被机械核对，drift 已逐条点名 |
| 11 | `node scripts/fetch-crs-assets.mjs --verify-rules` | 4 个 CRS 资产 **hash 与入库快照一致**，exit 0 | WAF 对拍不是用假规则 |
| 12 | `node scripts/release-check.mjs` | **exit 1**：工作区 36 处未提交 + 不在任何 tag 上 | 发布门禁自己说「发布已阻止」 |
| 13 | 已构建 sidecar 复制到仓外运行 | `/api/health` → `version:"0.0.0+unknown"` | **装到用户机器上版本号就是错的** |
| 14 | `npm audit`（root / server） | root **2 critical + 3 high**；server **1 high + 2 moderate**（prod） | 与 `AUDIT-SEC-2026.md`、README「0 known vulns」徽章矛盾 |
| 15 | `node server/bin/cli.js --version` | **exit 2**（不识别的参数） | 已发布 CLI 无版本查询入口 |

> 注：`docs/verification-2026-10-22-full-sweep.md`（上一轮全量验证，**当前未被 git 跟踪**）记录 16 PASS / 6 FAIL / 3 SKIP。本轮因缺 MySQL/Docker 无法复跑其 6 个失败项，**既不当它成立、也不当它不成立**。

---

## 2. 十维评分（主观加权，依据在上文与 §3/§4）

| 维度 | 分数 | 一句话依据 |
|---|---|---|
| 检测引擎能力 | **7.5 / 10** | 9 技术通道 / 18 方言分层诚实；外部裁判 187/187 是**小样本**且 Benchmark 占 178；WAF PL1 与 union 显式点仍有未决红 |
| 工程质量与门禁 | **9 / 10** | 6 道守卫 + 每道 selftest + 文档双向核对 + wiring 收集，同类项目罕见 |
| 测试体系 | **8 / 10** | 4298 用例全过（串行），但存在墙钟敏感 flaky 与「Node 24 libuv 退出断言」环境债 |
| 文档 | **6.5 / 10** | 极详尽且有推翻协议，但**对外口径过期/自相矛盾**（竞品表、Benchmark、en README、验收快照） |
| 工具自身安全 | **7 / 10** | exploit 双闸门 / SSRF 逐跳复核 / 常数时间 token 都是真的；扣分在依赖告警、`scanId` 路径穿越、爬虫旁路 |
| 发布工程 | **3.5 / 10** | 脏树 + 50 提交未推 + 本地 tag 与线上 release 的 commit 不是同一个 + 发布门禁 CI 不真跑 |
| 桌面端 | **5 / 10** | 编译/格式干净，但**未打包验证**且已装版本号错误（§3 P0-2） |
| CI | **7 / 10** | 13 job 覆盖广、远端最新定时跑 success；但两项门禁只在本地脚本里，且 release-check 只跑 selftest |
| 可维护性 | **6.5 / 10** | 代码 14.2 MB / 1733 文件很健康；但 CHANGELOG 704 KB、TODO 255 KB，人类已无法通读，新贡献者门槛高 |
| 产品化 / UX | **7.5 / 10** | Web/CLI/MCP/桌面四形态齐、报告可交付、triage 工作流；缺 `--version`、无 npm 包（设计选择）、包体偏大 |

**综合发布就绪度：6.5 / 10** —— 「技术 Beta」远高于及格线，「对外 Release」还差一层收尾。

---

## 3. P0 · 发布硬阻断（发版前必须处理）

### P0-1 发布标识不可复现（最严重）
- `node scripts/release-check.mjs` → **exit 1**：工作区 **36 处未提交**（含 README/CHANGELOG/facts/claims-ledger；写入本报告后为 37 处），「打包会把磁盘内容发出去」。
- 本地 `HEAD` 比 `v1.1.1` tag 多 **50 个提交**（`git log --oneline v1.1.1..HEAD | wc -l`），而 `package.json` 仍写 `1.1.1`。
- `git branch -vv` → `master ... [origin/master: gone]`；`git for-each-ref refs/remotes` **为空**。
- GitHub API：远端 `master` = `3d6abe31`（D110，2026-10-19 推送），也就是**远端落后本地 50 个提交**；线上 release `v1.1.1` 指向的 commit 在本地不存在（本地 tag 指向另一个 sha）。
- **后果**：现在打 tag 发版，产出的源码树与线上 release 既不同源也不可追溯；「v1.1.1」会同时指两个不同的代码状态。这是**任何**对外发布的第一道否决项。

### P0-2 桌面端 sidecar 版本上报错误（会装进用户机器）
- `server/src/core/version.js` 靠运行时向上找 `package.json`；`scripts/build-sidecar.mjs` 不带版本号，`sea-config.json` 无版本字段，`scripts/build-engine.mjs` 无版本 define。
- 本轮实证：同一条已构建 exe，**在仓内跑 → `1.1.1`**（读到开发树），**复制到仓外跑 → `0.0.0+unknown`**。装到用户机器后 `/api/health` 永远是这个值，排障与升级核对全部失真。
- 修法：构建期 `define` 注入 + SEA `--env`/asset 兜底，冒烟里断言 `version === package.json.version`（现有 sidecar smoke 断言 `/api/health` 200，但**没断言版本**）。

### P0-3 发布门禁在 CI 里形同虚设
- `.github/workflows/ci.yml` 只跑 `release-check.mjs --selftest`（自证清单用），而 `release-check.mjs` 一进 selftest 就 return ⇒ **CI 从不检查脏树 / tag↔版本 / Tauri npm↔crate 同线**。
- `npm run release:check` 既不在 `check:all`，也不在 `gate:close` 22 项里。
- 另有 2 道门禁（`greenguard`、`coverage-calibration`）只存在于 `scripts/ci-local.mjs`，`ci.yml` 零命中——本仓自己的验证报告已把这条记为「CI 与本机门禁漂移」。
- **后果**：D77 那类「npm 版本线与 crate 线漂移」问题会一路绿到打包末尾；脏树发版也不会被拦。

### P0-4 D125（triage）处于「半提交」状态
- `git status`：**实现文件未跟踪**（`server/src/services/findingTriage.js`、`src/components/TriageControls.tsx`、`src/components/VulnCard.tsx`、`src/hooks/useTriageForm.ts`），**测试文件已 staged**（`A server/tests/findingTriage.test.js`、`A server/tests/api.findingTriage.test.js`），路由/报告/i18n 改动未 staged。
- 现在执行 `git commit`（不加 `-a`）会提交「测试引用了不存在的模块」⇒ CI 必红；而不提交则 README:137/294 与 CHANGELOG 描述的是未落库能力。
- 附带：`README.en.md` 声称 17 套验收（中文是 25），且**没有任何门禁读它**。

### P0-5 三项验收未决（能力声明级，非文档问题）
上一轮全量验收记录、本轮无法复跑（本机无 MySQL）：
1. **CRS PL1：检出 4/8 < 基线 8/8**（人工挂链与自动选链双红），且 `off=on=4` ⇒「挂链有增益」在该环境不成立；
2. **显式 UNION 注入点的 union 通道漏报**（报告契约套件技术位只有 `["error"]`）；
3. **fileWrite 自报与外部事实矛盾**：`{ok:false, wrote:true, verified:false}` 且文件不存在——正是本仓自己定义的「中间层自报成功、无人校验外部事实」缺陷形态。

发布说明里若只字不提，等于用一个已知有偏差的验收基线去背书「检出能力」。

### P0-6 对外口径仍含已被自我推翻的数字
- `README.md:583-584` 竞品表仍写 sqlmap **16/19 检出、6/7 误报**；而 `CHANGELOG.md:887`（D102）已把同一批日志重新判定为 **14/19、0/7**，并称旧数字是 bench 脚本自伤。**贬低竞品的数字对自家不利时没改，对自家有利时没标作废**。
- `README.md:686` 仍以 `Benchmark 20/504 子集真值 4/12` 作为 Benchmark 结论，D115 已推翻（178/178）；同一句还写 Benchmark「不接门禁」，但 `README.md:637` 把它列为验收套件 #4。
- 三处 Benchmark 口径互不相等：README `4/12` / 台账+CHANGELOG `327 有效（178 真值 / 149 安全）` / 上一轮实跑 `344 有效（187 / 157）`。
- `README.md:662-663` 「最近一次全量结果（2026-09-20）12 PASS / 12 套件全绿」与 25 套件现状、上一轮 6 FAIL 冲突。
- 台账里 2 条 `refute_cmd` 已失效（`npm run bench`、`e2e/waf-real/crs-fidelity.mjs` 均不存在），使「可复现」落空。

---

## 4. P1 · 发布前应清（不阻断但会被追问）

| # | 问题 | 证据 |
|---|---|---|
| P1-1 | **生产依赖有高危**：`follow-redirects@1.16.0`（经 axios 1.20.0）在 root 与 server 两棵树里，GHSA-q3jh-wrc6-jgq8 / GHSA-8r9p-f939-6h3c（跨域重定向泄凭据头）。实际被自有 `maxRedirects:0` 缓解，但声明与事实不符 | `npm audit`：root 2C/3H/2M，server 1H/2M；`AUDIT-SEC-2026.md:56-64`、`README.md:4` 徽章「0 known vulns」已过期 |
| P1-2 | **认证后路径穿越**：`services/sideEffectLedger.js:52-53` 未校验 `scanId` 就 `join(ledgerRoot(), scanId, ...)`；`exploitRoutes.js:475/495` 只做长度校验 ⇒ `../..` 可越界读/写 `side-effects.json` 并递归建目录。审计报告的「路径穿越 ✅」只覆盖了 `scanLedger` | `scanLedger.js:139-145` 有正确写法可比对 |
| P1-3 | **浏览器爬虫绕过 SSRF/授权范围**：`discovery/browserCrawler.js:156-175` 直接 `page.goto()`，无路由拦截、无逐跳 scope 校验 ⇒ 与 `SECURITY.md:21` 「所有出站请求都过 httpClient」矛盾（该能力 opt-in 且需 playwright） | 默认 `--crawl-browser` 关闭，但报告已声明降级事实 |
| P1-4 | **版本号漂移**：`server/package.json` 与两个 `package-lock.json` 仍是 `1.1.0`，`version:check` 只核 3 个文件，看不见 | `npm run version:check` exit 0 |
| P1-5 | **英文 README 已分叉**（17 vs 25 套件、能力数字缺失），且无门禁覆盖 | `README.en.md:186` |

---

## 5. P2/P3 · 可以排期

- CLI 无 `--version`（`--help` 有、版本查询没有），对包管理/排障不友好。
- `--help` 341 行、CHANGELOG 704 KB、TODO 255 KB：信息完备但**不可通读**，建议生成分层索引。
- Docker 构建上下文约 3.3 GB（`.dockerignore` 未排除 `src-tauri/`、`.box-agent-scratch/`、`e2e/`、`logs/`、`reports/`）；`e2e/udf-lab` 189 MB 仍在库内。
- SSE token 走 query string（会进代理日志）；`sqlmapRoutes.js:29` 只读 `SCAN_API_TOKEN`、忽略 `SCAN_API_TOKEN_FILE`。
- `gate:close` 22 项不含 `version:check` / `greenguard` / `artifact-drift` / mutation。
- 文档小瑕疵：`README.md:594-595` 同一句重复；`wafRules.js` 注释写 126 matcher，实际 156；docs 篇数 42/38/43 三处不一致（无门禁）。
- `docs/verification-2026-10-22-full-sweep.md` 是本轮最有价值的审计文件，却**未被跟踪**（不进库＝不进任何门禁）。

---

## 6. 建议的收尾批次（按 ROI，约 1–2 人日）

| 序 | 批次 | 内容 | 完成判据 |
|---|---|---|---|
| 1 | D127 | **发布身份归位**：提交 D125/D126（含未跟踪实现）→ 本地与 origin 历史对齐（或明确 force-push 公告）→ 版本升 `1.2.0` → CHANGELOG `[Unreleased]` 转正 → 干净树上打 tag | `release-check` exit 0；`git rev-list v1.2.0..HEAD` = 0 |
| 2 | D128 | **sidecar 版本戳**：构建期注入版本 + 冒烟断言 `version === package.json.version`（仓外目录跑） | 出仓探针返回 `1.2.0` |
| 3 | D129 | **门禁进 CI**：`ci.yml` 把 `release-check --selftest` 换成真跑（dirty 检查在 push 上放宽、tag 上严格）；补 `greenguard`/`coverage-calibration` | CI 日志出现三项；故意制造脏树/tag 不一致能红 |
| 4 | D130 | **口径统一**：README 竞品表按 D102 重判改 14/19、0/7（保留旧数字并标作废）；Benchmark 三处口径统一并标注「合成靶场」；删重复行；en README 同步或明确标注「滞后」 | `readme:check`/`facts:check` 绿 + 人工复核 3 处 |
| 5 | D131 | **三项验收未决**：WAF PL1 bisect 或按实测收紧基线并记推翻链；union 显式点漏报定位；fileWrite `wrote` 只由外部事实置位 | 三项各有一条可复跑判据 |
| 6 | D132 | **P1 安全清账**：`npm audit fix`（两棵树）+ `scanId` 校验 + 爬虫走 egress 层（或改 SECURITY.md 表述） | audit 0 high；越界 `scanId` 400；文档与代码一致 |

> 若目标是**本周就发**：至少完成 1、2、4，并在 release notes 的「已知问题」里逐条写明 P0-5 三项与 P1 清单——**不要把「未验证」写成「不存在」**。

---

## 7. 发布检查清单（勾选即发）

- [ ] 工作区干净（`git status --porcelain` 为空）
- [ ] `npm run gate:close` 22/22
- [ ] `npm run release:check` exit 0 且 HEAD 在 tag 上
- [ ] 版本三处（root/server/tauri/Cargo）+ 两个 lock 一致
- [ ] `npx vitest run` 574+ 全过；`cd server && npm test` 0 fail（串行口径）
- [ ] `node e2e/acceptance.mjs` 在**有 MySQL 的机器**上跑完 25 套（或 release notes 列明 BLOCKED 项）
- [ ] 外部裁判至少复跑 DVWA + VAmPI（有 MySQL/PHP 的机器）
- [ ] `npm run build` + 桌面 `tauri build` 产物冒烟（版本号、/api/health、一次真扫）
- [ ] `npm audit`（root + server）无 high/critical，或逐条写明缓解
- [ ] README 竞品表/Benchmark/验收快照三处口径与最新证据一致
- [ ] release notes 含「已知问题 + 未验证面」段落

---

## 8. 本轮未验证面（不等于不存在，等于没有证据）

1. 25 套验收中的 23 套（本机无 MySQL/Docker/PHP）：WAF 两套、fileRead/fileWrite、OOB 真机、5 个外部靶场、报告契约等。
2. 桌面端**打包**（`tauri build` / NSIS）与安装包冒烟：只做了 `cargo fmt/check`。
3. 真机 REST/SSE 全链路（`npm run server` + 前端同端口）、MCP stdio 九工具、SEA 单文件打包、性能预算、sqlmap 同题对标。
4. GitHub Actions 的**逐 job** 结论：只确认了远端最新定时 run（287）success、run 282（D108 push）failure；未核对全部 287 次运行。

---

## 9. 值得肯定的地方（评价要平衡）

- **门禁纪律**：6 道守卫各自带 selftest，`readme:check` 与 `facts:check` 做代码↔文档双向核对，`gate-close` 把「漏跑清单」固化成一条命令——这在个人/小团队项目里极少见。
- **推翻协议不是口号**：台账 24 条里 5 条 `refuted` 都保留了旧数字、标注作废、指向新证据，CHANGELOG 有推翻链；`tamper` 的 drift 逐条点名而不掩盖。
- **fail-closed 贯穿到底**：缺依赖 BLOCKED 而非 PASS、未知 CLI 参数拒绝启动、文件写未验证就不该置 `wrote`（本仓自己点名了这个缺陷形态）、利用能力双闸门。
- **报告是真的能交付**：本轮实扫产出的 `report.md` 含方法、可信度、CVSS 向量、逐条证据、按通道的修复建议、人工裁决列，并且明确写「本次未开启拖库，影响面为定性推断」。
- **诚实边界写进产品**：`summary.dbmsEvidence.caveat`、`unverifiedSurfaces`、`uncoveredSurfaces`、`crawlBrowserFallback` 把「没测成」与「测了没洞」分开——这正是多数扫描器最容易撒谎的地方。

**总评**：这是一个「工程完成度远高于发布完成度」的项目。能力已经够用，缺的是发版那套枯燥动作。

---

## 10. 销账记录（2026-10-23，批次 D127–D132）

本报告写完后立刻按清单执行了一轮修复，逐项对应 §3/§4：

| 原条目 | 处置 | 判据 / 证据 |
|---|---|---|
| P0-1 发布标识不可复现 | **已修（D127）**：D125/D126 全部提交；version-sync 判据 3 处 → 8 处（新增 server/package.json 与两个 lock 的两份副本）；1.1.1 → 1.2.0 | `node scripts/version-sync.mjs` 8/8 一致；`node scripts/release-check.mjs` 在干净树 + tag 上 exit 0 |
| P0-2 sidecar 版本 0.0.0+unknown | **已修（D128）**：版本作为 SEA asset 内嵌 + 纯解析器 + 构建冒烟断言 + Rust 侧 ENGINE_VERSION | 出仓探针 `/api/health` → `1.2.0（来源 sea:package.json）`；`version.resolve.test.js` 7/7 |
| P0-3 发布门禁 CI 不真跑 | **已修（D129）**：`release-check` 真跑 + selftest 两步；greenguard / gate-recorder / coverage-calibration / flag-coverage 接线；npx eslint → npm run lint | `.github/workflows/ci.yml` 新增步骤；`npm run gate:close` 22/22 |
| P0-4 D125 半提交 | **已修（D127）**：实现文件入库、测试与实现同批 | `git status` 干净；`cd server && npm test` 全绿 |
| P0-5 三项验收未决 | **部分修（D131）**：fileWrite `wrote` 改由回读验证置位（attempted/unverified 补位）；CRS PL1 与 union 漏报**仍需真 MySQL + CRS 环境**，已写入 README「未决 FAIL」与 TODO 待推进 | `exploiter.fileWriteUnion.test.js` / `exploiter.test.js` 语义断言；README 验收表逐项标注 |
| P0-6 对外口径含被推翻数字 | **已修（D130）**：sqlmap 16/19、6/7 → 14/19、0/7（保留旧数字作废）；Benchmark 4/12 → 178/178、0/149 并纠正「不接门禁」；删除 09-20 历史快照；en README 17→25；AGENTS 三处口径 | `npm run readme:check` / `facts:check` 绿 + 人工复核 |
| P1-1 依赖告警 | **已修（D132）**：两棵树 `npm audit fix`；server **0 vulnerabilities**；根包剩 devDependencies 4 条（vitest/tinypool 需大版本升级），SECURITY.md 如实登记、徽章改 prod 口径 | `npm audit`（server）0；`npm audit`（根）2 critical+2 moderate 全 dev |
| P1-2 scanId 路径穿越 | **已修（D132）**：sideEffectLedger 补 safeScanId（与 scanLedger 同口径），读写/清理三处入口共判 | `sideEffectLedger.test.js` 新增 2 例（`../`、绝对路径、NUL、空串全拒） |
| P1-3 浏览器绕过 SSRF | **已修（D132）**：`context.route` 逐条过 `assertSafeHttpTarget`（host 级缓存、fail-closed）；SECURITY.md 写明「只拦 SSRF、不按 scope 拦 CDN」的有意边界 | `browserEgressGuard.test.js` 5/5 |
| P1-4 版本号漂移 | **已修（D127）**：见 P0-1（8 处互校） | 同上 |
| P1-5 en README 分叉 | **已修（D130）**：17 → 25 套件；另注明中文 README 为权威版本 | 人工复核 |
| P2 CLI 无 --version | **已修（D132）**：`-V/--version` 早退打印版本（README/help 同步，flag 覆盖门禁覆盖） | `node server/bin/cli.js --version` → `1.2.0`，exit 0 |

**仍未关闭（2026-10-23 D133 更新）**：OOB 真机 / 数据泄露实证环境不满足、无真实商业云 WAF
样本、Docker 镜像与桌面打包未验证、vitest 大版本升级、远端 50+ 提交未推送。
CRS PL1 4/8、显式 UNION 漏报、fileWrite 环境闭环三项已在 D133 复跑转绿，见 §11。

---

## 11. 2026-10-23 D133 发布复验（旧未决销账 + v1.2.0 外部裁判）

| 项 | 命令 | 结果 |
|---|---|---|
| 报告契约（显式 UNION） | `python e2e/run-with-sandbox.py e2e/contract/report-contract.e2e.mjs --drop-dir` | **8/8**；union 通道检出 |
| CRS 人工挂链 PL1 | `MYSQL_* node e2e/acceptance.mjs --only=waf-real,waf-auto` | **off=8 / on=8**；安全误拦 false |
| CRS 自动选链 PL1 | 同上 | **技术位=8**；安全误报 0 |
| fileWrite / fileRead | MySQL 8.0.28 沙箱（`secure_file_priv` 限定目录） | **均 PASS**；fileWrite `via=union`、文件系统侧含标记 |
| 全量 acceptance | `MYSQL_* WAF_GATE_PL=1 node e2e/acceptance.mjs` | **17 PASS / 0 FAIL / 8 SKIP** |
| 外部裁判 v1.2.0 | 5 个靶场同轮复跑 + Benchmark 三清单 | **187/187、0 误报** |

8 SKIP 中：四个外部裁判已单独复跑（187/187）；fileRead/fileWrite 已用沙箱复跑（PASS）；
仅 **OOB 真机（缺 PG）与数据泄露实证（环境不满足）仍未验证**。

**当前发布判断**：
- **本地 v1.2.0 技术版：可以发布**（`release-check` exit 0、`gate:close` 22/22、tag 在 HEAD、
  工作树干净、外部 187/187、全量验收 0 FAIL）。
- **线上 GitHub Release：还差** 推送 `master` + tag（需明确授权，且需网络可达）、远端 CI 在
  tag 上真跑、release notes 引用 CHANGELOG 1.2.0 的「已知问题与未验证面」。
- **商业产品口径：仍不建议**（无真实云 WAF 样本、OOB/数据泄露未验证、Docker/桌面未打包验证）。

证据：`e2e/results/acceptance-report.md`、`e2e/results/external-sweep-2026-10-23-v1.2.0.md`。

---

## 12. 2026-10-23 D134 独立复跑（宿主 MariaDB，20 PASS / 0 FAIL）

D133 的结论由另一会话产出，故本轮**在同机上独立重跑**了一遍全量验收（宿主 MariaDB 10.11.19
@3306，`root/root`，`secure_file_priv=D:\tools\mariadb\files\`；另有一个真 MySQL 8.0.28
沙箱在 3308 常驻）。结论与 D133 一致，并借这次复跑抓到两个把**环境**记成**能力**的真缺陷：

| 观察 | 真实性质 | 处置（D134） |
|---|---|---|
| fileWrite `文件落盘=false` / fileRead BLOCKED（方式=隔离沙箱重试） | 套件把目标目录写成 `tmpdir`/`D:/tmp`，与实例的 `secure_file_priv` 限定目录不符 ⇒ MySQL 拒绝 | 新增 `e2e/lib/fileopsPaths.mjs`（NULL 禁用 / `''` 不限制 / `'/dir/'` 必须用它）+ 5 例自证；两个套件改读 `@@secure_file_priv`。修后宿主实例真跑 PASS（`via=union`、文件系统侧含标记；fileRead 回读一致） |
| 红队 `0/19 检出率 0% FAIL` | 宿主 3306 没起时 `env.mjs` 自己拉起口令未知的 mysqld ⇒ 19 个真值点全部查库失败（**靶场库不可用**） | `env.mjs` 口令三候选全败时打 `[BLOCKED]` 并退出；`withRedteamLab` 捕获其输出（原 `stdio:'ignore'` 把诊断全丢）；判定收敛到 `e2e/lib/redteamVerdict.mjs`（+8 例自证） |
| 沙箱自愈重试整条链路抛 `UnicodeEncodeError` | Windows GBK 控制台打印 `⚠` 即崩，套件既没 PASS 也没 SKIP → BLOCKED | `e2e/udf-lab/mysql_sandbox.py` stdout/stderr 切 UTF-8 + replace |

**D134 后本机全量结果：20 PASS / 0 BLOCKED / 0 FAIL / 5 SKIP（exit 0）**
——比 D133 的 17 PASS/8 SKIP 多 3 项（fileRead/fileWrite 由「沙箱/跳过」变为**宿主实例真跑**）。
5 个 SKIP 全部是「四个外部裁判未起 + 数据泄露实证环境不满足」，与 D133 同一口径。

**发布判断不变**：本地 v1.2.0 可发布；线上发布差推送与 tag（需网络与授权）；
商业口径仍不建议（无真实云 WAF 样本、Docker 与桌面打包未验证）。

---

## 13. 2026-10-23 D135 本机补齐 DVWA 裁判与数据泄露实证（22 PASS / 0 FAIL / 3 SKIP）

D134 之后剩下的 SKIP 都在「靶场没起」这一类。本轮把本机**能起的**起起来——宿主 MariaDB 10.11
的 datadir 里本就有 `dvwa` 库，`dvwa.tar.gz` 也在，于是补上真 DVWA（PHP 8.3 built-in server，
`DISABLE_AUTHENTICATION=true` + `DEFAULT_SECURITY_LEVEL=low`）：

| 套件 | 结果 |
|---|---|
| 外部裁判 3 号（DVWA） | **5/5 真值、安全端点 0 误报、证据不足 0**（low GET / low 盲注 / high cookie / medium POST + impossible 对照） |
| 数据泄露实证 | **成立**：`--dbs` 取回**真库名 9 个**（`dvwa`/`sqli_lab`/`redteam_lab`/`campus_library`/… ）而非 payload 残片；139 请求、3 条漏洞 |
| 全量 acceptance | **22 PASS / 0 BLOCKED / 0 FAIL / 3 SKIP（exit 0）** |

**仍未验证（3 SKIP）**：Juice Shop、VAmPI、OWASP Benchmark 未在本机起靶场
（其单独复跑证据仍是 D133 的 187/187、0 误报，含 Benchmark 三清单）。
**OOB 真机本轮为 PASS**（真 PG `COPY TO PROGRAM` 真实回连），此前「缺 PG」的记录已被本机环境推翻。

结论：**本机可复现范围内，验收已无 FAIL、无 BLOCKED**；剩下的都是「没起靶场」，
以及仓库外才能验证的三件事（真实云 WAF 样本、Docker/桌面打包、远端推送）。

---

## 14. 2026-10-23 D136 再补 VAmPI（23 PASS / 0 FAIL / 2 SKIP）

把外部裁判 2 号 VAmPI 也起起来（上游 `VAmPI-master` + 现成 venv；漏洞实例 5000 +
参数化对照 5001，`tokentimetolive=7200`）。踩到并记录的两处：`run_port.py` 需要把源码目录
同时作为 cwd 与 `PYTHONPATH`（否则 `from config import vuln_app` ImportError）；
官方默认 `tokentimetolive=60s` 会让整轮扫描中途全 401（真假恒等 ⇒ 假阴性），必须显式设大。

| 套件 | 结果 |
|---|---|
| 外部裁判 2 号（VAmPI） | **2/2 真值、安全端点 0/5 误报、证据不足 0、Bearer 5 端点未测 0** |
| 全量 acceptance | **23 PASS / 0 BLOCKED / 0 FAIL / 2 SKIP（exit 0）** |

**仍剩 2 个 SKIP**：Juice Shop（需完整 Angular 构建，本机 4 轮未起）、OWASP Benchmark
（需 JDK17 + Maven + cargo）。两者的单独复跑证据仍为 D133 的 187/187、0 误报（含 Benchmark 三清单）。

综合三轮（D134→D135→D136）：本机 acceptance 由 20 PASS/5 SKIP → 22/3 → **23/2**，
且 **FAIL 与 BLOCKED 全程为 0**；未验证面收敛到「Juice/ Benchmark 未起靶场 + 真实云 WAF 样本 +
Docker/桌面打包 + 远端推送」四类。

---

## 15. 2026-10-23 D137 推翻「Juice Shop 本机不可复现」（24 PASS / 0 FAIL / 1 SKIP）

仓库长期把 Juice Shop 裁判记为「本机不可复现（需完整 Angular 构建、无法只部署 API 层，4 轮尝试失败）」。
本轮把它跑起来，**该结论按 §3.5 作废**，真因三条（都可复现）：

| 症状（旧记录） | 真因 | 处置 |
|---|---|---|
| `Cannot find module '../data/datacache'`、接连索要 `JuicyBot.png`/`threejs-demo.html` | 解压出的源码树**缺整个 `data/` 目录**（partial 解压）；那些资产本就在 `data/` 里 | `tar -xzf juice.tar.gz` 重解压（恢复 228 条 `data/` 条目） |
| `npm 10/9 装依赖崩 edgesOut` / `@codemirror/state` 解析失败 | 前端依赖必须**扁平（hoisted）**：npm 在该 lockfile 上崩 `Cannot read properties of null (reading 'matches')`；strict 布局的 pnpm 缺上游未声明的 `@codemirror/state` | `npx pnpm@9 install --shamefully-hoist` + `npx ng build --configuration production`（42s，产出 `index.html/main.js/polyfills.js/styles.css` = validatePreconditions 的四个名字） |
| （新发现）裁判侧全线 ECONNREFUSED、0/2 检出 | Node 24 在 Windows 下扫搜索路由触发 libuv `Assertion failed: !_wcsnicmp(filename, dir, dirlen), file src\win\fs-event.c, line 72` → **进程当场崩**（非引擎缺陷；同轮 validity-guard 正确判「结论不可信」而非「未检出」） | 用 **Node 22**（本机 22.22.2）跑靶场 |

**结果**：`--only=juice-shop` → **2/2 真值（搜索 LIKE 双层括号 + 官方登录 JSON body）、安全端点 0/4 误报**；
**全量 acceptance：24 PASS / 0 BLOCKED / 0 FAIL / 1 SKIP（exit 0）**。
唯一 SKIP = OWASP Benchmark（需 JDK+Maven+cargo，且源码要从 github.com 拉——本机 443 不通）。
台账新增 `juice-shop-runnable-local-d137`（refuted + 复现命令）。

---

## 16. 2026-10-23 D138 起 OWASP Benchmark → **25/25 全绿**

最后一个 SKIP 也起起来了：本机其实**已有** Benchmark 的源码与构建产物
（`.box-agent-scratch/BenchmarkJava-master`、`benchmark-db`），JDK17 + Maven 3.9.11 本机也有，
`~/.m2` 里 hsqldb 2.7.4 与 cargo 的 Tomcat 均已缓存 ⇒ **不需要连 GitHub**。

| 项 | 结果 |
|---|---|
| 基线清单 74 | **43/43 真值、0/24 安全**（header + 参数名形态 50 条；`{call}` 安全侧 0/3） |
| query 210 | **111/111、0/99** |
| header 67 | **33/33、0/34** |
| 合计 | **187/187 真值、0/157 安全零误报、证据不足 0**（与 D133 的单独复跑逐项一致） |
| **全量 acceptance** | **25 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP（25/25 跑出断言，exit 0）** |

两处起法要点（写进 TODO 复现配方）：HSQLDB 必须**手动常驻**（官方 antrun 的 fork 子进程随
`mvn` 退出被回收）；`cargo:run -Pdeploy` 不要跟 `clean` 连跑（库文件锁）。

**发布判断（更新）**：
- **本地 v1.2.0：本机全量验收 25/25 全绿、0 FAIL、0 BLOCKED、0 SKIP**，`release-check` exit 0、
  tag 在 HEAD、工作树干净 ⇒ 本机可交付状态已达成。
- **线上发布：仍差**推送 master + tag（本机 443 不通，需能出网的环境或代理）。
- **商业口径：仍不建议**——真实商业云 WAF 样本、Docker 镜像与桌面打包未验证；
  这三个不在本机可复现范围内，已如实登记在 TODO 与台账 caveat。

---

## 17. 2026-10-23 D139 桌面壳 release 构建 + 真机冒烟 + MCP 手测

评估里「桌面端零验证」与「MCP/REST 未验」两块本批补上（代码未改动，只记录实测）：

| 项 | 命令 | 结果 |
|---|---|---|
| 壳 release 构建 | `npx tauri build --no-bundle` | `Finished release profile in 2m15s` → `src-tauri/target/release/sqli-scanner.exe`（**12.9 MB**） |
| 壳 ↔ sidecar 真机 | 启动该 exe | 壳自动拉起 `sqli-engine` 子进程，引擎监听 `127.0.0.1:4567` |
| 版本上报（D128 第二道保险） | `GET /api/health` | `version=1.2.0`、**`versionSource=env:ENGINE_VERSION`** ⇒ Rust 侧 `env!("CARGO_PKG_VERSION")` 注入在真实链路上生效 |
| 一次性 token | 同上 | `authEnabled=true`（壳注入 token），public 的 health 仍可读 |
| MCP stdio | `printf initialize/tools\\/list \| node server/bin/cli.js mcp` | `protocolVersion 2024-11-05`、`serverInfo.version 1.2.0`、**9 个工具**（与 README 表一致） |

**仍未关**：NSIS 安装包（本机无 tauri 打包缓存、NSIS 工具链需联网下载而 github 不可达 ⇒ 只到 exe）、
Docker 镜像（本机无 Docker）、真实商业云 WAF 授权样本、远端推送。

---

## 18. 2026-10-23 D140–D141 版本互校补一处 + 免安装便携包

- **D140**：D139 跑 `tauri build` 后 `Cargo.lock` 里本仓包版本被 cargo 从 `1.1.1` 改成 `1.2.0`
  —— 说明 D127 的「8 处互校」漏了这份副本（不真跑 cargo 就永远不红）。
  `version-sync` 增加该判据（只认 `name = "sqli-scanner"`，不碰依赖条目），目标数 8 → **9**，
  并补一例 selftest。判据：`version:check` 9/9 一致。
- **D141**：产**免安装便携包**并在**干净解压目录**冒烟：
  `sqli-scanner.exe`（12.9 MB）+ `sqli-engine.exe`（sidecar 改名，Tauri 打包时同款命名）
  + README + LICENSE → `sqli-v1.2.0-portable-win-x64.zip`（38.7 MB，仓库外）。
  干净解压后启动：壳拉起 sidecar、`/api/health` = `1.2.0`（`versionSource=env:ENGINE_VERSION`、
  `authEnabled=true`），退出无残留。
  边界：这是绿色包，**不是**官方安装包（无开始菜单/卸载项）。

**发布判断（最终）**：本机可复现范围内**全部转绿**（验收 25/25、桌面壳 release 构建 + 真机冒烟、
MCP 9 工具、版本 9 处互校、便携包干净冒烟）。仍未验证的四件事都需要**本机之外的资源**：
官方安装包（联网）、Docker 镜像（无 docker）、真实商业云 WAF 授权样本、远端推送。

---

## 19. 2026-10-23 D143 交付件判据收敛 + 自证进收口清单

D142 加完两个便携包脚本后门禁立刻抓到两处真问题，本批一并收口：

| 门禁 | 红的原因 | 处置 |
|---|---|---|
| `duplication` 3272 → **3274** | 两个脚本各写一份「Tauri 命名约定」（sidecar 必须叫 `sqli-engine[.exe]`）与 `/api/health` 探活；后者还与 `build-sidecar` 的探活重复 97 tokens | 新增 `scripts/lib/portable.mjs` 作**单一来源**（命名约定 / manifest / 探活 / 选项解析 / 失败跳过 / 自证 harness + 两组用例）；`build-sidecar` 也改用同一探活 ⇒ 回到基线 3272 |
| `deadcode` 166 → **167** | 新导出 `targetTriple` 只有本模块内部用 | 去掉 export（跨模块不可见即不该导出）⇒ 回到基线 166 |

另补：两个脚本各自 `--selftest`（11 + 7 条判据，含「`authEnabled='true'` 字符串不得算过」这类反向护栏），
并按纪律**接进收口清单**（`gate:close` 22 → **24 项**，`must` 名单与 AGENTS §3 同步）。

判据：`gate:close` **24/24**；便携包端到端（组装 38.7 MB zip + 干净解压冒烟）与 sidecar 冒烟
（D128 版本断言 `1.2.0 / sea:package.json`）均复跑通过。
