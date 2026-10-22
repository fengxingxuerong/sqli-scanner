# 发布就绪度评估 · sqli-scanner（2026-10-23，v1.1.1 工作区）

> **方法**：不采信 README / CHANGELOG / 既有 e2e 报告里的任何数字。下面每条结论都对应本轮**实际执行的命令 + 退出码**，或代码 `file:line`。
> 凡本机**无法复跑**的，一律标注「未验证」，**不按通过计**（这是本仓 AGENTS.md §3.5 的要求，也是本评估的判据）。
>
> **环境**：Windows；node v24.18.0（已构建 sidecar 内为 22.22.2）；npm 11.16.0；cargo 1.98.0。
> **本机无 MySQL、无 Docker、无 PHP** ⇒ 25 套验收中 23 套本轮无法复跑。

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

**仍未关闭**（环境依赖，不假装修好）：CRS PL1 4/8 与自动选链 4<8、显式 UNION 点 union 漏报、
fileWrite 环境侧闭环、vitest 大版本升级、Docker 上下文体积、远端 50+ 提交未推送。
