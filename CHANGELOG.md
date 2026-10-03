# Changelog

本项目版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 2026-10-04 批次 K · CI #143 新红定位：前端变异目标跑在没有前端依赖的 job 里

上一批把 CI 从「lint 红」修绿了，`test-server` 却**新红**（#143）：

```
✗ 基线未通过：src/shared/htmlSanitize.ts —— 先修测试再跑变异
Process completed with exit code 3
```

- **真根因（看 job 配置 + 实录，不猜）**：`test-server` job 只 `cd server && npm ci`，
  **没有装根目录 node_modules** ⇒ `./node_modules/vitest/vitest.mjs` 不存在 ⇒
  批次 J 新接进来的 frontend runner 连基线轮都起不来。
  此前 mutation 门禁只有 server 目标，所以这个依赖面缺口一直没暴露 —— 属于「批次 J 没改 CI」留下的半截。
- **修法（按职责分工，不靠加安装）**：给 `mutation-check.mjs` 加 `--runner=server|frontend`，
  前端目标挪到**已经 `npm ci` 过**的 `test-frontend` job；`test-server` 限定 `--runner=server`。
  比在 server job 里补装一套前端依赖快，且 job 职责不被稀释。
- **顺手补上一个真实缺陷**：脚本基线失败时把 `stdio: 'pipe'` 的输出**全吞了**，日志里一行测试输出都没有。
  这次只能把「文件名大小写 / 超时 / 依赖缺失」逐个排除才定位 —— 已改为打印测试输出尾部 40 行 + 运行器
  与常见原因提示。**门禁失败必须留下现场**。
- **验证**：`--list --runner=server` = 14 个目标 / `--runner=frontend` = 2 个；非法 runner ⇒ exit 2；
  **缺陷注入复验**：把过滤条件改成恒真 ⇒ `--runner=server` 变成 16（含前端）⇒ 注入后从备份还原，`cmp` 一致。

### 2026-10-04 批次 I · CI `test-frontend` 偶发红定位与修复（FLAKY-FIX）+ 复评结论更正

**先更正我自己复评里的一个错判**：v2 §四 #6 写「`--crawl` 是空壳，引擎层 `grep -c crawl` = 0」——
**错的**（照抄了未核实的旧结论，没回源码看）。爬虫**已实现且接通**：

- `engine/crawler.js`（187 行，`LinkCrawler` / `extractLinks` / `attrValue`）
  + `engine/discovery/browserCrawler.js`（headless 版，playwright 不可用时降级）；
- 消费点 `engine/TargetParser.js:200-215`（`crawlDepth > 0` ⇒ `_crawlLinks`，`crawlBrowser` ⇒ `_crawlBrowser`）；
- 参数 `scalarsCore.js:194`（0–3）+ `defaults.js:314`（默认 0）+ CLI `--crawl-browser`；
- 且 `crawlDepth` 已与 `--level` 解耦（`TargetParser.js:192-199`：原 `level>=5` 门槛会让它静默不生效）。
  ★ 教训（本项目第三次同类）：**「现状」类结论必须回源码核实**，连自己前一天写的评价都会过期。

**FLAKY-FIX**：`test-frontend` 在 CI 偶发红（#137），此前**没有日志通道**只能猜。本批用
GH_TOKEN 打通了 `actions/runs/{id}/jobs` + `actions/jobs/{id}/logs`（以前一律 Not Found，
是因为**缺认证**，不是接口没有），拿到真因：

- 失败用例 = `src/tests/scanPage.test.tsx > 显式关闭 enableExtract：直接发起，无二次确认对话框`，
  **`Test timed out in 5000ms`（实际 5544ms）** —— 是**超时**不是断言失败；
- 同文件另两条 4053 / 3460ms，`scanConfigSections` 多条 3.2–3.5s，都贴着 5000ms 默认线；
- 本机同一文件 8 条合计仅 **9.4s** ⇒ CI runner 上重渲染型用例比本机慢 **2–3 倍**。

修法：`vitest.config.ts` 加 `testTimeout: 15000`。**放宽的是天花板，不影响快用例**，
超时仍会红；不动用例写法，因为慢的是 `renderPage()` 的组件树渲染本身，不是等待策略
（`waitFor` 只在条件满足时返回，没有可省的轮询）。

- 缺陷注入复验（临时探针睡 6.5s，用完即删）：`15000` ⇒ **绿**；改回 `5000` ⇒ **红**
  （`Test timed out in 5000ms`）⇒ 证明该配置真的生效，不是"改了个没接线的键"。
- 附带产出：`D:\projects\_sqli-gitfix-2026-10-03\ci-job-log.mjs`（按 run 号 + job 名拉日志，
  落盘到本地）—— 以后 CI 红了不用再猜。

### 2026-10-04 收口 · 批次 J · 前端变异覆盖（承接并发会话在制品）

`scripts/mutation-check.mjs` 的守卫面从 server 扩到 `src/`（此前前端**零变异覆盖**，
503 条前端用例的断言是否敏感全靠信念）。本会话接手时代码已在工作区、**未登记**，本次补齐验证与记录。

- 新增 `runner: 'frontend'`（`baseDirOf()` 决定路径基准 = 仓库根）+ `runTests()` 双跑分派。
  ⚠️ 两个 runner 的单用例超时开关**不一样**：server 用 node `--test-timeout`（kebab），
  前端 vitest 用 `--testTimeout`（**camelCase**，写成 kebab 会被静默忽略 —— 「没报错」≠「生效了」）。
- 首批纳入 2 个模块（选入标准：安全关键 + 纯逻辑密集 + 离线专属测试）：
  `src/shared/htmlSanitize.ts`（报告 HTML 注入 DOM 的唯一闸门）、
  `src/shared/dumpExport.ts`（CSV 公式注入防护，挂 **4 个**真调用它的测试文件——少挂一个 = 假存活）。
- **验证（本会话实跑）**：`--file=… --limit=3` 两个目标 **6 变异 6 杀死 0 存活**
  （htmlSanitize 8.5s / dumpExport 19.2s），即新增目标确实有断言守护，不是拉进来充数。
- CI（`mutation` job）跑的是 `--limit=8`，本次为省时只在本地抽验 2×3 个位点。

### 2026-10-04 收口 · 批次 F2 · sqlmap 桥接模式补齐 file-write / diff / export（承接并发会话在制品）

TODO 2026-09-28 #3：**`capabilities.fileWrite` 声明的是内置引擎的能力，走 sqlmap 模式拿不到同一交付面**。
本会话接手时代码已在工作区、**未登记**，本次补齐验证与记录。

- `buildArgs()` 新增 `--file-write / --file-dest`：与 `--file-read` 同源门控（`isExploitEnabled()`），
  且 **fileWrite 与 fileDest 必须成对 + 本地文件必须存在 ⇒ fail-fast**
  （sqlmap 对此只会在输出流里报错，届时任务已"启动成功" —— 那是调用方视角的假象）。
- 新增纯函数 `diffSqlmapVulns()`（键 = `param::technique`，缺字段归一，畸形条目不崩）+ 
  `renderSqlmapMarkdown()`（Markdown 单元格 `|` 转义 —— 内容来自 sqlmap 输出解析，param 可能含任意字符）。
- 新增端点 `GET /api/sqlmap/:id/diff?base=<scanId>` 与 `GET /api/sqlmap/:id/report/export?format=json|markdown|md`
  —— 齐内置 `/scan/:id/*` 的契约：**缺 base / 任一侧不存在 ⇒ 显式错误，不静默返回空 diff；
  format 白名单外的 html/csv/sarif ⇒ 显式 400，不静默降级成 json**（那三种是内置渲染器的交付面，桥侧不假装支持）。
- **验证（本会话实跑）**：`sqlmapBridge.args` + `sqlmapRoutes` + `mutationGate.wiring`
  **52/52 PASS**（其中本批新增 15 条：fileWrite 门控 4 / diff 5 / export 4 / 纯函数 2）。
- ⚠️ 未验证部分（诚实边界）：`e2e/api-range-lab/cases.mjs` 新增的 2 条**正向用例**
  （`--file-write` 真写文件、文件系统侧断言）**依赖靶场 + 本机 sqlmap**，本机不具备且按规矩不起靶场
  ⇒ 判据交给 CI `e2e-self-contained` job；本机未跑，不算已验证。

### 2026-10-04 批次 H · 曝光层落地（评价 v2 新增的第四条建议）

复评 §五新增建议：「技术债已不是这个项目的瓶颈，**没人看得到才是**」。本批把它做掉。

- **`description` / `topics` 补齐**：此前 `GET /repos/...` 实拉是 `description: null`、
  `topics: []`、`homepage: null` ⇒ GitHub 搜索排序的最上游入口是空的，连第一屏都进不去。
  现已写入 166 字符描述 + 20 个 topics，并**读回远端真值校验**（不采信写请求的 200）。
- **数字全部从 README 派生，不手写**：GitHub 远端元数据**没有任何门禁能查**，手写即新增一个
  永久无人校验的声明点 ⇒ `scripts/set-repo-metadata.mjs` 从 README 功能表抽
  「N 种检测技术 / N 种数据库 / N 个 tamper 插件」，**抽不到就拒绝写入**（fail-closed）。
- **新增分层口径 `verified`**：描述原为「18 dialects」，容易被读成「18 种都验证过」，
  而 README 是 6 真机 + 3 部分通道 + 9 模板 ⇒ 改为 **`18 dialects (6 engine-verified)`**，
  且这个 6 同样由 `**N 种真实引擎全链路验证**` 派生（措辞一改 ⇒ 脚本拒绝写，不会静默过期）。
- **首个 Release `v1.1.0` 发布**（正文 5752 字符取自 CHANGELOG 该段）：此前仓库 0 个 Release。
- topics 挑选纪律：只选与 sqlmap / nuclei 话题面重叠且**不误导**的词，
  不写 `bug-bounty` / `exploit` 这类与产品定位不符的流量词。

### 2026-10-03 批次 G · 三处红一次收口：变异门禁接线守卫的路径基准 bug + 两个新端点补文档

评价 v2（§五 #1）列的「半批不收口，第三次复发」—— 三处红（服务端 2 fail / readme / facts）同源，本批一次收干净。

- **真根因不是「目标表腐烂」，是路径基准写错**：并发批给 `scripts/mutation-check.mjs`
  加了**前端**目标（`runner: 'frontend'`，路径基准 = 仓库根），而
  `server/tests/mutationGate.wiring.test.js` 的 ②④ 仍按老的「一律 `server/` 基准」拼路径
  ⇒ `src/shared/htmlSanitize.ts` 被拼成 `server/src/shared/htmlSanitize.ts` ⇒ 判据报
  「目标模块不存在」（这就是那 2 个 fail）。
  ⚠️ **两侧路径都以 `src/` 开头**（`server/src/engine/…` vs `src/shared/…`），
  光看路径分不出来 ⇒ 基准只能靠 runner 字段 ⇒ 新增判据 ⑦ 专门钉这件事。
- **修法**：目标表改按顶层 `{…}` 解析（先剥行注释再括号配对），每条带 `runner`
  （缺省 `server`）⇒ `baseOf(entry)` 决定基准；②③④ 全部改用条目基准校验，报错里
  带上 runner 与实际基准（下次再错能一眼看出是「模块没了」还是「基准错了」）。
- **新判据 ⑦**：前端形态（`.ts` 目标或挂载落在 `src/tests/`）**必须显式**写
  `runner: 'frontend'`；frontend 条目的挂载必须在 `src/tests/`（走 vitest）；
  另带提取器自证（解析出的条目数 ≥8 —— 目标表被整段改写时上面几条才不会拿空集合比）。
- **缺陷注入复验 2/2 杀**（均先备份、见红后用备份还原，未反向 replace）：
  ① 删掉 `runner: 'frontend'` ⇒ ②③④⑦ 4 红，报错直指「runner=server，基准 …/server」；
  ② 前端条目挂 server 风格路径 `tests/htmlSanitize.test.js` ⇒ ③⑦ 2 红。
- **端点文档收口**：`GET /api/sqlmap/:id/diff`、`GET /api/sqlmap/:id/report/export`
  此前**只在代码里注册**，README 端点表与 `docs/api.md` 都没写 ⇒ `readme:check` ⒁/⒁b 双红。
  已补，并把契约写全：`?base=<scanId>` 的 added/removed/unchanged 语义与 diff 键
  `param::technique`、缺 base 或任一侧不存在 ⇒ 显式错误码（不返回空 diff）、
  export 的 format 白名单只有 json/markdown/md（html/csv/sarif 属内置渲染器，桥侧 400 而非静默降级）。
- **facts 重采**：服务端 2833 用例 / **2830 pass / 0 fail** / 3 skip；前端 503；徽章 3333。
- 门禁 8/8 全绿（readme / facts / refs / arch / modules / targets / lint / typecheck）。

### 2026-10-03 批次 D · 严格同题 sqlmap 对标：23 关 × 3 轮取中位的定版报告（评价 P2-12 收口）

项目评价（2026-10-03）§六指出「P2-12 无严格同题对标 ❌ 未动」——旧报告是单轮数字，
单机抖动会带偏结论，撑不起强断言。本批给 `e2e/sqlmap-benchmark/run.mjs` 加 `--runs=N`
多轮模式并跑出定版口径：

- **方法论**：同靶点（23 关 sqli-labs，双方同题同档）双方各跑 3 次——检出取**多数决**
  （表格标注命中轮次 n/3）、耗时取**中位数**、技术取命中轮并集。N=1 时行为与旧版一致。
- **定版结果（level1 档，2026-10-03 本机）**：我方 23/23 = 100%（**每一关都 3/3 稳定命中**
  —— 检出判定零抖动）；sqlmap 14/23 = 60.9%；结论一致率 60.9%（仅我方 9 关 / 仅 sqlmap
  0 关 / 双方未检出 0）。命中场景中位耗时：我方 **116ms** vs sqlmap **2.2s**（约 19 倍）。
- 「仅我方」9 关的形态与旧报告一致（双引号闭合族 / 空格过滤 / UNION 过滤 / ORDER BY 族 /
  多过滤挑战）—— sqlmap --level=1 浅配置的已知弱项，本轮多轮复跑确认这不是偶然：
  9 关 sqlmap 全部 0/3。
- 产物：`docs/sqlmap-benchmark/sqlmap-benchmark-2026-10-03-level1-runs3.md` +
  `results-level1-runs3.json`（含逐轮命中数）。旧单轮报告保留不覆盖。
- 边界（诚实口径）：本基准是 SQLite 靶场 + sqlmap --level=1 浅配置；「比 sqlmap 强」的
  强断言仍需 redteam 真值集同题多轮（19 靶点对照目前分母不同，见评价 §三.B）—— 本批
  收的是「同靶点同档位多轮中位」这一半，另一半（redteam 同题化）留待后续。

### 2026-10-03 批次 F1 · 暂停闸下沉到扫描视图：detect.js 两支 ad-hoc 客户端不再绕过暂停

TODO 09-28 #4 的兑现（安全控制缺口：按暂停后 tamper 链验证与拦截驱动重跑照常打靶——
「目标报警了先停手」对这两条路径形同虚设）：

- **修复形态**：暂停闸下沉到 `getScanClient` 返回视图本身（request 与 headRequest 都过闸）。
  不动 detect.js ⇒ `detect.orchestration.test.js` 的 fake-sm 契约零改动（当初「在 detect.js
  里包 `_wrapWithSignal`」正是被它打回的）；`branches` 测试的 fake 显式补
  `_waitWhilePaused` no-op —— 契约缺件当场炸，不静默放行。语义与点边界一致：paused 阻塞
  轮询、cancelled 放行（stop 的在途取消由 signal 负责）、条目回收后放行。
- **单测** `scanClient.pause.test.js` 4 条：paused 期间 `view.request` 不发请求（靶站侧计数
  为准，不采信客户端自报）、resume 后放行；headRequest 同样过闸（--null-connection 探针
  不得绕过暂停）；cancelled 立即放行（收尾不被闸卡死）；源码钉住「detect.js 的 ad-hoc
  客户端必经 sm.getScanClient」+「闸挂在视图 request 上」（挂到别的层 = 本判定失效）。
  缺陷注入复验：撤闸 ⇒ ①红（杀）。
- **接口靶场**：新增 `/wafnum` WAF 前置端点 + 事件锚定用例。相位锚点 = SSE 第一发
  `point_testing(tamperRetry:true)`（重跑刚开始，暂停窗口必然落在重跑期内部，不受机器
  快慢影响）。⚠️ /wafnum 只拦**原始签名**、刻意放行 tamper 变换形态 —— 全拦光会让链验证
  3 条全废、引擎按「跳过自动重跑」收场，重跑根本不发生（首版踩过，案例见注释）。
  16/16 PASS；**靶场级缺陷注入复验：撤闸重跑 ⇒ 该用例红（15/16）**。
- 顺带修复的暗缺口：headRequest 此前在 ctxBase 包装层也不过暂停闸（--null-connection
  探针可在暂停期间继续打靶）—— 视图层的闸把它一并盖住。

### 2026-10-03 批次 7 · 全方面测试优化：查出一个真缺陷（sqlmap 桥 `retry=0` 被静默丢弃）+ 补齐该链零契约守卫

按 `unwired-helper-detection` 的方法做测试质量排查：从**逐文件覆盖率**找最弱项
（`SqlmapOptions.tsx` func 27.6% 离群）顺藤摸到 sqlmap 桥接链，发现一条**跨层漂移真缺陷**。

- **真缺陷（跨层漂移，`retry` 一个键三段三个域）**：`SqlmapOptions` 的重试控件写
  `Math.max(0, ·)`（可达 0），`types.ts` 明写「0 表示不重试」，内置引擎也真支持
  （`RequestControlSection` 的 Slider `min=0` + `core/http/retry.js` 明处理 `retry=0`）——
  但 `sqlmapBridge.buildArgs` 却写 `retry >= 1`，把 0 与负值一起丢弃 ⇒ 省略 `--retries`
  ⇒ **sqlmap 回落默认 3 次重试**，用户「不重试」的意图被静默推翻。
  实测复现：`buildArgs({retry:0})` → `--retries` 缺失。
  旧测试的注释写着「0 表示不重试 → 不生成」，可见误解源头：**省略 flag ≠ 不重试**（那是默认值 3）。
  修：改用 `c.retry == null || c.retry === '' ? NaN : …` 判「缺席」（与同函数 `ignoreCode` 同款写法），
  允许 0-10，`retry === 0` 时显式发 `--retries 0`。
- **新增跨层契约守卫 `src/tests/sqlmapConfig.contract.test.ts`**（4 条，源码级提取，不 import 后端模块图）：
  ① 每个 `SqlmapConfig` 键都必须被 `buildArgs` 读取（否则面板有控件 = 静默 no-op）；
  ② 每个键都必须有面板控件（否则类型加了键、用户永远设不了）；③ `retry` 三段都在的回归锚点；④ 提取器自证。
  **这条链此前完全没有契约守卫** —— 对照内置引擎那侧早有 `scanConfig.contract.test.ts`。
- **补齐面板逐控件契约测试**（`sqlmapOptions.test.tsx` +8 条）：此前 26 个 `onChange({键:值})`
  回调只有 8 个被点过。现按「patch 的**键名** + **值形态**」逐控件钉：
  retry 的 0/负/清空语义、`unionChar` 只留首字符、字符串类字段 trim 后空串回写 `null`、
  可空数值清空回 `null` 且有值是**数字不是字符串**、10 个布尔开关的**值必须是 boolean**
  （字符串 `"false"` 在后端是真值 ⇒ 关了等于没关）。
- **变异门禁新增目标 `hashAnalysis.js`**（`--passwords` 的哈希算法识别 + 弱口令标注）：
  21 处变异 **21 杀 / 0 存活**、5.8s ⇒ 断言敏感度合格（含「报告不回显原始哈希」这条安全边界）。
- **守卫自证又抓出一个真洞**（第二次栽在同一类）：`sqlmapConfig.contract.test.ts` 首跑的
  断言 ① 误报 `osShell`/`fileRead`「没被读取」。根因是我的 `stripComments` **先跑块注释正则**，
  而 `sqlmapBridge` 的注释里有 `… 与内置引擎的 /exploit/* 是同一个`，其中 `/exploit/*` 的 `/*`
  被当成块注释开头，**一路吞掉了 243–254 行的真实消费点**。
  修：**先行注释、后块注释**（行注释抹掉整条，`/exploit/*` 不复存在）；并把该陷阱写进自证用例。
  同批修正 `reportFormat.parity.test.ts` 的同款隐患（那里也是块注释在前）。
- **验证**：受影响测试（前端 30 / 服务端 29 / 变异门禁接线 6）全绿；**缺陷注入复验 5 处**，均先红后还原——
  还原旧 `retry >= 1` → 恰 1 红；去掉 `unionChar` 截断 → 恰 1 红；开关键写错成 `flushSession` → 恰 1 红；
  `c.retry` 写成 `c.retries` → 恰 ①②③ 中 2 红；面板键改 `unionFromGone` → 恰 ② 红。
- 门禁 8 项全 `exit 0`（lint/typecheck/arch:guard/refs:check/modules:check/facts:check/readme:check/merge:check）。
  前端 **503 用例 / 60 文件**（+12）、服务端 **2816**（2813 pass / 0 fail / 3 skip）、徽章 **3316**。
  前端函数覆盖率 77.86 → **83.06**（新面板测试真的点亮了此前从未执行的 handler）。
  ⚠️ `retry` 修复仅**单元级**验证；真 sqlmap 二进制跑 `--retries 0` 的实际行为待 CI/靶场。
### 2026-10-03 批次 6 · 暴露链：SARIF 接回前端导出 + 导出格式漂移守卫

延续批次 5 勘查登记里的「SARIF 未接前端导出」——按「本地可完整验证 + 真价值」取下一项。

- **缺口（`REST 有 → UI 无`）**：`sarif` 在后端全链早已就绪——`ReportGenerator.toSARIF` 有实现、
  `scanRoutes.js` 的 `FORMAT_EXT` 白名单收它、`content-types` 给了 `application/sarif+json`——但前端
  `ReportExport.tsx` 的 `ExportFormat` 联合类型与按钮都没有它 ⇒ **UI 用户永远拿不到** GitHub Security /
  DefectDojo 认的标准格式（只能走 CLI/API）。
- **修**：三处接线——`ReportExport.tsx` 补 `ExportFormat` 成员 + SARIF 按钮（`title` 提示去向）；
  `useScan.exportReport` 补类型联合成员 + `mimeMap.sarif = 'application/sarif+json; charset=utf-8'`
  （与后端 content-type 对齐，否则「另存为」会把 `.sarif` 当成匿名二进制）；`useScan` 顶部注释同步。
  文件名后缀天然为 `.sarif`（`fileExt` 逻辑无需特判）。i18n 补 `reportExport.sarifHint`（zh/en 对称）。
- **新增漂移守卫 `src/tests/reportFormat.parity.test.ts`**（源码级提取，不 import 后端模块图，沿用
  `scanConfig.contract.test.ts` 同款手法）：① 前端能请求的格式 ⊆ 后端 `FORMAT_EXT`（否则一点就 400）；
  ② `mimeMap` 覆盖 `ExportFormat` 每个成员（否则 MIME 为 `undefined`）；③ sarif 回归锚点。
- **守卫自证抓出一个真洞**：首版提取器**不剥注释** —— 把一行 `// sarif: '...'` 注释掉后四条断言全绿
  （等于没守住）。修：提取前 `stripComments`，并把「注释掉也必须抽不到」写成自证用例。
- **验证**：本批前端测试 19/19；缺陷注入复验 3 处（改错 sarif MIME → 恰 1 红；按钮不渲染 → 恰 2 红；
  联合类型塞 `xml` → 恰 ①② 红），均先红后还原；`lint`/`typecheck`/`arch:guard`/`refs:check`/
  `modules:check`/`facts:check`/`readme:check`/`merge:check` 全 exit 0。
  前端 491 用例（+6）、服务端 2816（2813 pass / 0 fail / 3 skip）、徽章 3304。
  ⚠️ 仅单元级验证；真上传 SARIF 到 GitHub code scanning 待 CI。

### 2026-10-03 批次 5 · 优化空间勘查：修 SQL 报错签名分叉 + WAF 推荐链落盘

按 `codebase-optimization-survey` 做的勘查（三条并行只读勘察 → 逐条回源码复核），
落 `docs/优化空间勘查-2026-10-03.md`。本批只动两条**文档未登记**的真缺口：

- **正确性（本批最值钱）**：`scanValidityGuard.js` 的 `SQL_ERROR_SIG` 与
  `engine/payloads/index.js` 的 `ERROR_SIG` **分叉** —— 后者 2026-10-01 收紧时加了
  `XPATH syntax error`（MySQL `extractvalue`/`updatexml`）、SQLite `near "x": syntax error`、
  DB2 `SQL0104N`，前者没跟。后果是一条静默误判链：error-based 用 extractvalue 打**有洞**目标
  → 500 全是 XPATH 报错 → 未判「自己触发的」（`core/scanValidityGuard.js:280`）→ 计入 `serverErr`
  → 裁定 `target_error` /「结论不可信」—— 正是 `P1-FIX 2026-09-08` 要防的告警疲劳，从这条缝漏了回来。
  修：补齐为 `ERROR_SIG` 同集；新增**漂移守卫**（`tests/errorSig.specificity.test.js`：同一
  `REAL_ERRORS` 语料两侧必须一致命中、`GENERIC_PAGES` 必须一致不命中，单向收紧即红）+ extractvalue 行为回归。
- **暴露链**：WAF 推荐 tamper 链此前**只走实时 SSE**（`finalize.js` 只 `eventBus.emit`），
  落盘的只有厂商（`summary.wafDetected`）⇒ 历史/导出的报告永远看不到「识别到 WAF 后建议用哪条链重跑」。
  修：`finalize` 落盘 `summary.wafSuggestedChains` → `reportDelivery` 取数（形状归一 + 过滤空链）→
  `reportSections` 的 md/html 渲染，`vendor`（目标可控）过 `mdCell`/`esc`。
- **勘查同时登记**（未改，留待下批）：SARIF 未接前端导出、`--identify-waf`/`--udf-*`/`--advise` 仅 CLI、
  3 个 REST 端点前端 0 调用、前端无 bodyJson 通道、`ctx.baseline` 死字段、`core↔engine` 包级环。
  性能类条目**全部标注为未量化推断**，不写任何请求数结论。
- **验证**：受影响测试 56/56；缺陷注入复验 3 处（还原窄签名 → 恰 2 红；`finalize` 落盘恒 false → 恰 ⑨a 红；
  去掉渲染 `mdCell` → 恰转义用例红），均先红后还原；`lint`/`typecheck:server`/`arch:guard`/`refs:check`/
  `modules:check`/`facts:check`/`readme:check` 全 exit 0。服务端 2816 用例（2813 pass / 0 fail / 3 skip）。
  ⚠️ 签名修复仅**单元级**验证，真靶场 e2e 待 CI。

### 2026-10-03 批次 4 · 交付面：官方 composite Action + `--passwords` 凭据风险标注 + 报告章节拆分

竞品对标（`docs/竞品对标分析-2026-10-03.md`）暴露的两条交付面缺口一次补齐，另按体积纪律清掉一个上帝对象。

- **官方 GitHub Action（补上 CI 定位的空位）**：仓库根新增 `action.yml`（composite）—— 一条 `uses:`
  跑完扫描 → 产出报告套件 → 上传 code scanning → 按退出码判红；15 inputs / 3 outputs。选 composite
  而非 docker/node20：仓库未发布（无 npm 包 / 镜像），`github.action_path` 指向 checkout 可直接构建。
  入口 `one-click-scan.mjs`，`--out` 取 `github.workspace` 绝对路径；SARIF 步 `if: always()` +
  formats 门控；enforce 步三态（0 绿 / 2 由 `fail-on-findings` 决定 / 1 恒红）。
- **`--passwords` 从「读到哈希」→「认哈希算法 + 标注风险」**：新增纯函数
  `extraction/hashAnalysis.js`（`classifyHash` / `analyzePasswords`），按**格式**识别算法
  （MySQL native / caching_sha2、PostgreSQL md5 / SCRAM-SHA-256、SQL Server `0x0100` / `0x0200`、
  bcrypt / argon2 等）并逐条标强度 / 风险；`extractScope` 派生 `passwordAnalysis`（原始 `passwords`
  串契约不变），`models` / `scanHelpers` 同步字段（含 resume 恢复）。**诚实边界**：判定完全离线、
  不联网、不爆破，报告**不回显原始哈希**（文件头写明）。
- **报告章节拆分（消上帝对象）**：`ReportGenerator` 的章节渲染器上提到 `reportSections.js`
  （**52 → 36.5KB**），`mdCell` 移入 `reportHtml` 并 re-export（既有导入路径不变）；报告新增
  「凭据风险」一节（md + html，账号 / 主机名过 `mdCell` / `esc` 转义）。无循环依赖。
- **文档**：`README.md` 补两行 feature（凭据风险标注 / 官方 GitHub Action）+ CI 段；`README.en.md`
  补英文对应段（按「数字只在中文 README 声明」的纪律，**不重复数字**）。
- **测试**：新增 46 条 —— hashAnalysis 20 / passwords 接线 7 / 报告凭据风险 9 / `action.yml` 接线 10
  （含自证守卫、每个 ARGS flag 都被 `parseArgs` 接受、inputs / outputs 引用闭合；不依赖 `yaml` 包，
  因 CI test-server job 只装 `server/node_modules`）。缺陷注入复验 3 处（`--technique` 拼错 /
  input `scope`→`scopes` / 移除 HTML 行 `esc(`），均见红后还原。
- **门禁**：lint / typecheck / arch:guard / refs:check / modules:check / facts:check / readme:check /
  merge:check 全绿；服务端 2805 pass / 0 fail。
- **口径更正**：`ops-runbook.md` 旧列「仍待拆 `extractionMaps.js` 56KB（按 DBMS 拆）」为过期信息 ——
  该文件 2026-10-01 已拆成 16 行 facade，`Exploiter.js` / `Detector.js` / `ScanManager.js` 亦已收口；
  实测 `server/src` 现无文件超 100KB / 1200 行。

### 2026-10-03 批次 3 · WAF 链侧能力：定向变异搜索器补「减标点补位 + 三链组合 + 有序去重」

评价文档（`docs/项目评价-2026-10-03.md` §七.3）定性：提打穿链数必须动**链侧**，不是再写
第 229 个 tamper。本批在 A2 既有架构（画像 → 语义索引 → 组合生成 → 探针验证）内修掉
生成器的三个真实质量缺口：

- **缺口①（最贵）**：`reducesPunct` 插件（dash2hash）covers=0，被 `.filter(covers > 0)`
  挡在候选池外 ⇒ **CRS 标点预算方向（942460/942431）唯一实证有效项**（wafRecommend 实测
  tamper on 2/5 → 5/5）从生成器里整体消失，实证首选链 dash2hash×hexliterals 不可能被产出。
  修法：消除者（covers>0）与减标点补位（reducesPunct）分池 —— 补位者不占定向名额
  （单独不产生单插件链），只作为第二/第三槽位与消除者组合，两个顺序都生成。
- **缺口②**：被拦词族 ≥3 时（典型 CRS 画像 quote+space+comment）双链覆盖不满。
  修法：**每类别取最优消除者**再跨类别组三链（⚠️ 不能用 pool 前 3 名两两配 ——
  quote 被拦时前几名可能全是 LITERAL 类，同类别互相 skip ⇒ 三链恒空），有界 ≤3 个三元组。
- **缺口③**：去重键用**排序后集合** —— 变换复合不可交换
  （hexliterals∘dash2hash ≠ dash2hash∘hexliterals，静态表实证两种顺序都是首选），
  旧键把两个顺序折叠成一条，静默丢掉另一序（`planChains.push` 与
  `mergeCandidateChains` 两处同改有序键；后者此前连**静态表自己的两种顺序**都会吃掉一半）。
- 语义边界不变：补位者不抢 covers（covers 仍只来自消除者）；机械检验扩展到新链形
  （声称的 covers 必须被整链真实消除，不采信自报）；validateChain 链级守卫照走。
- 预算纪律不变：纯函数零请求，验证总条数仍 MAX_CHAINS=3（2 静态 + 1 生成）。
- 测试：`waf.bypassSearcher.test.js` +4 条（补位两序 / 补位者不单独占名额 / 三链全覆盖 /
  新链形机械消除复验）。缺陷注入复验：撤掉补位实现 ⇒ 3 条新用例全红（杀）。
- 端到端：`waf-bypass-search` e2e ✅（A 档 2 条生成链进验证流程 / B 档 0 / 预算 6:6）；
  `waf-real`（CRS 执行器 PL1/PL3）exit 0、PL1 对外口径数字零变化；`tamper-matrix` exit 0。

### 2026-10-03 批次 2 · UI-REACH：拖库/提取治理 + 时间盲注标定 14 键接进面板（缺口 52 → 38）

`KNOWN_MISSING_UI_KEYS` 里真实价值最高的两组调优键接进 Web/桌面面板（引擎真读、REST 白名单
早已收、此前只有 CLI/REST 能设的键）：

- **拖库/提取治理 8 键 → DataExtractionSection**（`enableExtract=true` 才渲染 —— 提取没开时
  这些旋钮没有消费方）：`dumpRowLimit`（单次行上限）/ `dumpMaxRows`（每表硬顶）/
  `dumpStart`/`dumpStop`（行区间，对标 --start/--stop）/ `extractConcurrency` /
  `dumpConcurrency` / `dumpDatabaseConcurrency`（三级并发）/ `maxColumnsGuess`（列数上界）。
- **时间盲注标定 6 键 → RequestControlSection**（`timeThresholdMs` 旁边，同属时序判定）：
  `timeBlindSamples`（每对采样 3-10）/ `timeBlindCalibrate`（先标定链路固有延迟）+
  `timeBlindCalibrateMin` / `timeBlindSleepSec` / `timeProbeSleepSec` / `timeExtractSleepSec`。
  慢链路/高抖动目标上，默认样本会把真延迟稀释成「不可判定」→ 报告落「未检出」（假阴性）；
  加样本 + 先标定是对症手段，此前界面用户拿不到。
- 接线四件套：`SCAN_CONFIG_KEYS` + `SCAN_CONFIG_VALUE_TYPES`（13 number + 1 boolean）+
  `ScanConfig` 类型 + `handleIntInput` 处理器（空串/非法 ⇒ 删键，与「关闭态请求体省键」
  全局口径一致；范围 clamp 留在后端 scalarsCore 单点把守，前端只做输入提示不做复制校验）。
- i18n zh/en 各 +22 键；契约测试按判据 ⑤ 移出 14 键（登记表 52 → 38，能力类保持为空）。
- 缺陷注入复验：把已接线的 `dumpRowLimit` 塞回登记表 ⇒ 判据 ⑤（登记腐烂）红（杀）。
- 选键纪律：其余 38 键维持「显式承认的债」定性不动 —— http2/disableKeepAlive/xpAutoEnable
  等键接 UI 是产品决策（会把「一键扫描」人群无法自行验证的旋钮塞进面板），登记表让缺口
  可数即可，本批不越权替用户做这个决策。
- 前端 485/485 全绿（含契约 20/20），tsc 0 错误，lint 0。

### 2026-10-03 批次 1 · CI #131 双红收口：CLI 批量组桶断链（rateGroup 根因）+ 组桶生命周期补全

CI #131（`e2e-self-contained` 与 `acceptance` 两个 job）同根失败：batch-lab C1 限速判据
**3 目标 × 6 req/s ≈ 19.53 req/s（上限 6）**。取证（CI artifact）+ 速率账
（237 请求 / 12.5s ≈ 3 个独立桶，共享桶应为 ≥39.5s）锁定根因：

- **根因（交付级）**：`bin/cli/config.js` 的 `buildConfig()` 是显式键清单，CLI 批量生成的
  组 id（`rateGroup`）**没有透传** ⇒ `getScanClient` 拿到 undefined ⇒ 每个目标各建一个
  per-scan 桶，「整批共用一个令牌桶、总量 ≤ rate」的保证在 CLI 路径整体静默失效。
  REST 路径（scanGuard scalarsCore）一直是对的 —— 断的只有 CLI。本机没红是**被 CPU 掩盖**：
  引擎逐请求的处理开销把自然发包率压在判据之下，CI 的快机器才让它显形（与 09-09 代理
  假阴性同款教训：单机绿 ≠ 判据验过）。
- 修复：`buildConfig` 透传 `rateGroup`（值由 cli.js 内部生成，形态与 REST 收紧同口径）。
- **接线守卫补判据缺口（⑤b）**：原 ⑤ 只钉「CLI 生成了组 id 变量」，没钉「组 id 进了
  target.config」—— 又一次「登记 ≠ 有入口」。⑤b 改为**真调 buildConfig** 断言透传与
  缺省不造键；缺陷注入复验：注释掉透传行 ⇒ ⑤b 红（杀）。
- **_resolveRateBucket 惰性重建**：rateKey 查不到时不再静默回退 per-scan/rate 桶（回退 =
  总量保证在异常路径下悄悄失效），改为同 key 惰性重建继续共享。forScan 视图现在把
  `ratePerSec` 随请求注入 —— 单测抓出首版实现的重建成**不限速**桶缺陷（effectiveRate
  为 undefined ⇒ createBucket 归一为 0）后补的，重建速率与建桶口径一致。
- **组桶引用计数回收（防泄漏）**：`_disposeScan` 的 `removeBucket(scanId)` 删不到挂在组 id
  上的桶 ⇒ REST 长驻进程每跑一批泄漏一个 TokenBucket。forScan 注册（scanId→rateKey +
  组内计数），退役时 `releaseGroupBucket`：最后一个成员退役才删桶，先退出的不拆还在跑的
  成员脚下的桶。
- **CI 卫生**：acceptance job 的 WAF A/B 步骤会重写被跟踪的
  `e2e/waf-lab/results/compare-real.md` ⇒ 验收报告每次自陈「工作区 dirty，不对应任何提交」，
  版本凭证恒失效。步骤后 `git checkout --` 还原（`if: always()`）。
- 测试：`rateGroup.test.js` +4 条（惰性重建不回退/重建速率正确、引用计数三态、重复注册
  防御、删光后再入组）、`rateGroup.wiring.test.js` ②⑤ 更形 + 新增 ⑤b。
- e2e 实测：batch-lab C1 **237 请求 / 39.2s ⇒ 6.16 req/s**（上限 6，判据 ≤7.5），
  C2 对照 63.61 req/s（限制来自限速的证明），C3 动态吃满与总量保证均过，exit 0。
- 环境取证附记：本机 `~/.local/bin/env` 是吞参数恒 0 的空壳，`env -u …` 前缀的命令
  **从未真正执行**（本次会话实证）—— 靶场类命令直跑即可，引擎的 proxyBypassLocal
  默认豁免回环目标，系统代理不污染 127.0.0.1 靶场。

### 2026-10-02 批次（第八批）· headless 浏览器爬取（crawlBrowser，实战分析 P1-4）

SPA 目标（React/Vue/Angular）的静态 HTML 只有空壳——路由在前端、数据接口靠 XHR/fetch，
HTTP 爬虫（6 组标签属性正则）看不见 `/api/*`。新增 opt-in 的 `crawlBrowser`：

- `engine/discovery/browserCrawler.js`（新）：Playwright 渲染页面后收集三类发现——
  ① 渲染后同域链接（JS 动态插入的也算）；② 页面实际发出的 XHR/fetch 请求（**SPA 主
  发现面**：接口 query 参数直接成为注入点，无需人工抓包导 HAR）；③ 渲染后 DOM 的
  HTML（crawlForms 表单解析复用，JS 渲染出来的表单也收）。浏览器探测沿 e2e 既定模式
  （msedge → chrome → 自带 chromium），Playwright 动态 import（未安装/无浏览器 →
  **优雅降级 HTTP 爬虫**，不阻断发现）。资源护栏：总页数预算 10、每页导航超时 15s、
  只入队同域、browser finally 关闭。
- 合并层统一：`_crawlLinks` 与 `_crawlBrowser` 共享 `_mergeCrawlFindings`（链接/表单/
  端点三源同一口径防漂移）；端点静态资源过滤在合并层兜底重做（不信任上游收集器）。
  端点点位带 `viaBrowser: true` 溯源；无 query 的端点跳过（无可放注入值的位置）。
- 四层接线：TargetParser 6.55 步（与 precision 标记/onlyPoint 互斥）+ REST 白名单
  pickBool 严格布尔 + CLI `--crawl-browser` + 面板爬虫分段开关（zh/en）。
- 测试 9 条：纯函数（同域/静态/去重/协议）、注入式集成（viaBrowser 溯源、无参端点、
  默认关闭零调用、onlyPoint/精确标记跳过）、降级路径、**真浏览器 smoke**（本地 SPA 页
  JS fetch `/api/items?page=1` → 端点捕获成功，浏览器缺失按 SKIP 口径早退不假绿）。

---

### 2026-10-02 批次（第七批）· 实战小刀：acceptance 沙箱口径固化 + OOB UNC 通道修正

- **`acceptance:sandbox`**：`acceptance.mjs` 本就读 `MYSQL_*` 环境变量，经
  `run-with-sandbox.py` 包装（隔离 MySQL @3308）后 16/16 全绿——固化为一等 npm script
  并写入 README，宿主无 3306 MySQL 时的推荐跑法（直连口径 6 套件 BLOCKED）。
- **OOB UNC/SMB 通道修正**（实战分析 §2-P1-5）：UNC 类向量（MySQL/MariaDB/TiDB
  LOAD_FILE、SQL Server xp_dirtree）此前内嵌 `host:port` 回调地址——Windows UNC 主机位
  不含 `:port`，真实目标上永远解析不了（报文发了但物理上不可能回连）。模板改用 `{UNC}`
  占位符（裸主机 + share 名 `<host>\oob\<token>`，token 挪进 share 供外部 SMB 监听
  Responder/Inveigh 读出），HTTP 类向量（PG COPY PROGRAM / Oracle UTL_HTTP / MSSQL
  ping）不变；一阶 OobDetector 与二阶 SecondOrderDetector 同批修正。
- **通道边界显式化**：投放 UNC 向量时引擎 log 一次提示（内置接收端只听 HTTP+DNS，
  收回 token 的三条路径）；面板 OOB 分段新增 `oobSmbBoundary` 提示（zh/en）；README
  「诚实边界」补通道边界说明。
- **前端 flaky 定性**：`scanConfig.auth.test.tsx` 的一次偶发失败（facts 采集期）定性为
  环境性根因——`@esbuild/win32-x64` 平台二进制被 npm 包装器装成 POSIX 形态（无 .exe），
  `npm approve-scripts esbuild` + 重装恢复；用例连跑 8 次全绿，未改测试代码。

新增 6 条单测（oobUnc.test.js）；OOB 全家桶 36 用例全绿（含一阶/二阶/接收端回归）。

---

### 2026-10-02 批次（第五批）· 竞品吸收：paramMine 参数挖掘（对标 Arjun）+ 扫描预设（对标 ZAP）

调研 sqlmap/Arjun/Nuclei/ZAP 等同类项目并核差距后落地两项（全记录见
`docs/竞品对照与吸收-2026-10-02.md`）：

- **paramMine 参数挖掘**（opt-in `--param-mine` / 面板爬虫分段开关 / REST `paramMine`）：
  TargetParser 只能发现「已出现在 URL/body/表单里的参数」，隐藏参数（`?debug=1` 才进 SQL
  的那类）整体漏检。开启后对目标 URL 主动探测：内置 ~260 条字典按 30/组分组发送 →
  反射定位/响应差异 → 二分收敛 → 单参复核；请求预算硬顶 150，全回显/过噪目标防噪护栏。
  载体只认 GET/HEAD query 与 urlencoded POST；JSON/XML/multipart、精确标记（值尾 *）、
  onlyPoint 均保守跳过。挖掘点带 `mined: true` 溯源标记。
- **扫描预设 quick/standard/deep**：面板折叠头常驻 chips，一击切换检测强度
  （= 既有键的 patch 快照，零新配置键、后端零改动；standard 与 DEFAULT_CONFIG 对齐由
  测试钉死；刻意不含 paramMine——显式 opt-in 不被预设顺带打开）。

新增 17 用例（paramMiner 11 + scanPresets 6）；靶场电池全绿（pentest 11/11、
real-mysql 10/10、fullchain 全链路、api-range 46/46、acceptance 16/16 经沙箱包装）。

### 2026-10-02 批次（第六批）· 实战 P0 三件：NTLM 解禁 / 跳过统计进交付格式 / PoC 复核预期
承接同日《实战视角全面分析》（批次 10）的 P0 清单，三件小刀快跑（合计 ≈2 天估）：

- **NTLM CLI 解禁**（P0-1）：引擎 NTLMv1 Type1-3 握手早已完整实现（`ntlmAuth.js` 自带
  MD4+DES-L、`ntlmHandshake.js` 按 host 缓存，`e2e/ntlm-lab` 真机验证），CLI 却按
  「未实现」拒收——报错与引擎现状矛盾。`parseAuth` 放开 ntlm，凭据形态对齐
  sqlmap `--auth-cred`（`DOMAIN\user:pass`，domain 可省）；PKI 维持不支持（走 `--client-cert`）。
  `--auth-type` 帮助文本同步。REST 侧 auth 对象本就整体透传，无需改。
- **skippedPoints 进交付格式**（P0-2）：跳过点统计（有多少点没测、为什么没测）此前只有
  JSON 整包与前端逐点标注可见，导出的 md/HTML/SARIF 客户看不到。现于「结论可信度与
  本次抑制项」节渲染一行人话摘要（原因码→现场语义：预筛选/静态资源/输入校验/用户跳过），
  SARIF 挂 `run.properties.skippedPoints`（0 结果 ≠ 0 风险的防线）；无跳过时零噪声、
  旧报告向后兼容。
- **布尔/时间通道 PoC 附「复核预期」**（P0-3）：这两类通道的 PoC 复放后要靠响应差异判读，
  此前报告只有请求侧。现把检测器判定轮的**真实采样**（`trace.pairs[].true/falseSamples`、
  `trace.injectSamples/baselineSamples`，非预测、不发包）摘成一行进每条 PoC：
  真假响应 len+片段 / 基线均值+注入采样+判定阈值。union/error 等回显类技术不渲染（零噪声）。

新增 26 条单测（cli.auth 12 + report.skippedPoints 7 + report.pocVerify 7）。
教训留痕：help.js 帮助文本写裸 `DOMAIN\user` 使 `\u` 成为非法 Unicode 转义、
CLI 全族测试崩——帮助文本里的反斜杠必须写 `\\`（esbuild 同日出现平台二进制缺失，
`npm install` 恢复，与本仓代码无关）。

---

### 2026-10-02 批次（第五批）· 登录编排收口（批次14 在制品）+ 真靶场对照组 + 一处断言缺口

接手上一会话的**在制品**（批次14 实战 P1-6 登录编排）：`loginFlow.js` 与两个测试文件
已写完但**新文件未 `git add`**（本仓硬规则：新文件必须先 add 再跑门禁，否则 `refs:check`
与其它门禁看到的不是同一份工作区）。本批做三件事：补断言缺口、建真靶场、收口接线。

**① 缺陷注入抓到一处真缺口（不是形式主义）**

把 `performLogin` 的「响应仍是登录页 ⇒ 登录失败」这条启发式去掉（`stillOnLogin = false`），
**12 条用例全绿**。即：`ok` 这个返回值**没有任何测试直接钉住** —— 已有用例走的是包装层，
「凭据错误不重试」那条断言（`res.status === 401`）在注入后恰好仍成立，判不出来。
后果很具体：凭据错 / 被验证码打回时仍判「登录成功」⇒ 白重试一次，且 `withLoginFlow`
拿不到「重登失败」信号去收尾。

- 补 `performLogin` 三条直测：正确凭据 ok=true、**响应仍是登录页 ok=false 且 detail 点名原因**、
  401 ok=false。注入复验：**杀**。
- 另注入「重登失败也重试（会死循环）」⇒ 杀 1 条（这条原本就有覆盖）。

**② 真靶场 `e2e/login-lab`（deps:[]）—— 带对照组**

- 靶站：真 SQLite（sql.js）+ **真表单登录**（hidden csrf + 文本/密码框 + urlencoded 提交 +
  Set-Cookie）+ **会话用 6 次即过期** ⇒ 强制走「自动重登」路径。真 CLI 进程 spawn。
- 场景 A（给 `--login-url` + `--auth`）：退出码 2、**14 次成功自动重登**、
  靶站计数 200=79 / 401=125、points=1 **vulns=2**。
- 场景 B（**对照组**，不给 `--login-url`）：**0 检出**。
  ⚠ 这条反例是套件的命根子 —— 靶站若不真校验会话，A 会天然绿，整套件等于没验任何东西。
- 三处接线：`e2e/run-all.mjs` LABS（CI `e2e-self-contained` + `ci-local`）、
  `e2e/acceptance.mjs` SUITES（第 17 套件）、`server/tests/loginFlow.wiring.test.js`（7 条源码文本守卫：
  包装点 / guard 链 / REST 白名单 / CLI 三开关 / 前端类型 / **不得自建 HttpClient** / **凭据不落日志**）。

**③ 顺带修**：`ciWindowsOnly` 登记表行号又漂了（我插 login-lab 条目 ⇒ 191→195、259→263）。
上一批给守卫加的「**报失效时直接打印该 kind 当前的真实行号**」当场兑现：一眼拿到 195/263，
一次改对（此前要人工 grep）。

**④ 数字**：服务端 **2741**（2740 pass / 0 fail / 1 skip）· 前端 **485/485**（58 文件）· 门禁链全 0。

---

### 2026-10-02 批次（第四批）· OpenAPI **YAML** 目标生成（零依赖子集解析器）

承接第三批刚上线的集合目标生成：**OpenAPI 规范绝大多数以 YAML 流通**（Swagger Editor /
springdoc / FastAPI 默认导出都是 YAML），而解析器只认 JSON ⇒ 新能力在实战里等于没通。

- `server/src/core/yamlLite.js`（新）：零依赖 YAML **子集**解析器。支持嵌套 map、
  序列、`- key: value` 的序列项、行内流式 `[a,b]` / `{a:b}`、引号标量、数字/布尔/null、
  URL 里的 `#`（不是注释）、文件开头的 `---`。
- ⚠ **硬边界：解析不了就整体拒绝并给原因**（锚点 `&` / 别名 `*` / 标签 `!!` / 块标量
  `|` `>` / 合并键 `<<` / TAB 缩进 / 复杂键 / 多文档）。**半解的 YAML 会展开出错的请求**
  （少参数、少路径）⇒ 静默少测目标，比明确说"请转 JSON"危险得多。
- `requestCollectionParser` 的 `openapi-yaml` 分支由「一律请转 JSON」改为「尝试展开，
  失败则报原因 + 保留转 JSON 建议」；`batchTargets` 把该格式从 URL 列表分支挪进集合分支。
- 服务端 **19 条**新单测（13 解析器 + 6 展开层）。**缺陷注入 2 次杀**：序列项不合并后续
  同项字段（杀 3）、摘掉锚点规则（杀 1）。
- 真靶场：`e2e/batch-lab` 增加 YAML 场景 ⇒ 展开 2 目标、**2 条真检出**、报告落盘 2 份。
- 口径订正（交付文档 §7.8）：per-scan **独立令牌桶早就有了**（`forScan` 按 scanId 建桶），
  真正缺的是**跨目标动态份额再分配** —— 上一版文档把这两件事混写成"独立桶未做"，已改。

---

### 2026-10-02 批次（第三批）· 批量编排收口（故障隔离）+ 集合目标生成（对标 sqlmap 2.0 OpenAPI）+ 「0 注入点」假阴性修复

来源：接手上一会话的**在制品**（`batchPool.js` 已写、`cli.batch.test.js` 与 `e2e/batch-lab/`
已写但未接线未提交），以及竞品坐标核实：ghauri 的批量**明确没有故障隔离**
（"One unresponsive target can stall the entire queue"）、`-m` 只吃文本 URL、`-r` 只吃单请求；
sqlmap 2.0(WIP) 正在做 **OpenAPI 目标生成**。本批把三件合流。

**① 批量编排收口：故障隔离 + 结果不丢 + 摘要点名**

- `server/bin/cli/batchPool.js`（新）：并发池 `runPool` 单个 worker 抛错**不中断整批**；
  `runBatch` 把失败目标点名进 `failures`，成功目标的报告照常进 `results`；
  `summarizeBatch` 给出 ok/failed/needsReview/byRisk/hasHigh/allFailed。
- **退出码三分**：有高危 → 2（既有语义不变）；**全批失败 → 1**（与「扫了但没高危」区分开）；
  部分失败仍 0（失败已在摘要里点名）。
- `-m` 与 `-l` 两条批量路径由「两处粘贴复制的池」收敛到同一份实现。
- 新增 `needsReview` 通道：报告产出了但**一个检测请求都没发**（0 注入点）的目标单独点名 ——
  批量里这类最会骗人（退出码与成功目标一样）。

**② 集合目标生成：`-m` 从「只认 URL 列表」扩到「也认请求集合」**

- `server/bin/cli/batchTargets.js`（新）：`expandBatchTargets()` 自动识别
  Burp XML / HAR / Postman / OpenAPI(JSON)，展开成 N 个目标，逐个保留 method/headers/body。
  此前这三样各在一处：集合解析只服务 `-r`（**且只取第 1 条**）、`-m` 只吃文本 URL ⇒ 断的。
- **跳过并点名**（而不是硬扫）的三类：非 http(s) 协议（解析器经原始报文往返会把它静默补成
  http，扫出来的就不是用户写的那个目标）、`multipart/form-data`（JSON 化会塌成垃圾键，见 TODO §O）、
  无法转 JSON 的 body。理由：带着坏 body 去扫 POST 端点 = 0 注入点 = 根本没测。
- **真机抓到的缺陷**：urlencoded body 留到扫描期才 `JSON.parse` ⇒ 整条目标崩
  （`Unexpected token 'a', "name=alice" is not valid JSON`）。修法是把 body 的 JSON 化
  **前移到展开期**（复用 args.js 的 `bodyToJsonString`）。
- 「识别成什么格式、展开几个目标」一律打到 stderr —— 静默降级是本仓反复踩的坑。

**③ 「0 注入点」= 不可判定：结论层终于消费 `noInjectionPoints`**

- `scanRunner.js`：0 注入点且无命中 ⇒ verdict 写 `inconclusive`（此前恒写
  `no_vulnerability_detected`）。实战形态：批量扫 100 个目标，30 个不通 ⇒ 每个都产出
  points=0 的报告，使用者读到的是「这 30 个站没有注入」——**把「根本没测」写成安全结论**。
  `discover.js` 早就打了这个标记，结论层一直没消费它。
- 文案与「测过但网络/会话不可靠」分开给（前者要人确认可达性/注入面，后者要人复扫未决点）。

**④ 靶场与门禁**

- `e2e/batch-lab/run.mjs`（新，deps:[]）：真 SQLite（sql.js WASM）靶站 + 真 CLI 进程。
  A 场景：3 目标混 1 死目标 ⇒ 报告 3 份全落盘、死目标 verdict=inconclusive、摘要点名。
  B 场景：OpenAPI 展开 2 目标（2 条真检出）+ HAR 的 POST 表单（body 保住，points=1 vulns=2）。
- 三处接线：`e2e/run-all.mjs` LABS（CI 的 `e2e-self-contained` job 与 `ci-local` 都跑它）、
  `e2e/acceptance.mjs` SUITES（第 16 套件）、`server/tests/batchLab.wiring.test.js`（源码文本守卫，
  防条目被删 / 断言被放宽 / CLI 不走新模块）。
- **缺陷注入 8/8 杀**（注入前 `cp` 备份、还原用备份并 `cmp`）：
  scanRunner 的 `nothingTested` 置假（杀 1）／runPool 去 try-catch（杀 1）／
  needsReview 不填（杀 1）／allFailed 去掉「成功数为 0」这一维（杀 1）／
  batchTargets 恒走 URL 分支（杀 4）／丢非 http(s) 协议守卫（杀 1）／丢 cookie 映射（杀 1）。
- 顺带修：`ciWindowsOnly` 登记表行号漂移（186→191、254→259，我插 LABS 条目导致下移），
  并按 TODO §8 的建议让「登记项失效」的报错**直接给出该 kind 当前的真实行号**（省一次 grep）。
  另修 `bespokeKeys.js` 一处死 import（`defaults`，eslint 0 的前提）。

**⑤ 数字**：服务端 **2646**（2643/0/3）· 前端 **475/475** · 徽章 3118 ·
门禁 lint/typecheck(双端)/arch/refs/modules/targets/merge/readme/facts 全 exit 0。

---

### 2026-10-01 批次（第二批）· XML/SOAP body 通道（竞品对标 ghauri）+ clientCert 接 UI + 接口靶场 46/46

来源：竞品对标体检（sqlmap / ghauri / jsql 三条线）与本轮「用自建靶场把全套跑一遍」。
三条线各自的结论：**JSON 嵌套早就有了，同类的 XML 形态完全空白** —— 政企/金融老接口
（SOAP 1.1/1.2、XML-RPC、`application/xml` 内部网关）body 是 XML 时，此前只能把整份 XML
当一个 body 参数 ⇒ 注入值从未进 SQL ⇒ 静默 0 检出。

**① XML / SOAP body 通道（新增能力）**

- `core/xmlBody.js`：零第三方依赖的「元素 + 文本」解析器 + 叶子路径发现 + 按路径写值 + 序列化。
- `TargetParser` 3.55 步发现叶子注入点（param 用点路径，如 `soap:Envelope.soap:Body.GetUser.id`，
  同名兄弟加数字下标），`injection.js` 在 **body 分支最前面**接管写回 —— 顺序是关键：
  晚一步就会被表单分支摊成 `路径=值` 的 urlencoded，只吃 XML 的目标一个字段都解析不到。
- 入口三端齐全：REST `xmlBody`（字符串 ≤10KB）、CLI `--xml-body` / `--xml-body-file`、
  `createTarget` 透传。（JSON 通道 2026-09-08 就三端齐备，这次是补齐它的同族。）
- **保守边界**：注释 / CDATA / DOCTYPE / 正文处理指令**整体放弃**（`ok:false` → 0 注入点）；
  只剥开头的 XML 声明（真实 SOAP 报文每条都有，不剥就等于在真实目标上 100% 放弃）。
  属性不做注入点（SOAP 参数都在元素文本里）。
- 服务端 14 条单测（10 解析器/发送形态 + 4 CLI 接线，后者走 `runSingleScan` 捕获真 input）。
  **缺陷注入 3/3 杀**：去掉 injection 的 XML 分支（杀 1）／TargetParser 不标 `xmlPath`（杀 2）／
  序列化不转义（杀 2）—— 注入前 `cp` 备份、还原用备份并 `cmp` 逐字核对。

**② clientCert（mTLS）接进 Web 面板 —— 收口上一批的半成品**

- 后端（clientCert.js / agentFactory / REST 白名单 / CLI `--cert`）此前已写好但**前端没有入口**，
  前端契约守卫 ④⑥ 因此红 2 条。现接进「授权范围与传输安全」分段（与 `insecureTls` 同段、
  语义正交：一个管「我信不信目标」，一个管「目标信不信我」），登记 `SCAN_CONFIG_KEYS` +
  值类型 `string` + 中英文案。前端 475/475。

**③ 接口靶场（`e2e/api-range-lab`）本轮从 31/46 修到 46/46 —— 三处都是既有欠债**

- **429 假红**：09-30 上线的分钟级限流（10 次/分）把一轮 40+ 次扫描打成 429，表现是「用例大面积红」，
  真相是护栏在正常工作、靶场没给它让路。主实例显式放宽 `RATE_LIMIT_SCAN_MAX/EXPLOIT_MAX=500`；
  ⚠️ 限速本身仍被专项用例钉住（那条用的是**独立实例** `EXPLOIT_RATE_PER_SEC=1`，不受影响）。
- **1007 假红**：利用端点要求 `body.scope`（授权范围红线），`exploitBody()` 没跟 ⇒ 撞的是红线不是被测能力。
- **6005 假红**：`file-write` / `os-shell` 是写类操作，缺 `confirmDestructive` 被护栏拦在能力判定之前，
  ⇒ `data` 空对象，「失败必须给出原因」看到的是空壳。
- 新增真靶点 `/soap`（真 MySQL + 真 XML 请求/响应）+ 2 条用例（正向检出 + 非法 XML 保守不发现）；
  `needsDb` 补 `xml` 组（否则靶站根本不起，报的是 ECONNREFUSED 这种会误导人的错）。

**④ 真靶场取证**

- `python e2e/run-with-sandbox.py e2e/api-range-lab/run.mjs` → **46/46 PASS**（隔离 mysqld @3308）。
- XML 用例的判据不采信接口自报：先手动打靶站 `/soap` 证明端点真查库回显，再要求引擎报告里的
  注入点是**叶子点路径**且真检出漏洞，最后用靶站侧 `__range/stats` 确认请求真的到了 `/soap`。

### 2026-10-01 批次 · 台账保留策略 + History 页改服务端数据源

两项都属于「能力早就写好了，但没接到用户手上」的缺口（TODO 接口靶场遗留第 1 / 第 5 条）：
服务端有 `GET /api/scans`，Web 页没接；台账会一直写，没有任何收敛手段。

**① 台账保留策略 `SCAN_LEDGER_MAX` / `SCAN_LEDGER_MAX_DAYS`**

- 长期运行的实例台账只增不减。`pruneLedger()` 在 `recordScan()` 之后自我收敛；CLI 另补
  `ledger prune --max=<N> / --days=<N>` 手动入口（**没有任何策略时 exit 2 拒绝执行**）。
- **默认关闭**：扫描产物是有损删除，不能因为升级静默清掉历史。两维都未设 ⇒ 一条不删。
- **顺序刻意是「先原子重写索引、再删目录」**：反过来时，目录删成功而索引重写失败 ⇒
  列表里有、点开 404（半份数据）；现在的顺序下失败模式是磁盘泄漏 + 孤儿目录，列表干净、可重试。
- 淘汰是目录与索引**成对**消失，并要求 `readReport` 真的返回 null ⇒ `/scan/:id/report` 走 404。
- 顺带治掉 `appendFileSync` 造成的重复登记（同 scanId 索引多行 ⇒ 列表出现两条同名条目）。
- CLI 的 `--max` / `--days` 在 `args.js` 里显式登记为「已知但不消费」—— 否则会被记成
  unknownFlag 打印「不会生效」，而它其实是生效的，这条警告会变成在骗人。
- 服务端 10 条 + CLI 1 条单测。**缺陷注入 6/6 杀**：只删索引不删目录（杀 5）／不重写索引／
  缺时间戳伪装成最新／天淘汰方向反／切断 recordScan→prune 接线／早退跳过去重 —— 各杀 1~5 条。

**② History 页：由 localStorage 改为「服务端为主 + 本地兜底」**

- 此前换机器 / 换浏览器 / 清缓存，历史就空了（同一批扫描在 CLI 那边一直看得到）。
- 合并规则见 `src/shared/historyMerge.ts`：同名条目服务端行胜出做展示，**但保留本地快照引用**
  （续跑要读 `report.target.config`，服务端清单只有摘要）；来源以 Chip 明示 `服务端`/`进行中`/`仅本机`。
- 服务端缺 `riskLevel` ⇒ 台账 meta 新增 `highestRisk`（取最高、只认四档规范值）；
  **老台账没这个字段 ⇒ UI 显示「风险未知」，不猜不兜底 `Low`**。
- 服务端取不到清单时退回本地列表并如实提示，不允许出现比改造前更差的白屏。
- 纯服务端条目不给删除按钮（服务端没有 DELETE 端点，给了按钮点了没反应等于骗人）。
- 前端 11 条单测（7 条纯函数 + 4 条组件）。**缺陷注入 3/3 杀**：组件不接服务端数据 ⇒ 3 条红；
  `riskLevel` 兜底成 `'Low'` ⇒ 2 条红；丢掉本地快照引用 ⇒ 1 条红。

**⚠️ 顺手修了一个接管前就已存在的损坏**：`server/src/engine/extractionMaps.js` 处于语法错误
状态（上一轮把 `SYS_QUERIES` 往 `server/src/engine/extraction/sysQueries.js` 迁时，
`LEN_FN` 的起始行被一起删掉，且新文件自身也没闭合 `LEN_FN` ⇒ 两边都不可解析，服务端
138 个测试因模块加载失败全红）。已 `git checkout HEAD` 恢复可用版本，两份半成品各自留档在
`logs/tmpdiag/extractionMaps.BROKEN.js.bak` 与 `logs/tmpdiag/sysQueries.quarantine.js`，**未销毁**。

- 门禁：lint ✓ typecheck(双端) ✓ arch ✓ refs ✓ facts ✓ readme ✓；服务端 2577（2574 pass / 0 fail / 3 skip）· 前端 472/472。

### 2026-09-30 批次 · httpClient 四期拆分：TLS/代理 Agent 工厂独立成模块

按「先搬无状态符号、再 re-export 回原文件」的顺序，把 `httpClient.js` 里的**模块级基础设施**
（零 `this` 耦合）迁到 `core/http/agentFactory.js`：axios 侧 keep-alive 单例、按
`{insecure, keepAlive}` 组合缓存的 Agent 工厂、代理 Agent 缓存（HTTP/SOCKS）。

- **零行为变化**：`httpClient.js` 保留 `agentsForTls` / `buildProxyAgent` 同名再导出，
  既有 import 路径（`p2.test` 等）全部不变。文件 63.5 KB → 58.6 KB。
- **为什么值得单独拆**：这段是**安全语义的承载点** —— 共享 `httpsAgent` 一旦被 insecure 组合
  复用，等于「一个自签目标关掉了全局证书校验」（原文件头部注释的原话）。此前只能经
  `httpClient.p2.test` 间接覆盖，抽出来后可以直测：① 默认组合复用共享单例、② insecure 组合
  新建且 `rejectUnauthorized=false`、③ 缓存按双维 key 不串用、④ 代理 socks 分流 /
  内嵌凭据解码 / insecure|secure 分 key 缓存。
- 新增 `server/tests/agentFactory.test.js`（6 条）。
- 缺陷注入 **2/2 杀**：secure 组合改为每次新建 ⇒ ① 红；缓存 key 去掉 keepAlive 维度 ⇒ ③ 红。
- 门禁：typecheck:server ✓ lint ✓ refs ✓ arch ✓ facts ✓；服务端 2577（2574 pass / 0 fail / 3 skip）。

### 2026-09-28 批次 · 接口靶场：26 条 HTTP 端点逐条在真 MySQL 靶站上验收

此前的 e2e 几乎都 `import ScanManager` 直接驱动引擎，接口层（Express 路由、SSE、导出、鉴权闸门、
利用、AI 外发、台账）从来没有一套"只走 HTTP + 真库靶站"的验收。补上 `e2e/api-range-lab/`
（44 条用例，本机沙箱 MySQL 8.0.28 上 44/44、21.6s），并把它挂进 `e2e/run-all.mjs`
与 `npm run e2e:api-range`。这套靶场的判据是**靶站侧计数**而不是接口自报，一轮就抱出 9 条接口层缺陷：

- **`GET /api/health` 的版本是写死的 `1.0.0`**，包早已 `1.1.0`；而 `server/tests/engine.e2e.test.js`
  把这个过期字面量**断言成契约** ⇒ 升版必红一条"看起来像产品坏了"的用例。改由
  `core/version.js` 与 package.json 同源（① `ENGINE_VERSION` ②根 ③server ④如实报 unknown），
  测试改为比对同一个来源。health 另补 `authEnabled/exploitEnabled/node` 等运维真正要看的布尔与计数。
- **`GET /api/scan/:id` 快照里没有运行态**：`status` 记在扫描条目上而不在报告里，于是
  "在不在跑 / 有没有暂停"在 HTTP 层只能靠 SSE 长连接推断，`pause` 的返回成了自证。
  新增 `ScanManager.status()` 并在快照里同时回 `status` 与 `state`（sqlmap 侧 /report 早就带 status，
  两个引擎的契约就此对齐）。
- **暂停不冻流量**：`pause` 此前只在 `scan/detect.js` 的**点边界**生效，而一个点是几十上百个包
  （实测按下暂停后 2.6s 内靶站又收到 5 个请求）。把等待下沉到唯一的请求出口
  （`scanRunner.js` 的 ctxBase 包装层），暂停期间真的一个包都不发；测试以靶站计数为准。
- **`POST /scan/:id/stop` 三态不分**：未知 id 也回 `code:0 + {stopped:false}`，且会把**已完成**的
  扫描状态改写成 `stopped`（交付报告里一次正常跑完成了"被人中断"）。改为未知 → `2001`、
  终态 → `alreadyFinished` 且不动状态机；`/sqlmap/:id/stop` 同口径对齐（并同步改掉钉住旧语义的用例）。
- **`format=db-json` 在没拖库数据时回 200 + `"null"`**（4 字节附件），用户读成"导出坏了"。
  改为 400 + 指明下一步（带 `config.extractScope` / `enableExtract` 重扫）。
- **`cookieParams` / `headerParams` 静默不测**：cookie 需 `level≥2`、header 需 `level≥3`，
  低 level 下调用方传了参数却 0 点位、报告写"未检出"。现写入 `report.summary.constraints`
  （与既有"被抑制能力必须可见"机制同源），用例同时做正反两档断言。
- **`config.extractScope` 是半截功能**：2026-09-23 收进白名单，但引擎只在 `enableExtract` 为真时才
  进提取阶段 ⇒ REST 传枚举参数拿到 200 + 空 `data`。按 CLI 既有口径（`enableExtract: args.dump || enumActive`）
  在配置守卫里补齐这条隐含关系，真库枚举/拖库在 API 侧第一次端到端可用。
- **利用接口只能"手搓点位"**：`/exploit/*` 要求调用方自己拼 `target+point`，前端利用页因此把
  `location` 硬编码成 `url`、让用户手抄 `originalValue`（body/cookie/header 与编码点位必然失真）。
  新增 `scanId`(+`pointId`) 形态：服务端从扫描上下文解析 target/point/dbms 并**沿用该扫描的
  HttpClient**（cookieJar / auth / CSRF / 限速桶），响应回 `resolvedFrom` 说明实际用了哪个点位；
  前端利用页与报告页「在利用台打开此点位」接线到这条路径。
- **`ok:true` 却取不到值**：`Exploiter.sqlShell` 对 SELECT 恒回 `ok:true`，即使标量提取为空。
  改为「投递」与「取到值」分离（`ok:false + delivered:true + 原因 + 下一步`），CLI 与接口同步受益。
- **两个安全口径缺口**：① `SSRF_ALLOW_PRIVATE=1` 把 `169.254.0.0/16`（云元数据）等**基础层**一起放行，
  与 `egressGuard.js` 文件头"基础层无条件拒绝"的承诺矛盾（改：基础层不受该开关影响，
  确要点名放行用 `SSRF_ALLOW_CIDRS`）；② sqlmap 入口 `--os-shell/--file-read` 不受
  `EXPLOIT_ENABLED` 约束，而内置 `/exploit/*` 受 ⇒ 同一双刃剑能力两个入口一半有闸（共用
  `core/exploitFlag.js`），且 `/sqlmap/start` 完全不读 `scope`（现与内置引擎同红线校验）。
- **scope 不支持 `host:port`**：`127.0.0.1:8140` 被整串当主机名 ⇒ 永不匹配，而报错又把同一串
  回显成"当前范围"，看起来像判据坏了。现支持带端口规则（主机相等 **且** 端口相等，只收紧不放宽），
  端口不符时报错明确差在端口。
- **接口侧完全没有服务端历史**：台账（`scanLedger`）只有 CLI 在写，REST 一条不落；而扫描上下文
  完成后 30s 回收 ⇒ `GET /scan/:id/report` 在真实交付里迟早变成"扫描不存在"，Web 历史页其实是
  浏览器 localStorage。本批：API 扫描终态自动落台账（`SCAN_LEDGER=0` 可关）、`/scan/:id`、
  `/report`、`/report/export`、`/diff`、复测基线全部支持台账回读并如实标 `source: ledger`，
  新增 `GET /api/scans`（台账+在途合并，需 token），回收窗口改为可配 `SCAN_RETIRE_TTL_MS`。
- **`.env` 里的开关读不到**：`index.js` 的 `dotenv.config()` 排在 import 之后，被 import 的模块在
  加载期取的环境变量一律为空（`EXPLOIT_ENABLED=1` 写进 `.env` 不生效，而 `.env.example` 正推荐这么配）。
  抽出 `core/loadEnv.js` 作为第一条 import，并把利用开关改为每次请求现读（与 sqlmap 桥共用同一判据）。
- **门禁驱动层的两处自伤**：44 个 e2e 脚本的超时分支写成 `sm.stop(scanId).catch(()=>{})`，
  而 `stop()` 返回布尔 ⇒ 超时即 TypeError（不是"如实报超时"，是当场崩），已批量改为直接调用；
  `facts-sync` 的前端解析只认 `N passed | M failed` 词序，而 vitest 失败时输出 `1 failed | 451 passed`
  ⇒ 一条真用例失败被洗成"找不到 Tests 行"，改为两种词序都解析并如实记录 pass/fail/skipped
  （本轮据此暴露出 `scanPage.startFailure` 在覆盖率档稳定超时，按其实际耗时把预算钉到 20s）。
- 文档：`docs/api.md` 全面改写受影响章节（健康检查、`/scans`、快照运行态、停止三态、导出失败形态与
  7 种格式、`scope` 全部写法含 `host:port`、`extractScope` 与 `enableExtract` 的耦合、参数级别与
  "给了没测"、利用两种入参形态与结果口径）；README 新增「接口靶场」小节并把端点表补齐 26 条。

### 2026-09-28 批次 · 真机 WAF 对拍从「放行率」升级到「打穿率」

首轮真机对拍（09-27）只证明了「WAF 放行」——靶站是 echo 后端，不碰数据库，所以那时的诚实边界
写着「放行 ≠ 能打穿，禁止对外声明绕过率」。本批把那一环补上：同一条样本要同时满足
①过了 WAF ②后端真 MySQL 真执行了注入并吐出证据，才记为一次「打穿」。

- **靶站真库化**（`e2e/waf-real/modsec-target.mjs`）：新增 `MODSEC_TARGET_DB=1` 模式，把 id
  **原样拼进** `SELECT ... WHERE id = <id>` 交给真 MySQL 执行，结果与错误都回显。
  ⚠️ SQL 执行失败也回 **200**（body 前缀 `SQLERR:`）：若用 5xx，对拍脚本的「非 2xx = 被 WAF 拦」
  会把「到后端了但 SQL 报错」误算成拦截——与「依赖真库但环境没起库 → ECONNREFUSED 被记成
  产品 FAIL」是同一类假象。另加 `SET SESSION max_execution_time=1000`（SLEEP 样本不拖超时）
  与 `/__mode` 探针（让对拍脚本能判定本轮口径是放行率还是打穿率）。
- **判据分层并抽成可单测模块**（`e2e/waf-real/pwnVerdict.mjs`）：`blocked / echo / reached_sql /
  pwn_result / pwn_error / unknown`。两条防假绿纪律：结果集证据**必须** `ROWS:` 前缀
  （echo 后端会原样回显 payload，任何「body 里出现 payload」形态的判据在它底下恒真）；
  报错证据只认 MySQL 自己生成的短语（`XPATH syntax error` / `Duplicate entry`）。
- **加直连通道量「可打穿上界」**（`modsec-live.mjs`）：绕过 WAF 直接打靶站，得到「每条样本本身
  能打穿到什么程度」。这才能把「变形把 payload 语义弄坏了」与「WAF 真拦住了」分开 ——
  打穿率的分母是上界而不是样本总数。上界为 0 时硬失败（此时「经 WAF 打穿 0 条」不能归因于 WAF）。
- **降级必须是可见的失败**：CI 里设 `MODSEC_REQUIRE_DB=1`，库没起来 / 靶站退回 echo 模式
  → 对拍脚本 exit 1，不接受一份看着正常的「放行率」报告冒充绕过能力。
- **CI 实测（run #97，job `modsec-live` success，18 步）**：靶站 `模式 db`、直连打穿上界 1/8；
  PL1 与 PL3 真机**打穿**插件各 **1** 个（`unionvaluesrow`），同口径**放行**的是 8 个 ——
  「放行 ≠ 打穿」第一次被量化（差 **8 倍**）；安全对照 0 误拦。
  ⚠️ 上界只有 1/8 ⇒ **仍禁止对外声明绕过率**（分母是 1，无统计意义）。与首轮 74/72 不可直接比，
  且存在一处**未解释差异**（首轮同口径报 74、本轮 8）已登记待查。
  见 [docs/WAF-真机对拍-2026-09-28.md](docs/WAF-真机对拍-2026-09-28.md)。
- CI job `modsec-live` 接 `mysql:8.0`（复用 acceptance job 的 docker run 起法）并等待就绪，
  timeout 30 → 45。
- 守卫 `server/tests/modsecLive.wiring.test.js`（13 用例）：判据分层行为断言（含两条回显反例）
  + 源码接线断言。缺陷注入 **6/6 杀**；期间揪出并修掉一处**自己的假绿** —— 判据原用
  `match(/MODSEC_REQUIRE_DB/g).length >= 2` 计数，被上方**说明注释**里的同名变量名喂饱，
  真把 PL1 的配置删掉依然全绿。已改成「每个档位 env 块各自紧邻匹配」后注入即杀。
- 门：`typecheck:server` ✓ `facts:check` ✓ `readme:check` ✓ `arch:guard` ✓ `refs:check` ✓ eslint ✓。

### 2026-09-28 批次 · 扩样本集：样本自带上下文（上界 1/8 的根因修复）

上一批留下的问题：直连打穿上界只有 **1/8**，任何百分比都建立在单条样本上。本批定位到根因并修掉 ——
**不是 WAF 强，是我们的尺子坏了**：靶站只有一处 `WHERE id = ${raw}`（数值、无引号），
而样本集里多数是**字符串上下文**写法（`1' UNION …-- -`），拼进去是语法错误，只能算「抵达 SQL 层」。

- **样本自带上下文**（`e2e/waf-real/samples.mjs`）：新增 `CONTEXTS` 作为拼接模板的**单一来源**
  （靶站与对拍脚本共用），样本从裸字符串升级为 `{ ctx, payload, exfil?, note }`。三种形态覆盖
  真实业务最常见的三种裸拼：`num`（数值无引号）/ `str`（字符串带引号）/ `in`（`IN (…)` 括号）。
  样本 8 → 15 条，取数样本统一带注入标记并显式声明 `exfil: true`。
- **靶站按 ctx 路由**（`modsec-target.mjs`）：路由表由 `Object.values(CONTEXTS)` 生成（不再手抄
  一份 path），未知路径回 `NOROUTE`，防「打空端点」被记成注入失败。
- **对拍脚本一律走 `sampleUrl()`**（`modsec-live.mjs`）：不再硬编码 `/num?id=`（那正是上界 1/8
  的直接成因）；干净请求用 num 形态、裸注入自检改用 str 形态（后者在数值上下文里是语法错误，
  会掺进一个与 WAF 无关的干扰项）。新增 `MODSEC_MIN_UPPER` 上界下限（CI 设 4，不够就硬失败），
  上界 < 半数时告警；报告新增「注入点形态」段与逐样本 ctx 列。
- **打穿判据收紧**（`pwnVerdict.mjs`）：`pwn_error` 从「只认 MySQL 短语」改为「MySQL 短语 **且**
  带注入标记」。旧口径下 `XPATH syntax error: '~8.0.33'` 就算打穿，但它只证明报错通道通了，
  证明不了注入者要的数据被带出来。
- 静态侧 `tamper-sweep.mjs` 同步按 ctx 取 param/uri（两边同一批样本，否则又会分叉）。
- 守卫：新增 ⑦b（按 ctx 打端点、禁止硬编码 `/num?id=`）／⑭（三种形态都有样本、靶站路由必须
  由 CONTEXTS 生成）／⑮（`exfil: true` 必须带标记，**按声明字段筛**、不按 payload 形状筛 ——
  形状筛在「标记被删掉」时正好把样本筛出集合，缺陷注入实测就是这么空转的）／④b（报错无标记
  只算抵达 SQL 层）。样本规模断言改为 import 真实条数（源码数字符串会把 `ctx`/`note` 数进去）。
- 本地验证：路由自检 19/19（echo 桩，不起真库）；缺陷注入 **4/4 杀**且各只红目标用例；
  守卫 20/20、`typecheck:server` ✓ eslint ✓。⚠️ 上界真值待 CI `modsec-live` 取证（本机不起靶场）。

### 2026-09-28 批次 · 第三轮 CI 取证：上界 1/8 → 7/15，并把「74 vs 8」结案为不许引用

上一批把尺子修好了（样本自带上下文），这一批只是把真值取回来 —— 真机对拍的真值只有 CI 能给
（本机既无 docker 也不起靶场）。取证通道：`GET /repos/{o}/{r}/actions/artifacts` 列出
`modsec-live-results` → 下载 zip → 读 PL1/PL3 两份报告。

- **数字**：直连打穿上界 **7/15**（`MODSEC_MIN_UPPER=4` 闸门通过，无需再"静默出数"）；
  真机**打穿**插件 **1** 个（`unionvaluesrow`，2/15；它自己的直连上界同为 7/15 ⇒ 按可打穿样本
  计 **2/7**）；同口径**放行** PL1 **24** / PL3 **23**；安全对照 **0 误拦**。
  镜像 digest 与 CRS **4.29.0** 已固化进报告（四要素齐全，数字可复现）。
- **三条可直接引用的口径**（每条都有报告行支撑）：
  ① `encode2hex` 真机**放行 15/15**、直连上界 **0/15** —— WAF 一条没拦但语义被变形弄坏、一条
  打不穿，是「放行 ≠ 打穿」最干净的标本；② `charunicodeescape` 自实现判放行 15/15、真机
  **0/15** —— 反向的「高估自己」在新样本集上复现；③ 打穿数（2）远小于该链上界（7）⇒ 差距
  归因于 WAF 而非样本质量。
- **「74 → 8」结案**：只拿到后两轮的报告产物（均为旧 8 条样本、上界 1/8、放行 8），
  **首轮（74/72）产物已不在**；三轮之间样本集、镜像 digest、PARANOIA/阈值、放行判据
  （`status >= 400`）全部一致，剩下的唯一差别（靶站 echo vs db）又被第三轮数据**证伪** ——
  `encode2hex` 在 db 靶站上必然产生 MySQL 语法错误响应却仍 15/15 放行，说明 CRS 出站数据泄漏
  规则（`RESPONSE-951` 族 951230，匹配 `You have an error in your SQL syntax` / `XPATH syntax error:`）
  在本镜像配置下未生效。⇒ **74 既不能复现也无产物佐证，两轮放行数都不许引用**；
  README 09-27 那条已就地标注为「过程留痕，不可引用」。
- 文档：`docs/WAF-真机对拍-2026-09-28.md` 新增第七节（数字表 + 三条口径 + 7.3 处置结论）。

### 2026-09-29 批次 · 注入点形态 3 → 5：补上真实框架的另两个高频位置

前三种形态（`WHERE id = ${raw}` / `WHERE name = '${raw}'` / `WHERE id IN (${raw})`）全都落在
WHERE 的等值/枚举上。真实 Web 应用里搜索页与列表页排序的出现频率同样高，但**逃逸前提完全
不同**，此前一个都没覆盖 ⇒ 结论只代表"等值/枚举那一类靶点"。

- **新增 `like` 形态**（`/like?q=…`）：`WHERE name LIKE '%${raw}%'` —— PHP `"... LIKE '%" . $_GET['q'] . "%'"`、
  Python `f"... LIKE '%{q}%'"`。逃逸要先闭合 `%'`，尾部还留着一个 `%'` 得用注释吃掉。
  样本 2 条：union 取数 + extractvalue 报错取数。
- **新增 `orderby` 形态**（`/order?sort=…`）：`... ORDER BY ${raw}` —— PHP `"... ORDER BY " . $_GET['sort']`、
  Python `... ORDER BY %s" % sort`。它**不在 WHERE 里**，等值/union 那套「先闭合再 union」的前提
  整个不成立，只剩「在表达式位置求值」的手法。样本 2 条：extractvalue 报错取数 + `IF(1=1,1,2)` 布尔。
- **为什么按 SQL 拼接位置而不是按语言分形态**：PHP 与 Python 的差别只在字符串怎么拼
  （`.` 拼接 / f-string / `%` 格式化），落到 SQL 是同一句 ⇒ 按语言分会得到重复形态、
  只增加请求量不增加信息量。语言写法写在 CONTEXTS 注释里备查。
- **代价控制**：请求量 = 插件 × 样本 × 双通道，样本 15 → 19（+27%）⇒ 只加真正改变逃逸前提的
  位置，不为「看起来更全」堆形态。
- 守卫：⑭ 的形态清单扩到 5 种；新增 **⑭b** —— 每个形态的 `sql` 模板必须真的把 raw 拼进去
  （用哨兵值 `__RAW__` 验证，写死的模板 = 注入点根本不存在）。
- 缺陷注入 **2/2 杀**且各只红目标用例：删掉 like 样本 → ⑭；orderby 模板写死 → ⑭b。
- ⚠️ 教训（自己的坑）：注入后还原用了 `replace_all`（`'like' → 'str'` → 反向），
  把两条**原本就是 str** 的样本一起改成了 like —— 形态分布从 `{num:7,str:5,...}` 变成
  `{num:7,like:4,str:3,...}`，靠一次性路由自检脚本才发现。
  **下次缺陷注入：先备份文件（`cp` 到 /tmp 之外的临时路径），还原用备份，不用反向 replace。**
- 本机验证：5 种形态的路由/URL/SQL 模板与样本分布自检（一次性脚本，不起服务）；
  服务端 2519（2516 pass / 0 fail / 3 skip）✓。⚠️ 新形态的真值仍以 CI `modsec-live` 为准
  （本机不起靶场、也不起 MySQL）。

### 2026-09-29 批次 · 第四轮 CI 取证：上界 7/15 → 10/19，且「形态变多 ≠ 绕过链变多」

- **数字**（run #105/#106）：直连打穿上界 **10/19**；真机**打穿**插件 **1** 个
  （`unionvaluesrow`，2/19，其直连上界 10/19 ⇒ **2/10**）；**放行** PL1 / PL3 各 **25**；
  0 误拦。闸门 `MODSEC_MIN_UPPER=4` 仍通过。
- **新形态 4 条里 3 条打穿**：`like` 的 union 取数与 extractvalue 各一条（`pwn_result` /
  `pwn_error`），`orderby` 的 extractvalue 一条（`pwn_error`）——
  **`ORDER BY` 位置能被报错取数打穿**，这类「不在 WHERE 里」的排序参数不是安全位置。
  `orderby` 的布尔样本 `IF(1=1,1,2)` 记 `reached_sql`（设计上就不取数，只测放行）。
- ⚠️ **形态变多 ≠ 绕过链变多**（本轮最不能漏读的一条）：靶点 3 → 5 类、分母 7 → 10，
  改善的是**测量的代表性**；而真机打穿插件**仍然只有 1 个** —— **没有发现任何新的打穿链**。
  下一步该提的是「打穿链数」（链侧能力），不是继续往样本集里堆形态（那只会加大请求量）。
- 文档：`docs/WAF-真机对拍-2026-09-28.md` 新增第八节（8.1 数字 / 8.2 新形态逐条 / 8.3 上述
  结论 / 8.4 诚实边界）。

### 2026-09-29 批次 · 接口靶场遗留项：拆掉两处「自己证明自己」的假绿

接口靶场（`e2e/api-range-lab`）暴露的 8 项里，先做掉最像假绿的两条 —— 共同形态是：
**声明与真值分处两地，而接口报的就是那份声明本身，于是漂移永远查不出来。**

- **`/exploit/capabilities` 从手写清单改为由方言表推导**。以前是四个硬编码数组
  （还带 `MySQL(sys_eval UDF)` 这种注释式写法），能力表在 `Exploiter.TAKEOVER_CAPS` 另有一份
  ⇒ 「清单说有、动作说没有」在接口层不可观测。现在：新增 `capabilityIndex()` 做反向索引，
  路由返回 `...capabilityIndex()`（能力 → 支持的 DBMS）+ `matrix`（DBMS → supported / risk /
  requiredPriv / note，供 UI 提示权限与风险）。只收 `supported === true` 的条目。
  前端 `ExploitCapabilities` 类型补 `matrix` / `enabled`。
- **`docs/api.md` 并入自动门禁（判据 ⑭b）**。api.md 是对外接口契约，此前零门禁：代码加了端点、
  改了字段，文档不动也不红。现在与 README 那张表同一把尺子双向核对（判据自动补 `/api` 前缀、
  剥掉查询串，避免两边永远对不上的假红）。**首跑即抓到 4 个真缺口**并补齐：
  `POST /scan/:id/pause`、`POST /scan/:id/resume`、`GET /scan/:id/diff?base=`、`POST /exploit/sql`
  —— 四个都早已上线，文档里没有。顺带把 capabilities 的响应样例改成推导后的真实形态。
- 新增 `server/tests/exploitCapabilities.test.js`（5 条）：接口返回值逐条等于推导结果 /
  推导与方言表双向自洽 / 关键能力钉真值（**方言表删条目 ⇒ 必须红**，能力下架要有人显式确认）/
  源码不得再手抄清单 / `matrix` 字段完整。
- 缺陷注入 **4/4 杀**：关掉 `MySQL.fileWrite` ⇒ ③；路由改回手写数组 ⇒ ①④⑤；
  api.md 删掉 pause 标题 ⇒ 报漏写；api.md 加幽灵端点 ⇒ 报「不存在」。

### 2026-09-29 批次 · facts 采集：数字必须对应**一个确定的代码版本**

`--refresh` 要跑几分钟测试，数字采自「跑测试那一刻的磁盘」。采集期间若有人改了测试源码
（并发会话最常见），产出的数字就**既不对应采集前也不对应采集后**的任何一版代码 ——
而旧行为会把这份数字连同「新指纹」一起落盘，两个文件双双是新的、看起来完全正常，
实际是一次**没人能复现的采集**。

- **采集前后各取一次指纹**（`scripts/facts-sync.mjs`）：不一致即报
  「**采集期间文件被改动，本次结果不可用**」，点名被改 / 新增 / 删除的文件，
  **拒绝写盘**并退出 1（不再留下一句可能来自上一轮的旧数字）。
- 抽成纯函数 `diffDigests()` + 新增 `--selftest`（5 类形态：无差异 / 改 / 增 / 删 / 空指纹），
  CI lint job 已加该步骤 —— 钉的是**判据本身**，数字每次采集都在变，判据不能跟着变。
- 不把「采集前指纹」写盘：写盘会造出「上次采集进行到一半」的中间态文件，而失败时本来就
  不该留下任何产物；同一进程内比对即可拿到同样（且更干净）的判据。
- **真实验证**：采集到第 40 秒改一个测试源 ⇒ 报「被改（1）：server/tests/exploitCapabilities.test.js」
  + EXIT=1 + `_facts.json` 未被改写。
- ⚠️ 实验过程中的一次误判：先拿 `docs/api.md` 试，**它不在指纹源里**（指纹源只有测试文件）
  ⇒ 判据自然不报。验证「采集期改动」类判据前，先确认改动对象真在指纹源里。


### 2026-09-27 批次 · README 的 API 表与命令行示例：从"没人核"变成双向核对

接着上一批的判据面，把两类"照抄就会错"的文档补上门禁。

- **判据 ⑭ API 表双向核对**：取数源是 `server/index.js` 的 `app.use('/api…', xxxRoutes)` 挂载点 +
  各 router 的注册行（同一批路由也挂 `/` 供 Tauri，只数 `/api` 一份）。实测双向都有错：
  ① README 写了**不存在**的 `POST /api/scan/stop`（真路径带 `:id`）—— 照文档调用直接 404；
  ② 代码注册 25 条，表里只列了 10 条真端点，**漏写 15 条**（`/scan/:id`、`/events`、
  `pause`/`resume`、`point/:pointId/retest`、`diff`、`/payloads`、`/sqlmap/*` 五条、`/report/ai` 两条）。
  README 表已按实注册集合重写为 25 行，并注明"由 readme:check 双向核对"。
  `capabilities` 那一行顺手如实标注：**目前是手写列表，不由 Exploiter 方言表推导**（缺陷本体另批修）。
- **判据 ⑮ 命令行路径存在性**：README 两处教 `node bin/cli.js --help`，而 CLI 真身在
  `server/bin/cli.js` —— 从仓库根照抄就是 MODULE_NOT_FOUND（实跑对比：根路径 rc=1，
  `node server/bin/cli.js --help` rc=0）。现规则要求 README 里每条 `node <仓库内路径>.{js,mjs,cjs}`
  都真实存在；接入时全量 README 命中 12 条、**零假阳**，故判据形态可以放心做成"文件在不在"。
  将来若要写构建产物路径，加进白名单并注明理由，不许把整条放宽成不检查。
- 自证扩到 **26 类漂移样本全部被点名 + 5 类正确样本无误报**。
- 门：`readme:check` ✓ `facts:check` ✓ `arch:guard` ✓ `refs:check` ✓ eslint ✓。


### 2026-09-27 批次 · 两条此前裸奔的对外数字：验收套件数与 tamper 官方分母

上一轮全栈审计实测到 README 有对外数字与真值不符而**没有任何判据**，本轮把判据补上并收口。

- **判据 ⑪ 验收套件数**：README 两处称「12 套件」，`e2e/acceptance.mjs` 的 SUITES 实为 **15**。
  取数口径有个坑值得记：数组里有 **2 条 title 用模板字面量**（`` `CRS 人工挂链 A/B（PL${WAF_GATE_PL} 档基线）` ``），
  只匹配单引号会把 15 数成 13 —— 判据自己先错一遍。现按 `title:\s*['"`]` 计数并以 `\n];` 收数组边界。
  同时把 README 那条流水线叙述补齐（漏写 OOB 带外真机、WAF 定向变异搜索 A2、WAF 通道降级编排 A3 三个套件）。
  规则**只认两种固定措辞**（`（N 套件，` / `N 套件一次跑完`）：带日期标题的「12 套件全绿」是某一轮的
  运行记录，纳入判据等于要求"改文档必重跑 20 分钟门禁"，那是假红来源。
- **判据 ⑫ tamper 官方分母**：README 写「覆盖官方全集 84/84」，而分母来自外部真值
  `upstream-sqlmap-tamper.json`（tag 1.9.11）实为 **70** 条；现跑 `npm run tamper:parity` 打的是
  「官方 70｜本仓 228｜缺 0」——**分子对、分母错**。改判据后：分母与 `count` 字段比、
  分子与 `总数 − 缺失数` 比，并要求数据源自洽（`count === names.length`，否则直接抛错）。
- **判据 ⑬ 二级文档不许抄数字**：`SECURITY.md:58` 写"服务端 1249 测试"（真值 2483，差近一倍）、
  `CONTRIBUTING.md:11/13/26/27` 写 225/2355/349/2361，而该文件自己 `:34` 就写着"以 _facts.json 为准"。
  处置不是再加一套同步机器，而是**把副本删掉**、改成指向事实源 —— 抄一份就要多守一个文件，
  判据形态因此做成"禁止出现这种写法"（结构判据），不随事实漂移、不会造成"改代码必须改文档"的假红。
- 自证：`--selftest` 样本从 16 类扩到 **22 类漂移全部被点名 + 5 类正确样本无误报**（含
  「有缺失时分子如实写差值」与「二级文档写 18 场景不该被误伤」两条反过度收紧的边界）。
- 过程里判据立刻见效：我给 README 的 tamper 行加了注释 → ⑫ 的解析锚点不再命中 →
  脚本按设计**报"判据已失效"而不是静默跳过**；把锚点放宽为容忍括号内注释才算数。
- 本批改完 README/测试文件后 `facts:check` 报"采集源指纹已改动"（4 新增 + 11 修改，全是本轮文件），
  按设计走 `--refresh --coverage` 重采 + `--fix` 回写 README 数字。


### 2026-09-27 批次 · 桌面版随机端口断链：SSE 与报告导出还在拼编译期常量

A3 那次加固（sidecar 端口「4567 被占则随机」+ 一次性 token）只搬了三样里的两样：
壳选了端口、引擎生成了 token、前端有 `setApiBase()` —— 但**只有 axios 的两个拦截器**
（`apiClient.ts:62/97`）读 `getApiBase()`。自己拼 URL 的两个出口拼的仍是编译期常量
`API_BASE`（`.env.tauri` 把它钉成 `http://127.0.0.1:4567`）：

| 出口 | 位置 | 症状 |
|---|---|---|
| SSE 订阅 | `src/hooks/useEvents.ts:132` | 扫描能起、进度永远不动 |
| 报告另存盘 | `src/hooks/useScan.ts:263` | 导出永远 404 |

再加一处同族：`src-tauri/tauri.conf.json` 的 CSP `connect-src` 只放行 `http://127.0.0.1:4567`，
随机端口下连 axios 那条路径也会被 WebView 拦掉 ⇒ 放宽为 `http://127.0.0.1:*`
（使用门槛仍是一次性 token，不是端口）。

- 两个出口改走 `getApiBase()`；`API_BASE` 的注释与 `lib.rs` 的 `pick_engine_port` 文档
  都写下「端口可变动的三处出口必须同步」，防下次只搬一半。
- 新判据 `src/tests/desktopRuntimeBase.test.tsx`（3 条：回退路径 + SSE + 导出）。
  **它刻意不 mock `../shared/apiClient`** —— 既有 `useEvents.test.tsx` / `useScan.export.test.tsx`
  正是把该模块整个换成 `{API_BASE: 'http://test/api'}`，才让这个缺陷在 411 条前端用例全绿下活到今天；
  把持有运行期值的模块 mock 掉，就看不见"没人读它"。用例另含一条"未注入运行期 base 时仍走 `/api`"，
  防止修成恒取运行期值。
- 顺带：10 个 mock 该模块的测试文件补 `getApiBase`（改法带命中数断言，逐文件确认恰好 1 处锚点）。
- 验证：摘掉两处修复前新用例 **2 红 1 绿**，修复后 3 绿；前端全量 **53 文件 / 414 条全绿**
  （基线 411 + 新增 3），`tsc --noEmit` 0 错、eslint 0 问题、`cargo fmt --check` 0 问题。
- ⚠ **没真跑过桌面包**：CSP 端口通配符的浏览器行为与 sidecar 实连属配置级推理，
  需 Windows 上 `npm run build:tauri` 出包后手点一遍（`cargo clippy` 本机易 ICE，未跑）。


### 2026-09-27 批次 · 时间通道的三处「判据与注释不同源」

六路并行全栈审计里，引擎层是唯一一处**判据本身错**的层。挑出的三条都在时间/payload
选择这条主判据链上，形状各不相同但根子相同：注释/文档写的是一个口径，代码做的是另一个。

1. **时间盲注「提取」阶段从来没加基线**。`blindExtractor.js` 里那行注释一直写着
   「以基线耗时 + timeThresholdMs 为准，避免目标本身慢造成误判」，代码却是
   `thresholdMs = config.timeThresholdMs * 1` —— 基线没加。本仓另外三条时间路径**都**加了
   （`TimeBlindDetector` 的 μ+z·σ、`StackedDetector` 的 `max(阈值, 基线+sleep/2)`、
   `DBFingerprinter` 的 `baselineRtt + thresholdMs`），唯独拖库输出的这一段漏了。
   后果不是「值偏一点」：自身响应慢于阈值的目标上「耗时 ≥ 阈值」对每个条件恒成立 ⇒
   长度二分恒判真 → 顶到 `blindMaxLen` 上界 → 逐位置循环失控。
   - 用例 `tests/extractor.timeBaseline.test.js` 三条都带 15s 截止时间：**未修复时第一轮
     就跑不完**（现场打印「已发请求 218 个」），修复后 0.7/3.5/3.5s 通过。
   - 基线取 3 次**串行**中位数（同 `StackedDetector` 的误报防护）：并发采样会把令牌桶排队
     时间只算进基线，判据侧与基线侧必须同量。全失败回落 0 = 旧行为。
   - 注入超时同步补基线（`StackedDetector` 的 ★FIX [P0] 同因）：否则慢站上「基线+sleep」
     超 timeout → `_send` 返回 null → 全部条件判假 → 一次本可提取的值被误报「取不出」。
   - `calibrateTimeSleep` 新增可选入参 = 判定侧已含基线的阈值，标定与判定同源；
     未传时回落配置阈值（直调它的 T4 用例行为零变化）。

2. **预筛选在空探针数组上恒判「无迹象」**。`timeProbeValues('SQLite')` 返回 `[]`
   （SQLite 无服务端 sleep，这是诚实的），而 `prefilterPoints` 用 `timed.some(...)` 决定跳过
   —— 空数组上 `.some()` 恒 false ⇒ 只要基线与单引号探针同构就整点剪掉。
   与本模块文件头那条红线（「不可判定一律保守保留」）相反：这次不是探测失败，
   是**判据落在不存在的探针上**。只在显式 `--dbms sqlite` 时命中（未定库走 default 分支有 3 条探针）。
   - `tests/prefilter.emptyProbe.test.js` 两向都钉：SQLite 全保留（修复前 0/2 红）、
     MySQL 与未定库无信号时**仍要剪**（别把 200+ 请求的剪枝收益一起赔掉）。

3. **`useRegistry` 在兄弟检测器里被写成两种判据**：Boolean/Error 判 `=== true`、
   TimeBlind 判 `!== false` ⇒ 默认配置下**同一次扫描**里 time 走声明式注册表、布尔/报错走扁平
   ⇒ `--test-filter/--test-skip/level/risk` 只在一半通道生效，调用方只看到「参数被接受」。
   `docs/项目评价-2026-09-23.md:225` 早就把这一类命名为「`useRegistry` 双拷贝漂移」，本轮收口。
   - 新增 `payloadRegistry.registryMode(config)` 作唯一判定点，四处调用点全部改走它
     （三个检测器 + `ScanManager` 的能力护栏）。统一方向取「显式 true 才切换」：
     两侧向量集互有增减（MySQL boolean 扁平 69/注册表 49，MySQL error 扁平 61/注册表 69），
     没有任何一侧免费，而 `defaults.js` 与 `docs/api.md:225` 的承诺本就是「false=扁平（默认）」。
   - `tests/registryMode.contract.test.js` **不复制判据**（照抄 `=== true` 就成了自证），
     而是从可观测结果反推每个通道实际用了哪个源，再断言三者一致 + 与 `registryMode` 一致；
     含 `{useRegistry:'true'}` 字符串档。摘掉本次修复（time 改回 `!== false`）后
     **4 条里红 3 条**，且「前置事实」那条自己报出观测退化 —— 反空转有效。
   - 代价与实测：默认档下 time 通道由注册表 34 条改为扁平 31 条，**registry-only 的
     `GET_LOCK`/`BENCHMARK` 变体缺省不再投放**，需要 `--use-registry`。
     `e2e/detection-runner` 19 场景改前/改后逐条 diff 为空（含请求数：`time_only` 两侧都是 164），
     统计同为 19 PASS / 0 FAIL / 0 SKIP / 1 WARN。
   - `collectCapabilityConstraints` 补一条：扁平路径下设了 `--test-filter`/`--test-skip`
     时明确写「未生效」，`useRegistry=true` 时该约束消失。守卫用例三个方向都覆盖
     （含「只设 testSkip」，防判据只写一侧）。

**未验证**：真 MySQL/真 PG 上的时间通道实测本轮没跑（需 `python e2e/run-with-sandbox.py` 起沙箱，
直连宿主 3306 必红），`npm run acceptance` 全量同理 —— 这一半由远端 CI 的 acceptance job 覆盖。


### 2026-09-25 批次 · 补上"入库产物 = 当前代码跑出来的那份"这道外部一致性门禁

前面几节反复出现同一个形状：**产物在说谎，而当轮 CI 全绿**。
`e2eArtifacts.consistency.test.js` 查的是"结论列与同行测量列自不自洽"（内部一致性），
它抓得住 09-20 那五天，却抓不住一份**内部自洽但与当前代码不符**的基线 ——
比如靶场改了 payload、检测通道变了，而入库报告还是旧的那份。仓库里没有任何判据比这个。

- 新增 `scripts/artifact-drift.mjs`（`npm run artifact:drift`）：把 HEAD 里那份与磁盘上那份
  **只忽略时间戳**后逐行比。不用 `git diff --exit-code` 是因为产物必然带生成时间，
  逐字节比 = 天天红。
- 接进 CI 的 `e2e-self-contained`（该 job 刚真的重跑过那三个档 ⇒ 比的是"同一轮、当前代码"），
  并同步进 `scripts/ci-local.mjs`。**只登记 multi-engine 三档**：waf-real 那几份要真 MySQL/真 MariaDB，
  服务端小版本一变 error 通道文本指纹就变 ⇒ 现阶段是假红来源，等测过稳定度再加（脚本注释里写了理由）。
- `server/tests/artifactDrift.wiring.test.js` 钉三处接线 + 覆盖面：少任何一处（package.json /
  ci.yml 步骤 / ci-local 的 cmd / **ci-local 的 job id**）就红；漂移清单里的每份产物必须
  ① 被 git 跟踪 ② 在 run-all 里有对应且**会真被重跑**的档 ③ 至少 3 份、每份至少 3 行表格。
  最后一条是反空转 —— 本仓第一版守卫的目录过滤器写成恒假，就是被同类断言抓出来的。
- 验证：漂移检查本身 3 次（未重跑绿 / 真重跑三份产物仍绿——证明归一化吃掉了真实 churn /
  注入一句反向结论红 + 精确 diff）；接线守卫 **7 个变异逐个摘掉被保护物全部变红**。
  其中"package.json 脚本"那条第一版锚点带了 `\n`，在本机 CRLF 文件上命中 0 次 ⇒
  被判成无效变异而不是"通过"，改成不锚换行的替换后才成立。


### 2026-09-25 批次 · CI 真跑的偏偏是唯一证不出事的那一档

上一轮忙完，远端 run `09a5e92` 的日志第一次出现了 `▶ multi-engine-lab ... ✅ 通过 6.6s`
（4 个引擎 jar 逐个 sha1 校验通过）。我当时把它当成果报给自己，但同一行里就写着：

```
[判定] 断言：safe 零误报=✅　tamper 收益 on(0) ≥ off(0)=✅　桥存活=✅
```

`0 ≥ 0` 空转成立。翻 `results/multi-engine-report.json`：CRS-on 档 **36 格全空**，连 `dbms`
都是 null。也就是说 —— 下载 jar、校验 sha1、注入 `ENGINE_JARS` 这条链全在干活，跑的却是
**唯一证不出任何事的那一档**（≈PL3 全规则档把探针整条 403；`acceptance.mjs:380` 对 MySQL
早就记过同一件事：「PL3 下 off=on=0」）。真正有信息量的 `NO_WAF=1` 档只在我手动跑过一次，
产物入了库，**门禁里没有它**。

1. **补注册两档，都挂在同一个 java 依赖上**（`e2e/run-all.mjs`）：
   `multi-engine-lab-no-waf`（`verify.mjs` + `NO_WAF=1`，检测/定库类断言只在这档成立）与
   `dialect-templates`（`verify-dialect-templates.mjs`，16 条"方言模板在真引擎上可执行 + 反证"
   —— 它 09-22 起就写在 `docs/P2-dialect-probe-2026-09-22.md` 的"退出码 0 = 全通过"里，
   却从没进过任何门禁）。本机实测 6.4s / 4.4s / 1.5s。
   顺手统一退出码口径：dialect 脚本缺 `ENGINE_JARS` 时原本退 2，而 run-all 的跳过判据是
   `code===0 && /\[SKIP\]/` ⇒ 一台没放 jar 的机器会把"环境没配"报成"测试挂了"。改成 `[SKIP]` + 0。
2. **接上一个从没被读过的字段**：`SCENARIOS[].must = ['boolean']` 自写下来没有任何一处引用它，
   于是"某引擎退化到只剩 error 通道"照样 ✅。现在它进判定（且只在无 WAF 档进 —— CRS 档 0 检出时
   挂它就是永久红）。变异：给 num 的 `must` 加一个不存在的 `stacked` ⇒ `rc=1` 且原因点名缺哪个通道。
3. **定库从"印一行警告"变成断言**：新增 `expectDbms`，取值是这轮从产物里读出来的事实
   （H2→`H2`、HSQLDB→`HSQLDB`、Derby→**null，即"当前定不出"**）。双向漂移都红：丢了 ⇒ 红；
   Derby 哪天真定出来了 ⇒ 也红，并明确提示"把基线和 README 覆盖面一起改，别只改代码"。
   两条变异各 `rc=1`。原来那句"定库与真实引擎不符 = 误判，比定不出库更糟"只 `console.log`，
   现在同样进判定 —— 误判会直接写进交付报告的 DBMS 字段。
4. **说明列学会了说"丢了一部分"**：上一版只分红 on 空/非空，于是 `derby/str`
   （`off=union,error,boolean` → `on=error,boolean`，**union 被打掉**）印成「tamper 后检出」。
   改成集合差分（`丢失 X` / `新增 X` / `技术位与 tamper 前一致`），并给表格加"定库 off/on"列
   —— "哪条通道才带得出库名"此前只在控制台里，跑完就没。
5. **档位不再由我手敲**：报告抬头的 `≈PL3` 原本是字面量，`CRS_PL=1` 跑出来的产物照样印 PL3；
   现在取 `crs-engine` 的 `EFFECTIVE_PL`，且非默认档写独立文件名（`.pl1`），一次改档探索不会再
   悄悄覆盖入库基线。判定行也自证：空转时印「✅（空转：两侧均 0，本档不证明绕过能力）」，
   CRS 档直接写明"检测类断言本档不适用"。
6. **撤下 README 那句没有证据的"× CRS"**：覆盖面表里 `H2、HSQLDB、Derby …… 仅布尔通道 × CRS`
   溯到 2026-09-09 的 `results/p3-multi-engine-report.md`（那晚记的是"tamper 打穿 CRS 后
   H2/Derby 的 error 通道检出"）。同一套设施今天复跑 = 0/9 ⇒ 那句结论**已不可复现**
   （这些天 CRS 执行器改过保真度：`+`→空格、PL 区块截断、FILES 停止预解码，尺子变了）。
   处置：P3 原件顶部加失效声明并**保留**（它记录的是那天的实验，删掉等于把负记录也扔了），
   README 改成按档分开引 —— 无 WAF 档给覆盖面与定库，CRS 档只给"safe 零误报"。

**收尾时顺手把档扫了一遍，结论翻转了半句**：把 `CRS_PL` 从 1 量到 4，
PL1 = 三引擎 × 三场景 **9/9 检出**（布尔通道，h2/derby 另有 error），PL2/PL3/PL4 = **0/9**。
所以"这三库过不了 CRS"根本不成立 —— 成立的是"过不了 PL2 以上的 CRS"，而 CRS 官方默认部署是 PL1
（本仓 `waf-real` 的对外口径也在那一档上）。于是：
`multi-engine-lab-crs-pl1` 也注册进清单（第三个档，产物 `.pl1.md`），README 的覆盖面那一栏
改写成"三档分开引"，并把断崖写进去 —— 不许拿 PL1 说"任何 WAF 都能过"，也不许拿 PL3 说"过不了 WAF"。
断言的挂载条件随之从"按档名"改成"按实测"：`MUST_ASSERT = NO_WAF || EFFECTIVE_PL === 1`、
`DBMS_ASSERT = NO_WAF`（PL1 下 UNION 哨兵照样被吃，把定库基线挂上去只会把"没送达"报成"探针坏"）。
四档本机耗时 6.4 + 4.4 + 4.9 + 1.5s。

### 2026-09-25 批次 · 顺着"档位"摸到的四条：PL2 是全仓唯一有净收益的档、CRS 报告根本不在仓库里、3308 有两个主人、结论列按长度判

上一节写完还剩一个没回答的问题：**高 paranoid 档到底是"过不了 WAF"还是"档太严"**。
把 CRS 逐档量完之后，顺带挖出三个同类缺陷。

1. **真 MySQL 的逐档数字（原来只有 PL1/PL3 两个点，中间是空的）**：
   PL1 = off 8 / on 8 / 自动 8；**PL2 = off 0 / on 1 / 自动 0**；PL3 = 0/0/0；PL4 = 0/0/0。
   ⇒ ① 断崖在 **PL1→PL2**，之后是平的（三个 Java 引擎在同一把尺子上同形）；
   ② **PL2 是全仓目前唯一观测到"挂链有净收益"的档**（orderby 的 error 通道 0→1）——
   以前所有档要么"探针本来就能过"要么"全拦"，tamper 的价值从来没被量出来过。
   四个点写进 `waf-bits-baseline.json`（逐档逐字段，含 `复测` 命令），README 那张档位表补齐。
2. **`e2e/waf-real/results/` 整目录被 .gitignore 排除** —— 而 README 管 `npm run waf-real` 叫
   "对外唯一口径"。后果有两层：客户 clone 下来看不到任何数字来源；扫 md 的产物自洽守卫
   在 CI 的干净 checkout 里**连文件都找不到**，对这份口径从来没生效过。
   修：`results/` 从"整目录忽略"改成"忽略非 md"+ 白名单只开给 `waf-real-report*.md`
   （其余 md 保持原政策，不一次性引入六份新产物）。守卫立刻抓到两条真缺陷（见第 4 点）。
3. **改档跑一次，就把入库基线悄悄换掉**：`waf-verify.mjs` / `waf-auto-check.mjs` 写的是固定文件名，
   而 CRS 档位是可变的 —— `CRS_PL=3 npm run waf-real` 会把"对外口径 PL1"那份产物覆盖成 0/0 那份。
   同一天在 multi-engine-lab 上刚踩过同一个坑，这次是它的泛化。修：非默认档一律另起文件
   （`.plN.md` / `.plN.json`），并把 `paranoiaLevel` 写进 json。
   连带修掉 `waf-auto-check` 的一句撒谎话：它无论跑在哪一档都去读 PL1 那份产物当"人工挂链基线"，
   实测打印过 `PL4 下 自动=0（人工挂链基线：off=8 on=8）`；现在按档找对应产物，档位对不上就明说不可比。
4. **结论列按长度判 ⇒ 报喜不报忧**：`on.length > off.length ⇒ 绕过生效` 这一句同时写在
   `waf-verify.mjs` 和 `mariadb-verify.mjs` 里。前者会把 `off=[boolean,error] / on=[error]`
   （同为长度 2，丢了一整条通道）印成 "—"；后者入库那份 09-09 的 `mariadb-report.md` 里
   `num`、`blind` 两行前后完全相同（`boolean`/`boolean`）也印"绕过生效"。
   生成端改成集合差（`绕过生效（新增 X）` / `反而丢失 Y` / `技术位持平` / `全拦`），
   并把守卫从"只看说明列"扩到"结论列 + A/B 两列同向"（B 类判据，六条合成用例 + 一条
   **往真实产物注入撒谎结论**的用例 —— 只测合成分支不够，表头写法一变守卫就会静默跳过整张表）。
   `mariadb-report.md` 没法重跑（本机 MariaDB 便携版没起），所以只**按本行两列重算结论列**、
   测量列原样不动，并在文件顶部写清哪些话能引、哪些不能（09-19 执行器修准后未复跑）。
5. **3308 端口有两个主人**：真 MariaDB 便携版（`mariadb-verify.mjs` 的靶的）和
   `e2e/udf-lab/mysql_sandbox.py` 起的隔离 **MySQL 8** 沙箱共用 3308、同库名。
   ⇒ 沙箱在的时候跑一次 mariadb-verify，就会把 MySQL 的数字写进标着 MariaDB 的产物里，
   而且看起来完全可信。修：脚本开跑前读 `SELECT VERSION()`，不是 MariaDB 直接硬退（rc=2）。
   实测覆盖：经 `run-with-sandbox.py` 起了真沙箱后跑 mariadb-verify ⇒ 当场拒绝、未产生任何扫描；
   另"版本自报不是 MariaDB 就拒"那一支本轮**没有真发环境可测**（便携版没起），只有代码路径。
6. **门禁口径统一**：`waf-auto` 的断言原来写 `?.auto ?? 0`，即"该档没记基线"= 下限 0 = 必过；
   而同文件的 `waf-real` 对同一件事是 `基线缺该档 ⇒ FAIL`。两条判据不该一松一严，
   现在 auto 缺字段也直接红（`WAF_GATE_PL=9 --only=waf-auto` 实测：FAIL + 原因 + 现场日志）。



### 2026-09-25 批次 · multi-engine-lab：Linux 上必崩的 classpath、永远退 0 的"门禁"、以及印了五天的反向结论

远端连着两次红都在同一步（`e2e-self-contained` → run-all → multi-engine-lab），
报的是 `Error: write EPIPE`、0.5s、没有任何原因可看。查下去是三层问题叠在一起。

1. **classpath 分隔符硬写了 `;`**（`lab-app.mjs` 的 `-cp "${ENGINE_JARS};${HERE}"`）。
   Windows 用 `;`、POSIX 用 `:` ⇒ Linux 上整串被 JVM 当成**一个**条目 ⇒ 找不到主类
   `EngineBridge` ⇒ JVM 立刻退出。而 `run-all.mjs` 给这个靶场配的 `ENGINE_JARS` 是
   `D:\engines\jars\*.jar`（Windows 路径），CI 上 jar 根本不存在 —— 于是
   **本机它能跑、Linux 上必崩**，且崩在"往已死进程 stdin 写"这种形态上。
   修：分隔符改走 `path.delimiter`；加 `bridgePreflight()`（ENGINE_JARS 未设 / jar 不在
   即前提不满足）⇒ 按设计 `[SKIP]` 退 0 并打印原因，run-all 记「跳过」而不是「失败」。
   ⚠ 我第一版写成"`;` 和 `:` 都拆一下"，当场被自己的跑批打回：Windows 上
   `D:\engines\jars\h2.jar` 会从**盘符冒号**处切成 `D` + `\engines\…` ⇒ 每个 jar 都"不存在"。
   现在只按平台分隔符拆；跨平台复制错格式由 preflight 明确报错，不猜着拆。
2. **`verify.mjs` 从头到尾没有一处设置失败退出码**，而它文件头写着
   "断言：safe 永远零检出；tamper on 应 ≥ tamper off"。⇒ run-all 里这个靶场**恒记 ✅ 通过**，
   一条断言都没落地；JVM 半路死掉也一样绿（本机模拟 `JAVA_BIN=node` ⇒ 全 0/3 且 RC=0）。
   现在退出码真的承接判据：`0` 断言通过 / `1` 误报红线或收益为负 / `2` 前提失效（桥中途死）。
   前提失效与断言失败**必须分开**：前者去修环境，后者才是真回归。启动处另加一次探针
   （桥起不来 ⇒ `[SKIP]` + 原因，而不是扫完九个组合再交一堆废数字）。
   同时补上 stdin / 子进程 'error' 监听（缺了就是未捕获异常）与 stderr 尾部留证 ——
   CI 那两条红"没有原因"正是这么来的。
3. **入库报告印的是反向结论**（这次才算清账）：表格"说明"列原本写
   `${on ? '检出' : '未检出'}`，而 `on` 是拼接**字符串**，空的时候是 `'-'` —— 照样 truthy。
   于是 `multi-engine-report.md` 与 `.no-waf.md` 两份基线的 9 行**全部**印"检出"，
   而 off/on 两列都是 `-`。重跑两份产物后：
   - WAF=on：off=0 / on=0 ⇒ 新加的"本档有效性"行明说"绕过收益无从判定，本档只验了误报红线；
     'H2/HSQLDB/Derby 布尔通道被检出过'这句结论本档**不提供**证据"；
   - `NO_WAF=1`：off=9 / on=9 ⇒ 检测能力本身没问题，是 CRS 档下 `dash2hash` 收益为 0。
   旧基线里那 9 个"-"到底是"真没检出"还是"当时桥就是坏的"，已无法从产物判断 ——
   这正好是把有效性写成行的理由：**下次不必再靠考古**。

**下一步（本轮未做，只登记）**：CRS-on 档两侧全零说明"真 JDBC 引擎 × CRS"这个组合
从没证明过任何绕过收益（`dash2hash` 只在 H2 的 MySQL 方言态投放）。要么换成"裸请求被 CRS 拦、
挂 tamper 能过"的形态重做这档，要么把 README 里"部分通道验证：H2/HSQLDB/Derby"的范围
说清只到"无 WAF 下布尔通道"。本轮只修**诚实性**，不动结论。

**门禁**：`node --check` × 2、eslint 0 error、`refs:check` / `facts:check` 过；
本机三向真跑：无 ENGINE_JARS ⇒ `[SKIP]` 退 0；带真 jar ⇒ 两档各退 0 且报告如实；
`JAVA_BIN=node` ⇒ 退 2 并带 `JVM 退出（code=9）；输出尾部：node: bad option: -cp`。
CI 侧的必崩条件（Linux 缺 jar）现在会走 `[SKIP]` —— 这条**本机不能代替远端验证**，
以推上去后 `e2e-self-contained` 的实跑结论为准。

**并把这类事故钉成机器判据**（`server/tests/e2eArtifacts.consistency.test.js`）：
扫入库的 e2e 报告，凡"结论列说检出、同一行测量列全空"就红。为什么不"重跑再逐字节比对"：
产物带时间戳，那样天天红；而这次事故的性质就是**同一行内部自相矛盾**，不重跑也能判。
两条自己的错在过程中被当场抓住：
① 第一版按位置取测量列 ⇒ 「场景」列也算数据 ⇒ 把撒谎的旧基线放回工作区都不红；
   改成按表头文字选列（`tamper|off|on|命中|…`）后，变异验证两步都红、还原后绿。
② 全仓那份的目录过滤写成恒假 ⇒ 扫到 0 个文件 —— 靠守卫自己那条"文件数不得少于阈值"
   的防空转断言暴露，而不是静默假绿。
**CI 现在真跑这一档，而不是永远 SKIP**（`e2e-self-contained` 新增前置步）：修完分隔符之后，
Linux 上的结果只是从 ❌ 变成 ⏭ —— 远端日志实证：`⏭ 跳过（按设计）0.4s`、
`[SKIP] ... ENGINE_JARS 中这些 jar 不存在：D、\engines\jars\h2.jar;D、…`（还是被 `:` 切碎的
Windows 串）⇒ 也就是说 **H2/HSQLDB/Derby 的真引擎检测仍然从没在 CI 跑过一次**。
新步按 Maven Central 官方 `.sha1` 逐个校验下载（4 件：h2 2.2.224 / hsqldb 2.7.3 /
derby 10.16.1.1 / derbyshared），全对才 `ENGINE_JARS=…:$dir/…` 写进 `$GITHUB_ENV`；
**任何一件不可信就不设** ⇒ 套件按 preflight 明确 SKIP（不假绿、也不把推送变成假红）。
校验不是形式主义：本机经代理第一次取 h2 得到 285KB 的**合法 zip 头 + 错 sha1**（真身 2,614,933
字节），只看 `curl` 退出码就会拿半截 jar 去跑。重试到第 1 次即全绿（4 件 sha1 全对）。

配套修的是 `run-all.mjs` 里那条会**覆盖** CI 环境的写死值：`lab.env` 无条件注入
`D:\engines\jars\*.jar`，排在 `...process.env` 之后 ⇒ 就算 CI 备好了 jar 也会被顶掉。
现在 `ENGINE_JARS` 已存在就让位、默认路径必须真实存在才注入（否则交给 preflight 报"未设置"）。
两条代码路径用可区分的方式验过（`NO_WAF=1`，同一命令只差 ENGINE_JARS）：
- 继承单个 jar ⇒ `[判定] ... on(3) ≥ off(3)`（只有 H2 那台引擎能用 ⇒ 证明读的是继承值）
- 不设 ⇒ `on(9) ≥ off(9)`（本机默认全套 ⇒ 证明 fallback 生效）
`ENGINE_JARS` 指到刚下载的 jar 亦真跑通过（`✅ 通过 6.5s`）。
CI 侧的"下载→校验→注入→真跑"这条**本机无法验证**（Linux 路径 + GitHub 网络），
以下一次远端 `e2e-self-contained` 日志为准：期望看到 `▶ multi-engine-lab ... ✅ 通过`
而不是 ⏭；若仍 ⏭，日志里会有 ❌/⚠ 的哪一件取不到。

另记一条相关事实：CI 里没有"跑完测试后工作区必须干净"的门禁（`git diff --exit-code` 在
`.github/workflows/ci.yml` 里零命中），而有 22 份 `results/` 产物是被跟踪的 ⇒
"证据被改写后与仓库不一致"目前无人管；本轮只钉住了"证据会不会对自己撒谎"这半边。

### 2026-09-25 批次 · CLI 的 `-d` 也归 scope 管了；顺带把"拼错的开关静默忽略"这条假安全关掉

做 REST 直连那条红线时顺手核了第二条入口，结果是**真的不对称**：

| 入口 | 之前 | 现在 |
|---|---|---|
| REST `mode:'direct'` | 按 DB 主机判 scope（09-25 上午刚补） | 同 |
| CLI `bin/cli.js -d <dsn>` | `args.scope && **!args.direct**` ⇒ **完全不判** | 与 REST 共用 `core/scopeGuard.assertDirectDbInScope` |

而 CLI 那三行注释同时自称"与 scanRoutes sanitizeStart 同步拦截同构" —— 同构那句在我改完
REST 之后就变成假的：**同一个 `-d mysql://root@10.0.0.9/db`，从 REST 进被拒、从 CLI 进放行**。
判据搬进 `scopeGuard`（两条入口共用一份），不在任何一条入口的文件里留第二套。

### 附带挖出来的更贵的一条：CLI 解析器把无法识别的开关**静默丢弃**

`bin/cli/args.js` 的循环原本没有兜底分支 —— 拼错的开关不报错、不告警，直接当没看见。
同文件对 `--no-escape` / `--union-char` 却写着「保留显式识别并给出可操作提示，避免用户以为
传了没生效而反复排查」：政策本来就有，只是只覆盖了两个特例，其余上百个开关仍然一声不响。
代价实测落在红线上，同一个意图三种写法三种结果：

- `--driver mysql --scope 10.20.0.0/16` ⇒ 越界主机被拒（对）
- `--driver sqlite --scope …` ⇒ 内嵌驱动放行（对）
- `--scope-typo 10.20.0.0/16` ⇒ **红线整个消失，命令照常跑完、退出码 0** ← 假安全

现在：未识别开关收集进 `args.unknownFlags` ⇒ 循环结束打一条告警 ⇒ 两个入口
（`bin/cli.js` 的 main、`scripts/one-click-scan.mjs`）以 `unknownFlagError()` **拒绝启动**（退 2）。
`--no-escape` / `--union-char` 保持原政策（告警但继续），靠接在同一条 if/else 链**尾部**
实现 —— 我第一版把它写成链外的独立语句，于是 `-u`、`-d`、`--scope` 全被记成未识别，
被自己的新测试当场打回（"不该有未识别开关：-d,--driver,--scope,…"）。
台账子命令 `ledger show <scanId>` 例外：nanoid 可能以 `-` 开头，不按开关判。

**这次自查到的三处自己的错**（都靠 CI 等价命令抓回，没靠感觉）：
1. 测试里我把 flag 写成 `--driver-type`（真名 `--driver`）与 `--tech`（真名 `--technique`）
   —— 正是新硬拒该拦的那类错，于是新特性先把自己的测试拦红；连提示语里我也举了
   `--driver-type` 当反例，改成用真名，免得教人用一个不存在的开关。
2. `bin/cli.js` 用了 `unknownFlagError` 却没导入 ⇒ `tsc -p server` 与 `eslint` 各报一处
   （**这条最阴**：缺导入让 `main()` 抛 ReferenceError 也退非 0，那条 spawn 测试当时
   是"因为程序崩了所以通过"—— 补回导入后重跑才算数）。
3. 变异验证确认这条断言真承重：把入口硬拒换成 `if (false && …)` ⇒ 恰好那条"真起 CLI"的用例红，
   其余 4 条单测仍绿（它们只测纯函数，正是"只测被调函数→入口坏"的形态）；还原后重跑恢复绿。

新增测试 11 条（`cli.directScope` 6 + `cli.unknownFlags` 5）。全量：server **2372 条 0 失败**
（徽章 2720）、`tsc -p server` 零错、eslint 0 error、arch-guard 无新违规、refs/facts/readme 全过。
顺序按上一批的教训走：**先 `git add` 新测试文件，再 `--refresh --coverage`** —— 数字采自跑测试
（看得见磁盘），指纹采自 git 索引（= CI 视野），反过来必红。
`docs/_facts*` 与 README 已随本次重采落盘（覆盖率 lines 90.46 / branch 77.35 / func 79.92）。

### 2026-09-25 批次 · 搬运工具自己也得能干活：push-via-api 此前**删不掉远端文件**

症状：把废弃夹具的产物 `e2e/waf-lab/results/compare.md` 从仓库里删掉后推送，脚本按设计
拒绝更新 ref —— `⚠️ 远端多出 … / 本地 1410 / 远端 1411 条目，差异 4`。
根因不是那道校验（它是对的），是它唯一的成立前提：**"这次推送里没有删除"**。
脚本只上传"本地新引用到的对象 + 变更条目"，没有任何一步告诉远端"这条要摘掉" ⇒
只要提交里含删除，就永远推不上去，而且报错方向还指着"你再核对一遍差异"。

改法：根树那次 POST 带上 `{path, mode, type, sha:null}`（GitHub trees API 的删除语义），
422 时退回 `{path, sha:null}` 重试一次。两道安全设计写进文件头：
① **只对 blob 发 null** —— 目录由父树重建自然消失，逐个 null 目录才是能清空远端的动作；
② `PUSH_MAX_DELETIONS`（默认 50）护栏：删除数异常多 ⇒ 大概率是 `--local` 取错了提交，
宁可停下。`--dry-run` 现在先打印删除清单。

端到端验过（不只看退出码）：dry-run 列出 1 条 ⇒ 真推后校验"本地 1410 / 远端 1410，差异 0"、
ref 前进、那份文件在远端确实没了（此后远端树与本树条目数一致，含删除）。

### 2026-09-25 批次 · 废弃入口不能再"跑满一分钟然后印一行 NO"

`npm run waf-e2e` 指向 09-18 就判定失效的空壳夹具（`compare.e2e.js` 的 `/vuln` 端点纯字符串
回显、不执行 SQL ⇒ 两侧检出恒为 0 ⇒ 判据 `detectRateB > detectRateA` 结构上不可能成立）。
文件头当时写着"已失效、请勿据此判断"，但那**只是注释**：命令照旧能跑满约一分钟，
再印一行 `NO ❌` 并以 1 退出。实测代价就是本仓反复踩的那个形状 ——
读者从输出里读到的是"这个判据没通过"，而真因是"这个夹具不可能通过"，方向完全相反。

现在这个入口直接说清三件事再以 2 退出：废在哪（一句）、用什么（三条等价命令，含刚挪进
acceptance 的那份 CI 门禁）、历史实现在哪（`git log -- <本文件>`）。
整段夹具**删除**而不是留着加 `if` —— 留着就会被再跑一次，而它每次产出的都是反向结论。

顺手把这次发现的一条**可复用判据**写进文件头（当年 configB 为什么长那样）：
`randomcase` 会随机化每个字母的大小写，把 `UnionDetector` 用于确认回显的标记
`SQLISCANNER0` 打乱 ⇒ union 检测失效，表现为"开了 tamper 反而 0 检出"。
这类"绕过插件恰好破坏检测锚点"的坑不看明白就会重踩。

同时修 `e2e/README.md` 的索引表两行：
- `waf-lab` 行原先只写 `compare.e2e.js`（照着跑就掉进上面那个坑）⇒ 改成指向
  `compare-real.e2e.mjs` 并标空壳入口；
- `mariadb-verify` 行的入口在本仓并不存在（`e2e/mariadb-verify.mjs`）⇒ 真路径是
  `multi-engine-lab/mariadb-verify.mjs`（它不是独立靶场目录）。
  这类"文档索引腐烂"与当年 ci.yml 两个指向不存在文件的 job 同族，所以补了一次性审计：
  按表格逐行核入口是否存在 —— 13 行里第 1 版脚本报了 2 个，**其中一个是我自己的误报**
  （`detection-runner/run.js` 实际存在，是脚本的路径候选写错），核实后只改 mariadb 那一行。

**一处"先改文档后落事实"的自查**：`docs/waf_runbook.md` 收尾那条改成"旧产物已于 09-25 删除"时，
那两个文件其实还在树里 ⇒ 这次真的 `git rm e2e/waf-lab/results/compare.md`（并删掉未跟踪的
`compare.json`），让文档说的事实与树一致。
另核一件事：`run-all` 的 `waf-lab` 条目指的是 `compare-real.e2e.mjs` 而不是这份废弃入口，
所以把入口改成 exit 2 **不会**把任何门禁改红（也解释了这份夹具为什么能在没人察觉的
状态下烂一周 —— 没有任何门禁指着它）。

### 2026-09-25 批次 · WAF A/B 真 MySQL 门禁从"周度才有"挪到每次 push

`e2e/waf-lab/compare-real.e2e.mjs` 是真断言门禁（0 通过 / 1 判据失败 / 2 连不上库），
但它此前只挂在 `tamper-waf-matrix` job 上，而那个 job 的 `if:` 是
`schedule || workflow_dispatch` —— 也就是说**每次 push 都不跑它**。改了 tamper/WAF/通道降级
的代码，红线要等到下周一才可能亮，这跟"没有门禁"只差一句"反正会红"。

挪法与同批的 recall-lab 一样：`acceptance` job 自己起了 docker mysqld 并有
"初始化靶场库表"这一步，所以新步骤直连 3306 + `sqli_lab` 即可，不需要 Python 沙箱；
周度矩阵里那份**保留**（它走 `compare-real.run.py` 的沙箱启动器，顺带验那个 launcher），
并在两处都写了"这里不再是唯一执行处"，免得注释变成过期结论。

本机按 CI 将用的同一条路径真跑过（不是按沙箱路径跑的）：
连上 `8.0.28 @ 127.0.0.1:3306/sqli_lab`、`users` 行数=5、9.3s 跑完，
判据①拦截率 79.4%→45.7% ✅、判据②高危命中 30→0（crs_942141/942142/942180）✅、
有效性前置 A=1/1 B=1/1 ✅。失败方向也验过：`MYSQL_PORT=3399` ⇒ **RC=2** 并打印两种跑法，
不会静默当成通过。

这一步的"有效性前置"本身就是同日补的（见下面 A3 那条之前的 `evaluateAbExperiment` 一笔）：
A3 通道降级初版把 configA 打到零检出时，旧判据仍然退出 0、报告照印 ✅。

### 2026-09-25 批次 · recall-lab 的两条真实 MySQL 场景：自 09-10 写下起第一次进了自动门禁

`e2e/recall-lab/recall.e2e.js` 有 18 条场景，其中 `real_mysql_numeric` / `real_mysql_str`
需要外部 mysqld。它们此前的实况是：**任何自动路径都跑不到**——
CI 的 `recall-lab` 独立 job 没有 mysqld（步骤名当时已如实写着"16 条"，另 2 条恒 SKIP），
而端点写死 `127.0.0.1:3307` 意味着沙箱给的那个端口永远探测不到。
今天早些时候把端点改成读 `MYSQL_HOST/PORT/USER/PASSWORD`（`real-lab-driver.js:mysqlEndpoint()`，
默认值不变）之后，这条链路第一次能被指到别处；本轮把它接完：

- **CI**：`recall-lab` 独立 job 删掉，整步并进 `acceptance`（那个 job 自己起 docker mysqld，
  且 `npm run acceptance` 已经用同一套 `MYSQL_*` env）。建库不需要额外初始化 ——
  `MYSQL_INIT_SQL` 自带 `CREATE DATABASE IF NOT EXISTS sqli_test`。
- **判据（关键）**：只搬位置不够。步骤名写着"18 条"，而 mysqld 连不上时套件**仍然退出 0**、
  只跑 16 条 —— 那个数字就又成了没人验证的宣称（正是这次要修的形状）。
  所以加 `RECALL_REQUIRE_MYSQL`：声明了它就把"跳过"当失败；CI 那一步显式设 `1`。
  默认口径不变（本机没起 mysqld 不是代码缺陷，仍然 SKIP + 退出 0）。

**三个方向都真跑过**（新断言必须知道什么输入会让它红）：

| 场景 | 结果 |
|---|---|
| 带开关 + 指到没监听的 3399 | RC=1，`[FAIL] real_mysql_* … 未执行`，原因带端口与沙箱命令 |
| 带开关 + 指到可达的 3306 | RC=0，**18 条 `[PASS]`**（MySQL 两条分别检出 `[union,error,boolean]` / `[boolean]`） |
| 不带开关 + 不可达 | RC=0，仍打印"跳过真实 MySQL 场景（不 fail）"（默认未变） |

顺带修了收尾那句**误导性的归因**：它原先固定写"存在 must 未命中场景，回归失败"，
而 `failed` 也可能来自"场景根本没执行"或 `status` 非 completed —— 三种故障查法完全不同，
归成一句会让人去查一个不存在的问题。现在按明细说原因（`未执行：…` / `未达标：场景（status=…, must 未命中=[…]）`）。

**另外更正一处历史文档**：`docs/optimization-report-2026-08-25.md` 第 101 行把
"recall-lab 18 场景"当作 CI 结构完整的证据 —— 写的时候与之后很长一段时间里，
CI 实际只跑 16 条。该报告是当时快照、按本仓口径不改正文，此处留这条为准。

### 2026-09-25 批次 · 两条入口共用一个守卫：直连模式的 config 曾整段绕过 clamp

收尾清单上挂了两次的那项（"抽公共 config 守卫让直连分支也吃 clamp"）本轮做掉了，
顺带修掉同批挂着的 `manifest.summary.byRisk/byTechnique` 恒 null。

**直连那条入口坏在哪**：`sanitizeStart` 里 `mode:'direct'` 是**早退分支**，
返回的 `config` 曾是 `{...defaults, ...cfg}` —— HTTP 分支那 536 行 clamp / 形状校验 /
白名单收敛**一条都没走**。实测会原样进引擎的值：`concurrency:9999`（9999 路并发打库）、
`timeoutMs:99999999`、以及**带分号的 `dumpWhere`**（它会被原样拼进提取 SQL 的 WHERE 位，
而 HTTP 分支正是为此拒分号）。同一分支还漏了第二条播报：`warnDroppedConfigKeys`
只在 HTTP 分支调用，于是直连"传了个不生效的键"是**静默**的。

**修法按"两条入口走同一个守卫函数"，不是"在第二条入口里手挑几个键 clamp"**
（手挑 = 两张清单各自漂移，而漂移正是它当初被漏掉的机制原因）。整段守卫平移到
`api/scanConfigGuard.js:buildGuardedConfig(cfg, scopeRules)`，HTTP 与直连各调一次：

- 搬移前先用脚本核过块内依赖：只用到 `cfg` / `config` / `scopeRules` 与模块级导入，
  HTTP 专有的 url/method/params 处理**全在块外** ⇒ 能整段平移、不夹带目标解析；
- 随块搬走的还有 `PARAM_DEL_ALLOWED` / `EXTRACT_SCOPE_MODES` / `sanitizeIdentList` /
  `sanitizeExtractScope`（只有块内用到），`sanitizeExtractScope` 由 scanRoutes re-export
  保住既有引用路径；
- `scanRoutes.js` **1190 → 589 行**（arch-guard 那条 1200 软线的债一次还清，留出一倍余量）。

**同批修的输出层缺陷**：`summary.byRisk` / `byTechnique` 只在**并行的**
`ReportGenerator.build()` 里算过，而产品实际走 `createReport` → `scan/finalize` ——
于是机读清单 `scripts/one-click-scan.mjs` 的两个键恒 null。现场就是仓库里那份现成产物
`reports/127.0.0.1-2026-09-17T13-51-34/manifest.json`：findings 三条（High/Medium 齐全），
`summary.byRisk` 是 null，而同层 `totalPoints/totalVulns` 有值（那两个是清单自己现算的）。
计数现在落在**报告本体**（`finalize`），并且与 `build()` 共用 `models.countBy` 一份实现。

**验证**（三条新判据都能红，全部用变异跑过）：

| 守卫 | 变异 | 结果 |
|---|---|---|
| `api.entryParity.test.js` 三条 | 把直连的守卫调用换回 `{...cfg}` | 恰好 3 条红，还原后绿 |
| `report.summaryCounts.test.js` 两条 | 摘掉 `finalize` 里那两行赋值 | 2 条红（报"manifest 读到 null"） |
| 直连 scope / `{INJECT}` 旧判据 | —— | 4 条全过，抽取未削弱 |

搬移当场被**文本型守卫**咬到三处（`docs.configDefaults` / `configReachability.guard` /
`configDroppedKeys.warn` 都按源码文本找 clamp 收敛点）。没有放宽它们，而是把扫描范围
改成"入口层这一整簇"（scanRoutes + scanConfigGuard 并读）——这类守卫的价值就在于
"改名/挪走时先红"，所以它必须跟着事实挪，而不是被删。

**门禁**：server 全量 **2361 条 0 失败**（新增 6 条）、`tsc -p server` 零错、
eslint 零错、arch-guard 无新循环依赖。搬移涉及每条扫描的启动路径，所以改完又跑了一轮
**全量 `npm run acceptance`：15 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP（15/15 跑出断言）**
—— 比上一轮的 14 PASS + 1 SKIP 多一套件，是因为这次本机 PostgreSQL 在听，OOB 真机套件
第一次在本地跑出断言（不是被跳过）。

**这一笔推上去之后 CI 仍红了一次，红在门禁自己身上而不是代码**（`lint` job 的
`facts:check`：`指纹采集于 …（315 个文件）→ 现在 317 个`）。机制是 `facts-sync` 两个面的
**口径不对称**：用例数是"**跑**测试"得来的（看得见磁盘上的新文件），指纹却是
`git ls-files`（只看得见已入库的）——我在两个新测试文件还没 `git add` 时采的数，
于是 `_facts.json` 写着 2361（含新文件的量）而指纹写着 315（不含它们）。
**本机 `--check` 当时是绿的**（本机的索引同样没有那两个文件）——这个红只有推上去才看得见。

2026-09-22 那次修复（`TRACKED-ONLY`）处理的是**反方向**的洞（未跟踪文件污染指纹 ⇒
红得修不掉），这次补的是剩下的这一半：`--refresh` 末尾主动比"磁盘 vs 索引"，
有未入库测试源就**当场点名说清后果**（含"提交后 CI 会判采集源已改动、本机看不出来"）。
新告警按判据真跑过一遍：临时放一个未入库的测试文件 ⇒ 它被算进 2362 却不进指纹（317），
告警点名它；删掉再采 ⇒ 回到 2361 且告警静默。数字与指纹随后重新同批落盘（317 = CI 视野）。

### 2026-09-25 批次 · A3 端到端第一次真跑：挂死被读成"输出格式变了"，一路挖出门禁层三个洞

推上去之后远端 `acceptance` job 唯一的红是「WAF 通道降级编排（A3）端到端」，
理由是 `取不到画像/决策行（输出格式变了？）`。**这句归因是错的**，而且它把我支使去了
一个本来正确的方向之外：输出格式没变，是**套件一行输出都没有打出来**（它第一行正常输出
在第 164 行，所以 50..163 任何一处卡死都长这样）。本地 `timeout 90` 复现：0 字节输出、RC=124；
更关键的是**会话开始那一版（47b2768）同样挂死** —— 这不是本次改动的回归，而是这份 e2e
自接线以来从未在任何环境真跑过（CI 这次是第一次）。

用逐阶段打点的临时副本定位到三处，逐个修：

1. **`listening` 竞态 ⇒ 永久挂死**（`waf-channel-degrade.e2e.mjs`）。两个靶场几乎同时 bind，
   两条 `await new Promise(r => server.once('listening', r))` 的写法里，第二个的 `listening`
   在等第一个期间就发完了 → 事件不重放 → 永不 resolve。改成**一次 `Promise.all` 等全部**
   （监听器在同一同步批里挂完），并把 `error` 一起接住：端口被占时报 `[BLOCKED] 靶场未就绪…`
   而不是无声挂死。变异验证：把这段还原成两条 await 的副本 → RC=124 零输出（改动确为承重）。
2. **靶场解码不忠实 ⇒ 画像恒空**。`httpClient`/axios 把空格编成 `+`，线上形态是
   `id=1%27+AND+1%3D1--+-`；靶场只做 `decodeURIComponent(originalUrl)`，于是黑名单词
   `' and '`（带空格）**永远命不中** → 裸探针全放行 → `verifyTamperChains` 走"目标不敏感"
   早退分支 → `blocked=[]`、`probed=0`。也就是说：修好竞态之后它会从"挂死"变成"全红"。
   修法是给靶场补 `+`→空格折叠，与本仓 CRS 执行器同口径（`crs-engine.js` 的 `t:urlDecodeUni`
   就是这么做的）。**这是夹具 fidelity 问题，不是把测试改绿**：真实 WAF 看的是解过码的 ARGS，
   夹具替它少解一步，画像就是在量夹具。修后实测：双拦画像 `[and,or,union,select]`、
   单拦 `[and,or,union]`，7 条断言全绿，两档各 12 个探针（预算纪律那条也终于有事实可断）。
3. **门禁包装层的超时不结算**（`acceptance.mjs` 的 `run()`）。给这套件补了它该有的预算
   （自包含、无 DB、真跑约 2s ⇒ 显式 `60000`，而不是躺在 900s 默认值里烧 CI 的 18 分钟），
   补完立刻暴露：win32 上 `spawn(..., {shell:true})` 起的是 cmd.exe，`child.kill()` 只打死
   shell，孙进程仍持有 stdout/stderr 管道 ⇒ `'close'` 不触发 ⇒ **带超时的包装层自己变成无限等待**
   （实测：60s 早已到期，门禁在 200s 外还在原地等）。现在超时走 `taskkill /T /F` 连树杀 +
   5s 兜底结算（输出里带 `[TIMEOUT]`，`code:-2`），正常路径行为不变。

顺带把失败原因的归因写诚实：新增一条前置判据 —— 输出里连 `[channel-degrade]` 都没有时，
报"套件未跑到打结论那行（挂死或提前崩溃）+ stdout 尾部"，不再让人去改解析正则。
该分支用"故意挂死的桩"真跑过：60.8s 结算，理由是挂死而非格式。

**这一批的共同形状**：三个洞都在**门禁驱动层**（不在产品代码里），而且都是"注册成功但从未
在干活"——判据写了、套件接进来了、CI 也跑了，但没人看过它的真输出。教训记两条：
接进 CI 的新套件必须**至少真跑一次并读它的输出行**，以及**包装层的超时要有兜底结算**，
否则它只在坏的时候才第一次被测试。

### 2026-09-25 批次 · 推上去才发现：我本地的"静态检查"没照抄 CI 范围，lint job 当场红

推送完成后回读 CI，`lint` job **失败**（test-frontend / audit 过）。两条都是我本次改动造成的，
而且都在**本地能提前抓到**：

1. `tsc -p server/tsconfig.json` 报 `scanRoutes.js(1115)` TS2339 —— 我在 retest 里写的
   `payload.url` 落在 `sanitizeStart` 返回类型的**联合**上（直连那半边没有 `url` 字段）。
   我本地跑的是 `npx tsc --noEmit`：**根 tsconfig 不覆盖 server/**，所以那条错误根本没进视野。
   本仓记忆里明明写着"静态检查照抄 CI 范围"，我这次是拿一个不同范围的命令当成了同一个门禁。
2. `node scripts/arch-guard.mjs` 报"新债"：`scanRoutes.js` **1252 行** > 单文件 1200 上限。
   会话开始前它是 1187 行 —— 是我今天几笔改动把它推过线的（不是既有欠账）。

**修法按 arch-guard 的本意走：把代码搬出去，不是删注释凑数。** 两处抽取都是"本来就该在那儿"：

- `api/directTarget.js`（新）：直连模式的入参校验 + 规范化 + **对 DB 主机的 scope 判定**。
  它是纯函数，留在路由文件里没有理由；抽出来之后 `directScope` 那 8 条测试照过。
  文件头记着为什么只补 scope、SSRF 那半为什么保留。
- `scanConfigTuning.warnDroppedConfigKeys()`（新导出）：未知键 / 值形态不合的**播报壳**。
  判据 `diffDroppedConfigKeys` 仍留在 `scanConfigUtils` 保持纯函数（这是它自己的设计约束），
  挪走的只是打日志那一层 —— 与本文件既有的 hex/flushSession 播报同形状。

顺带把 retest 那处的参数来源说准：`bodyParams/cookieParams/headerParams` 取自 base 报告，
它们在原扫描启动时**已经过同一条守卫**，不必二次加工（我之前的注释说"顺带把 clamp 也拿到了"，
那是夸大）。改完之后 `payload` 不再 spread 联合类型，TS 那条错误从根上消失，不需要 JSDoc 强转。

结果：`scanRoutes.js` **1189 行**（比会话开始的 1187 只多 2 行 —— 今天的净增债基本还清），
arch-guard 通过，`tsc -p server` 零错，eslint 零错。受影响测试 **71 条 0 失败**
（configDroppedKeys / directScope / retestGuard / configReachability / configOrphanKeys /
configWhitelist / securityGovernance / directMode 全部）。

**流程上记一笔**：以后凡是动了 `server/**`，本地至少要跑 `npm run typecheck:server`（= CI 那条），
不能只跑根 `tsc --noEmit`；而 arch-guard 的行数上限是**软线**，接近时应当主动抽取而不是继续往里加。


### 2026-09-25 批次 · 直连模式把"两条红线"当成一条跳过了：配了 scope 仍能连任意数据库主机

清单第 ③ 条。**执行复现**：`scope:['10.20.0.0/16']` 配置下，
`sanitizeStart({mode:'direct', db:{driverType:'mysql', host:'10.0.0.9'}, ...})` 照样通过。

起因是一句看起来很有道理的注释：`直连模式不发起 HTTP 请求，跳过 SSRF 校验（无 SSRF 面）`。
**这句话一半对**——直连确实没有 SSRF 面（DB 连接是操作者明示意图，不是服务端被诱导去摸内网）；
但它顺手把 **scope** 也免了，而本仓自己把这两条分得很清（`scopeGuard.js` 原话：
SSRF 管"别打自己人"，scope 管"别打没授权的人"）。对渗透工具这是最贵的一类错位：
授权书写的是"只许打这 3 个系统"，而换个入口（`-d` 直连数据库）范围约束就不存在了。

**为什么这不是"既定取舍被推翻"**：09-08 那批审计把 scope 的覆盖点列成
「目标 + safeUrl + 二阶触发页 + 每一跳重定向」，而**直连能力是 09-09 之后才加的** ——
清单没跟着更新，不是有人决定豁免直连。带日期的那份记录不改（它是当时的事实），
把活的清单补在 `scopeGuard.js` 头部。

**修法只补 scope，SSRF 那半原样保留**。判定形状配了九个，因为"漏放"和"错杀"各有代价：
范围内 / 范围外 / **未配 scope（必须与历史完全一致）** / 主机只出现在 `connectionString` 里
（界内、越界各一）/ 内嵌驱动无主机（memory·sqljs·sqlite·pglite 不出网 ⇒ 不得误杀）/
网络驱动解析不出主机（**fail closed**：配了 scope 就是期待"未知目标不放行"）/
域名通配命中与不命中。错误码用 `SCOPE_VIOLATION(1004)` 而不是 `INVALID_TARGET`——
调用方按码分支，"没授权"和"参数写错了"在 UI 上是两句话。

新增 8 条断言（`api.directScope.test.js`），与既有 `directMode.test.js` 12 条同跑 20/20。
变异验证：把新加的 `if (directScope.enabled)` 短路 ⇒ **4 红 4 绿**，而那 4 条绿的正好是
"不该误杀"的形状（范围内 / 未配 scope / 内嵌驱动 / HTTP 分支未被弄坏）—— 说明这套断言
既会抓漏放也会抓错杀，不是一个只会红的摆设。

**同一条直连分支还有另一半没修，但已执行确认存在**：它的 `config: {...defaults, ...cfg}`
**在所有 clamp 之前返回**，实测同一份输入直连分支送进引擎的是
`{concurrency:9999, timeoutMs:99999999, ratePerSec:"20", dumpWhere:'id=1; DROP TABLE x',
techniques:['union','__bogus__'], totallyBogusKey:1}`，而 HTTP 分支同一份输入收敛成
`{ratePerSec:20, concurrency:10, timeoutMs:60000}`。正确的修法是**把 config 守卫抽成
两条分支共用的函数**（就像 retest 那格复用 `sanitizeStart` 一样），而不是在直连分支里手挑
几个键 clamp —— 后者正是本批刚批评过的"第二条路自己拼检查"。那是笔需要单独跑全量的重构，
留到下一轮，不混进这个安全修复里。


### 2026-09-25 批次 · 单点重测绕开了整条入口守卫：分号版 dumpWhere 曾经直送引擎

清单第 ② 条，**执行复现**（express + 桩 ScanManager，把真正到达 `sm.start` 的 config 打出来）。
`POST /api/scan/:id/point/:pointId/retest` 是 `merged 直送 sm.start`，绕开整条
`sanitizeStart`。实测当时到达引擎的 config：

```
{concurrency:9999, timeoutMs:99999999, ratePerSec:"20",
 dumpWhere:'id=1; DROP TABLE x', techniques:['union','__bogus__'], totallyBogusKey:1}
```

逐条对照主入口的守卫：concurrency 本该 clamp 到 1..10、timeoutMs 到 1000..60000、
`ratePerSec` 字符串本该类型归一（否则下游按"不限速"建桶——就是本批另一格刚修的那个洞）、
未知键本该 warn。**最重的一条是 `dumpWhere`**：它会拼进提取 SQL，而主入口的注释明写着
"分号是把一个条件变成第二条语句的那一步"，因此明确拒收 —— 但重测这条路把它原样放了进去。
非法 `techniques` 同理：主入口直接拒绝，这里静默透传。

修法是**复用同一个函数**而不是在第二条路上补几个检查：`merged` 先过 `sanitizeStart`
（顺带把 `bodyParams/cookieParams` 的 clamp 和 `headerParams` 头名黑名单也一起得到了，
这些同样是重测原来没走的）。

**这里有个不修就坏事的前提**：`onlyPoint` 刻意**不在** `KNOWN_CFG_KEYS` 白名单里 ——
它是服务端从报告里的真实点位算出的跨文件内部字段（`tests/configOrphanKeys.guard.test.js`
已把这类字段排除在名单外）。若直接把整条 config 塞进净化，`onlyPoint` 会被白名单丢掉，
**重测就静默退化成整站重扫**（那个退化恰好是这条端点当初要避免的事，而且它有自己的测试）。
所以顺序是：净化 → 贴回服务端算出的 `onlyPoint` → 删 `extractScope`。副产品是
override 里伪造的 `onlyPoint` 也进不来了。

**顺带修掉一处自报字段说谎**：回显里的 `configApplied.tamper` 读的是 `merged.tamper`，
而内置引擎的 tamper 在 `config.wafEvasion.tamper`（顶层 `tamper` 只有 sqlmap 桥接层用）。
⇒ 用户设了 tamper 复测，接口报 `tamper: null`（做了不说）；反过来若有人把 sqlmap 面板的
顶层 `tamper` 串进来，它会被报成"已应用"而引擎根本没看它（**报了一个不存在的效果**，
这一向更坏）。改成读引擎真正消费的键，两个方向各一条断言。

测试 5 条（`server/tests/api.retestGuard.test.js`）。写桩时踩到两次"桩不完整"，都记下来
免得下次再当成产品缺陷：① 不给 `bus.create` 返回会终结的 emitter ⇒ 模块级并发槽位不回收；
② 不给 `sm.scans` ⇒ `scanGovernance.js:83` 读 `.get` 抛 TypeError，症状长得像端点坏了。
变异验证：把净化整段退回旧的直送形状 ⇒ 5 条里 4 条红（第 3 条只测 onlyPoint 语义，
两种形状下都该绿）。还原后 5/5。

**方法论收获**：入口守卫的失效形状不是"某条路上少写一个检查"，而是**第二条路自己拼对象**。
以后看到"从同一份数据派生的第二个入口"（重测 / 复跑 / 批量导入），第一个问题应该是
"它有没有走同一个 `sanitize*`"，而不是"它校验够不够"。


### 2026-09-25 批次 · sqlmap 的 `--timeout` 收的是秒：单位没问工具，是靠问它本身才定案的

清单第 ① 条。这次不靠记忆判断单位，直接问**我们要调用的那个二进制**
（本机 sqlmap 1.10.7，`sqlmap -hh` 原文）：

```
--timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
```

而本仓这个字段从头到尾是**毫秒**：`DEFAULT_SQLMAP_CONFIG.timeoutMs = 30000` 旁边注释写着
「超时 30s」，内置面板的 slider 是 1000..60000ms。`sqlmapBridge` 却把毫秒原样推过去
（`String(Math.round(timeoutMs))`）⇒ 默认值变成 `--timeout 30000`，**30000 秒 ≈ 8.3 小时**。
后果不是"超时太短"而是相反：**单请求超时永远不会触发**，慢目标上改由本文件的
`SQLMAP_MAX_RUNTIME_MS`（默认 30 分钟）**整场击杀**，连已经拿到的结果一起丢。
用户设的这个值从来没按他设的意思生效过，而且偏的方向对扫描器是最坏的那一边。

修法：桥接层一次性换算 `Math.max(1, Math.round(timeoutMs / 1000))`，
入参守卫（1..600000ms）不动 ⇒ 亚秒级兜到 1 秒，不会发出 sqlmap 收不了的 `--timeout 0`。

**顺手发现：光改换算会修出一个反向的 1000 倍陷阱。** UI 标签原文是
`"超时 --timeout (ms)"` —— 既点名 sqlmap 的 flag（那个 flag 收**秒**）又标着 ms。
按 flag 语义填 `30` 的人，在旧代码下**恰好蒙对**（30 被当秒透传）。只改换算而不改标签，
这批人下一秒就会得到 `--timeout 1`。所以两处一起改：标签改成「请求超时 (毫秒)」，
不再在 UI 里提外部 flag 名；换算只发生在服务端一处。

**同一个契约被两处测试锁着**：改完后本文件的单位用例绿了，全跑却红在另一条
「全部新参数与既有参数共存」上 —— 它也写死了 `'30000'`。只改一处，另一处就会继续
替旧单位作证。现在两条都钉秒，并加一条 `!args.includes('30000')` 反向断言：
单位换算再退回去，这条会直接指着毫秒原文报。

**一条自查（未提交前就撤掉的结论）**：我一度把后果写成"redteam-lab 传的
`--timeout 150000` 会进 sqlmap"。查了才知道 CLI 那个 `--timeout` 是**它自己轮询扫描状态的
截止**（`bin/cli.js:238 args.timeoutMs`），根本不进 sqlmap 参数。所以本条只写经查证的
面板/默认值路径。

另：`grep -rn "byRisk\|byTechnique" server/src/` **零命中** ⇒ 清单第 ⑥ 条
（manifest 自报这两个计数）成立了一半 —— 引擎确实从不产出，脚本读到的永远是 null。尚未修。


### 2026-09-25 批次 · 导出这条路同时坏了两侧：错误信封被存成报告文件、设了 Token 就必 401

清单里第 ④⑤ 条，**都执行复现过**（真 app + 真 `fetch`）后修掉。

**复现**：起 `createApp()` 在临时端口上打下载端点，取一个不存在的 scanId ——
`format=csv → status 200 | ct application/json | 有 Content-Disposition? null |
body {"code":2001,…,"message":"扫描不存在或已结束"}`。而 `src/hooks/useScan.ts` 只判
`res.ok` 就把 `res.text()` 交给 `tauriBridge.saveFile('report_<id>.csv', …)`
⇒ **用户拿到一个装着错误 JSON 的"报告文件"**。症状会被读成"报告导出坏了/内容不对"，
真因是那次扫描早已被回收 —— 归因方向整个错。
第二处：设 `SCAN_API_TOKEN=secret123` 后 `裸 fetch → 401 / 带 x-api-token → 200`。
而这条 fetch 是 **`src/` 里唯一一处绕开 `apiClient` 的**（它要拿原始响应体做另存盘，
而 `apiClient` 的拦截器按 JSON 解包）⇒ 一旦启用 Token，**全部导出必失败**。

**修法**：后端只在**下载**这一条端点上把缺扫描改成 `404`（`/scan/:id/diff` 那类 JSON 接口
按 200+code 契约被前端正常解包，不动）；前端补发同一个 `getApiToken()`，并把
"**响应有没有带 `Content-Disposition`**"当作"这是不是产物"的判别式——不带就抛错并带上
服务端的 `message`，**任何情况下不落盘**。为什么用这个判别式而不是 content-type：
`format=json` 成功时本来就是 `application/json`，只有文件名头能区分"产物"与"错误信封"。

**测试分两层**（共 8 条）：`server/tests/api.exportNotFound.test.js` 用桩管理器起真路由，
钉 ①缺扫描 404 ②成功路径必须仍带 `Content-Disposition`（前端判别式赖以成立的前提，
谁把它去掉这条先红，而不是让前端静默退回老坑）③设 Token 时裸请求 401、带上才 200
④接线守卫；`src/tests/useScan.export.test.tsx` 用 `renderHook` + 桩 `fetch` 钉真行为。

**两次变异**：前端撤掉鉴权头 ⇒ "带 x-api-token 请求"红；把判别式改成恒不触发 ⇒
"错误信封不存盘"红；其余两条不受影响（归因清楚）。

**我自己写错的一条断言**：第 4 条测试原本写 `expect(init.headers).toBeUndefined()`，
而我实现里无 token 时传的是 `headers: {}` —— 测的是实现细节而不是不变式。改成断言
"**不许发出空的鉴权头**"（`headers['x-api-token']` 必须为 undefined），形状随便实现。

清单里还剩 4 条未复现：sqlmap `--timeout` 单位 · retest 端点绕过 `sanitizeStart` ·
`mode:'direct'` 绕过所有 clamp（含"无 SSRF 面"说法是否成立）· manifest 两个自报计数恒 null。


### 2026-09-25 批次 · 产品侧入口/输出层审计：最坏的一条不是缺陷本身，而是"夹具替产品发明了字段"

派两个只读代理分别审**入口层**（`sanitizeStart` 与路由）与**输出层**（报告/SARIF/CSV/下载），
共交回 11 条候选。**我自己复现了 5 条并修掉；剩下 6 条我不写进结论也不动手**（见文末清单）。

**输出层：SARIF 的两个映射一直是死的**，证据是仓库里那份真实产物
`reports/127.0.0.1-2026-09-17T13-51-34/`：3 条 vuln 的 `riskLevel` 是 `High/High/Medium`，
导出的 `report.sarif` 里 `level` 却**全是 error**；同一份 `report.json` 里 `vuln.url` 是
`http://127.0.0.1:8130/items?cat=1`，导出的 `uri` 却**全是 "/"**。消费方（扫描平台 / IDE 插件）
按 SARIF 的 level 做分诊 ⇒ Medium 被当严重项处理，而受影响地址彻底丢失。
根因是两行读了不存在的字段：`v.severity`（模型写的是 `riskLevel`，全仓 `server/src` 没有任何
一处给 vuln 赋 `severity`）与 `point.url || r.target.url`（真实字段是 `point.actionUrl` /
`target.baseUrl`）。

**最值得记的是为什么它一直绿**：`tests/report.sarif.test.js` 有一条
「severity 映射 critical→error / medium→warning」的断言，而它的夹具是**手写字面量**，
里面就写着 `severity` 和 `target.url` —— 夹具替产品发明了一套字段名，于是测试测的是那个
想象中的产品。修法不能只是改映射：**夹具改成由真实工厂与真实富化函数生成**
（`createInjectionPoint` / `createVulnerability` / `attachVulnContext`），再加一条夹具自检
（必须带 `riskLevel`、必须**不带** `severity`、`url` 必须由富化填上）。以后谁再手写一个不存在的
字段，夹具自检先红。
（写这条夹具时我自己又踩一次：`attachVulnContext` 是 `touched ? {...report, vulns: out}`
**返回新对象**，我第一版丢了返回值 ⇒ 富化等于没跑，症状是"地址断言红"。）

**入口层两条**：

1. `ratePerSec: "20"` 会**静默关掉限速**。下游 `createBucket`/`TokenBucket` 用
   `Number.isFinite(x) && x > 0` 判定，而 `Number.isFinite` **不做类型转换** ⇒ 字符串被判成 0，
   而 0 的语义恰恰是"不限速"（那是 P0-FIX 为 `--delay=0` 定的）。数字字符串是 curl/YAML/CSV
   里最常见的形态，且因为"键在、值也发了、只是类型不对"，连 dropped 告警都不会响。
   修法只在入口做**类型归一**（数字字符串→数字，仍不 clamp，既有「不 clamp」契约一字不动；
   非数字形态不写进 config 并喊出来，绝不解成"不限速"）。显式 0/负数仍是"不限速"。
2. 一处**假告警**：`diffDroppedConfigKeys` 算在 `BACKFILL_SCALAR_KEYS` 兜底透传**之前**，
   于是那 18 个靠兜底才进 config 的键全体被喊「设置不会生效」。实测复现：六个键
   （delay/testFilter/reqRate/maxReq/hpp/noCast）同时被报警、同时确实都在返回的 config 里。
   假告警和静默丢弃是同级的错——它把排查的人支使去改一个本来正确的配置。修法是把比对推迟到
   `return` 之前。新增的测试不是抽查几个键，而是**从源码抓全部兜底键**遍历，断言
   「告警集 ∩ 落地集 = ∅」。
   顺带看清了既有守卫为什么没拦住：它那条"噪声预算是硬约束"用例用的是**面板形态** payload，
   里面 `testFilter:''` 属"空值不算丢弃"——形状写对了，却没覆盖真实调用方会发的第二种形态。

**三次变异各自验红**：映射改回 `v.severity` ⇒ SARIF 断言红；入口去掉类型归一 ⇒ 字符串用例红；
在兜底**之前**多调一次比对 ⇒ 不变式红，并精确复刻出「18 个键被丢弃…设置不会生效」那行历史日志。

**没有自己复现、因此不写进结论也不修的 6 条**（代理自称已执行的 4 条同样待我复现）：
sqlmap `--timeout` 疑似传毫秒（且被 30 分钟上限反向击杀）· `/scan/:id/point/:pointId/retest`
疑似绕过整条 `sanitizeStart` · `mode:'direct'` 疑似在所有 clamp 之前返回（含"无 SSRF 面"那句
说法是否成立）· 导出失败时前端疑似把 200 的 JSON 错误体另存成报告 · 设了 API token 时
UI 全部导出疑似 401 · `manifest` 两个自报计数疑似恒 null。已开任务追踪。


### 2026-09-25 批次 · 先撤回一个我上一轮的判断，再去补那格"从来没人验过的 18"

**撤回**：上一轮我写"剩下最大的一块是 `XML:/*`"。两条依据当场都不成立：
① 所谓"XML 用例"是**表单字段值里含 `<?xml` 字符串**（`var=foo'||(select extractvalue(xmltype('<?xml…`），
不是 XML 请求体 —— 官方 942 回归集里几乎没有真正的 XML 体用例，实现了也不动任何数字；
② 产品侧**没有任何模块 import `crs-engine`**（`grep` 只命中 scripts 里的路径字符串），
所以这个执行器的 XML 盲区不影响扫描器行为，只影响保真度口径的完整性。
⇒ 判据没错（`XML:/*` 确实不支持），**"最大的一块"是我没查影响面就排出来的**。

**一条未决，写清楚而不是猜着改**：那 2 条误触（`942210-31/44`）这轮把触发形状定准了 —— body
`pay%3D1+OR+2%2B` 里**没有字面 `=`**，于是整串进的是 `ARGS_NAMES`，规则自己的 `t:urlDecodeUni`
把它解成 `pay=1 OR 2+` 才命中；此前"复现不出"是因为复核时把它当**值**喂。但本机没有
ModSecurity 参照，"官方会不会也命中"判不了，而且存在**反向证据**：`930100-3` 要求解析期
**不**解码，`942210` 看起来要求解析期**要**解码 —— 两条官方用例对同一件事的期望相互矛盾。
没有裁判就不动，留未决 + 这条形状记录。

**这轮真正补的是那格"从来没人验过的 18"**。`recall-lab` 有 2 条真实 MySQL 场景，代码里自
09-10 就注着"从未真正跑通"。根因不是依赖：`real-lab-driver.js` 把端点**写死** `127.0.0.1:3307`，
而 `e2e/run-with-sandbox.py` 起的是隔离 mysqld、注入的是**别的端口** ⇒ **本机不存在任何一条命令
能让这 2 条跑起来**。而且它跳过时打印的是"mysql2 不可用"，把"驱动解析不到"和"服务端没起"
混成一句话 —— 本轮我自己就被这句话误导了一次（驱动其实一直解析得好好的）。

改三处：端点全部走 `MYSQL_HOST/PORT/USER/PASSWORD`（**默认值一字未改**）；探测的是**配置里那个
端点**而不是写死的 3307；跳过原因分成两类并打印实际探测地址与可用命令。
**实测**：`python e2e/run-with-sandbox.py e2e/recall-lab/recall.e2e.js` ⇒ **18 场景 18 通过**
（`real_mysql_numeric` 检出 union/error/boolean，`real_mysql_str` 检出 boolean），
产物 `recall.md` 从 16 行变 18 行；直跑仍是 16 + 一条说清原因的 SKIP。

**CI 步骤名停止说谎**：那一步写着 `Recall-lab e2e (18 scenarios)`，而这个 job 没有 mysqld
⇒ 结构上只可能跑 16 条，退出码还照样 0。改成实话，并写明要真跑 18 该并进哪个 job
（下方 file-read/file-write 那个已经起了 docker mysqld）。**没有替 CI 做这个改动** ——
共享基础设施在本机验证不了，不该由一次"顺手"来动它。


### 2026-09-25 批次 · 夹具替规则解了一次码：两族数字同时变好，顺手撤回一条假归因

**起点是上一批留下的那条分歧**。给 `930100-3` 写归因时做了个差分：同一载荷，
**原文**喂进执行器 ⇒ 命中 930100，**预解码**喂进去 ⇒ 不命中。当时把它点名进基线了
（理由写明"根因在夹具不在执行器"），本轮去改那个口径。

**改的是裁判的输入，不是裁判的阈值**：`toReq` 一直用 `new URLSearchParams(search)` 建 ARGS，
顺手就把 query 解码了一次；而 CRS 的规则自己声明 `t:urlDecodeUni` —— 解码本来就是**规则取值链
的一环**。夹具先解，规则就会解**第二遍**：`%2527` 本该得到 `%27`，两遍之后得到 `'`。
这不叫"方便"，这叫把二次编码载荷的判定条件改了（方向上更容易命中 ⇒ 偏假阳侧）。
表单 body 与 cookies 同一口径改走原文（新增 `rawPairs`）。

**两族数字同时变好**（改前数字本轮已锁在案：942 99.3%／930 97.0%）：

| 族 | 改前 | 改后 | 收回的用例 |
|---|---|---|---|
| 942（805 例） | 99.3% | **99.6%** | 942500-3、942500-4 |
| 930（38 例） | 97.0% | **100.0%** | 930100-3（几小时前刚被点名） |

两份基线各收紧一次，并把收回过程写进各自的 `_收紧记录`。**其中一条归因被公开撤回**：
942500-3/4 原来写着"本执行器的 `t:replaceComments` 先于 `@rx` 生效，把注释吃掉了"，
而 942500 声明的变换只有 `t:none,t:urlDecodeUni`（conf 第 515 行）——**根本没有 replaceComments**，
那句话是猜测。真机制（差分量出来的）：该规则要的是 optimizer hint 形态 `/*+` 里那个加号，
夹具预解码时 `URLSearchParams` 已经把 `+` 变成空格，规则再解时形态已经不同。

**为什么这不是"改测试让它变绿"**：改的是夹具喂给规则的**输入形状**，而两族的分歧数都是
**下降**的（没有任何一条从一致变成分歧）；误触一侧 942 仍是 2、930 仍是 0。更实在的一点：
条目从基线里删掉之后，回归会被抓到 —— **这句是实测过的**：临时把 `toReq` 改回预解码，
942 与 930 两族门禁**各自 RC=1**，并逐条点名 `942500-3`、`942500-4`、`930100-3`
（README 记分板那行也从反方向报了 `README=99.6% 本次实测=99.3%`）。收紧后的基线因此
本身就是回归探测器，比把条目留在基线里"容忍"强。

**门禁自己要求的回填**：942 跑完打印 `⚠ README L604 保真度：README=99.3% 本次实测=99.6%`
（那条 WARN 是上一批装的，本轮第一次真的被用上）。据此回填 README 记分板与两处"805 条"
的口径描述（现在是 942 + 930 两族）。**没有**给 930 在记分板加行 —— 那个核对只在裁 942 时跑，
加一行没人核对的数字等于再造一个静默漂移点。

**顺带**：`decodeSafe` 因不再解码而成为未使用符号，eslint 报 error 后删除。


### 2026-09-25 批次 · 930 真正接进门禁：加一族受管，暴露的是"三处各写一份真相"

**接着上一轮做**：词典 operator 落地后 930 是 90.9%，剩 3 例。本轮把该收的收掉、把门开开。

**先补取值面**：`FILES` / `FILES_NAMES` 此前在执行器里根本没有这个 kind，而夹具的 `toReq`
也不解析 multipart —— 上传文件名（`filename="../1.7z"`）从来没进过任何变量的取值面。
补上后 **90.9% → 97.0%**（930110-10/-11 收回），普查里 `FILES` 归零（6 处→4 处）。
有意**不动 ARGS 那三行**：multipart 体今天照旧落进 `args.__raw_body`，顺手"净化"它会改变
942 那 720 例的输入面。

**最后 1 例的机制是当场差分出来的，不是猜的**：`930100-3`（`0x2e.%000x2f…`）。930100 声明
`t:none`，它的正则备选里全是 `%XX`/`0x` 形态 —— 也就是**按编码原文匹配**；而夹具构造 ARGS 时
已经用 `URLSearchParams` 解码过一次。同一载荷两条喂法：原文 ⇒ 命中 930100，预解码 ⇒ 不命中。
⇒ 根因在**夹具**不在执行器；修它要改 ARGS 的取值口径（ModSecurity 不自动解码参数），
那会同时改动 942 门禁的输入面，属另一笔"必须先拿改前数字"的改动，本轮不做，条目进基线并写明机制。

**接入门禁时发现三件必须先拆开的事**（都写成 `GATED ? … : …` 一个条件在管）：

| 名义上管的事 | 实际混着的另一件事 | 改法 |
|---|---|---|
| 是否比对基线 | 基线文件按谁的用例标题命名 | 基线**按族分文件**，942 沿用无名那份 |
| 报告文件名 | 哪一份是 README 引用的对外口径 | 命名按 `BASE_FAMILY` 判定，不按 GATED |
| 是否核对 README 记分板 | 记分板那一行是 942 的数字 | 条件改为"族 == BASE_FAMILY" |

不拆的后果很具体：**把 930 接进门禁的那一瞬间**，一次 930 测量会覆盖掉 README 引用的 942 报告、
会拿 942 的用例标题基线去判 930（红得没有意义）、还会天天 WARN 一条没人能修的记分板漂移。

**门禁名单在代码里、跑不跑在两份清单里 ⇒ 补了一道双向守卫**
（`server/tests/crsGatedFamilies.wiring.test.js`，5 条）：① `GATED_FAMILIES` 每一族必须在
ci.yml **和** ci-local.mjs 各有一步真跑它（并把 npm 脚本名解析到真实命令行，验 `--family=` 对得上）；
② 清单里出现的 `--family=X` 必须确实受管（不给免检族发合格证）；③ 受管族必须已有本族基线文件、
且每条分歧的理由自包含。为此加了跨平台的 `npm run waf-fidelity:930`
（`CRS_EQUIV_FAMILIES=930 npm …` 那种前缀在 Windows 的 cmd 壳里不生效，而"受门禁管"必须意味着
两台机器跑的是同一条命令）。**变异验红两次**：删掉 ci-local 那一行 ⇒ 守卫红（"它永远不会红"）；
词典路径改坏 ⇒ 930 门禁 **RC=1、21 条未点名分歧**（失败现场留在 `/tmp` 日志里，不是口头保证）。

**又抓到两处"结论句过期"**：`idleFamilies` 那句无条件印"非门禁族只报数不判红"，930 受管后
等于给受管族发免检声明 ⇒ 改为从 `GATED_FAMILIES` 现算；以及 —— 守卫第一次跑就抓到
`KNOWN_REASONS` 表与基线 JSON **已经不一致**（表里 `942210-44`/`942500-4` 还是"同上"，
而 JSON 里前者早被改成整段完整记录）。这正是那份文件自己注释里预言的"两处各写一份理由必烂一处"。
处理：**删掉整张表**，理由的唯一来源变成基线文件本身，生成骨架时一律写"待补理由"，
由新守卫卡住（不许"同上"、不许空）；顺手把 942 基线里残留的那条"同上"补成自包含记录。

**边界与现状**：942 复跑 99.3%／误触 2／基线 7 条点名全部仍成立（一字未动）。930 现为 97.0%、
基线 1 条、红线仍 90%（余量 2 例）。XML 载荷仍不在检测面内（`XML:/*` 3 条），`REQUEST_URI_RAW`
仍缺 —— 这两项是 930/942 共同的对外边界，别把 97.0% 外推到 XML 接口。


### 2026-09-25 批次 · 930 从"没法裁"到 90.9%：@pmFromFile 词典接上，顺带抓出自己三道空转守卫

**做了**：实现 `@pmFromFile`（`crs-engine.js:loadPmDict` + execOp 分支），并把上游两份词典
（`lfi-os-files.data` 720 行 / `restricted-files.data` 275 行，CRS v4.1.0 `rules/` 同目录）
入库、登记进 `tests/manifest.json` 的哈希账本 —— 走的是 conf 已经在用的那段核对逻辑
（`fetch-crs-assets.mjs` 的校验循环只读 `conf`/`upstreamConf` 两个字段，加进列表即可复用；
`.gitattributes` 的 `e2e/waf-real/crs/** -text` 也已覆盖 `.data`，否则 Windows 检出改行尾
会把"逐字节与上游一致"变成假话）。

**数字**（族 930，38 例 / 应拦 33，当场重测，非引用旧值）：

| | 逐规则一致率 | 误触 | 缺口 |
|---|---|---|---|
| 词典前 | 27.3% | 0 | 21 例卡在 @pmFromFile |
| 词典后 | **90.9%** | 0 | operator / 词典 / 空词典三类全归零 |

原先写在报告里的"剔除词典规则后 75.0%"是对**上限**的估计，实测越过了它 —— 因为词典规则
并不需要 `normalizePathWin`：上游条目按"最短可辨识路径"写，`....//....//etc/passwd` 里
含 `/etc/passwd` 这个子串就够了。剩下的 3 例都有名字：2 例是 multipart 的 `FILES:`（普查
本来就点名了），1 例是 `0x2e.%000x2f` 形态的 930100。**仍未接入门禁**：90.9% 距 90% 红线
只有 1 例余量，且分歧基线文件是按 942 的用例标题建的（930 要进门禁得先按族分文件）。

**抓出三道自己的空转守卫**（都是"实现了≠在干活"，只是这次的对象是我本轮刚写的代码）：

1. **Set 用 `.length` 判空 ⇒ 恒假**。`parseCrsFile` 末尾把普查桶归一成数组，我没把新加的
   `missingDicts`/`emptyDicts` 登记进去，它们留在 Set 形态；消费侧照兄弟桶的写法写
   `if ((census.missingDicts || []).length)` —— Set 没有 `.length`，于是"词典缺失"这条告警
   **永远不会响**。而同一段数据的 md 那行用的是 `[...]` 展开（Set 可迭代）⇒ 打印正常。
   **一份数据、两个真相，撒谎的恰好是更安静的那边。** 用变异验出来的：把词典路径改坏，
   md 报了缺失、控制台仍报"无缺口"，改完归一列表后两边一致。
2. **硬编码结论行**：`crs-equivalence.mjs` 的控制台里钉着"930 的主缺口是 @pmFromFile 词典
   规则未实现"，实现之后它会**继续每天印一遍已经不成立的事实**。改为按普查现算
   （operator / 词典 / 变换三类缺口全从数据生成），md 里那句同类结论一并删掉。
3. **标签与定义不符**：`idleFamilies` 的含义是"除本轮之外入库的族"，文案却写"已入库但
   **未接入门禁**的族" —— 跑 930 时它打印 `未接入门禁的族：942`，而 942 恰恰是唯一受门禁管
   的那一族，读者据此会得到一个完全反向的结论。措辞改为"未参与本轮评估"。

**差分验证**（`e2e/waf-real/selftest.mjs`，跑在 `run-all` 的 `waf-real` 套件里 ⇒ CI 与
`npm run ci:local` 都会跑到）：8 条端到端断言 + 6 条快照断言。把词典路径改坏 ⇒ **8 条红、
退出码 1、930 一致率精确回到 27.3%**；反向对照（`/index.html`、`notes.txt`、`main.css` 必须
不拦）钉住"恒返回命中"这种看起来更严的假绿。快照里钉了条目总数 936 —— 词典被人改薄也会红。

**顺带**：`IMPLEMENTED_OPS` 上方那句"只实现了**这两个** operator"注释随登记同步；
942 一族数字复跑一字未动（99.3% / 误触 2 / 720+85 例）。


### 2026-09-25 批次 · 收摊时从一份"绿着的产物"里翻出门禁洞：无区分度 ≠ 可以不看

**表面任务**：把工作区里 8 个被上一轮全量跑批改脏的 e2e 产物按信噪分掉归档。

**信号不在 diff 的大小里，在语义里**：5 个文件只有时间戳和随机 token 在动（还原），
2 个是真事实（`battery-history.jsonl` 的追加记录、`acceptance-report.md` 里误触
4→2 与新增的 A2 套件行）。第 8 个 `waf-lab/results/compare-real.md` 一版**归零**：

| | 注入点 | 检出 | 总请求 | 拦截率 | 高危命中 | `passed` |
|---|---|---|---|---|---|---|
| 已提交版（09-20） | 1 | 1 | 175 | 79.4%→45.7% | 30→0 | true |
| 工作区版（09-25 01:06） | 1 | **0** | **246** | 74%→24.5% | 58→6 | **true** |

两侧检出全零，报告照印「tamper 确已绕过 WAF ✅」、退出码 0。

**归因链**（不靠猜：产物 mtime 01:06 早于 237849e 的 01:36）：那份产物是 **A3 通道
降级初版还在工作区时**留下的现场，64c2576 的「同形态通道不得被记号画像判死」已经把
检出修回来 —— 在 HEAD 上复跑，数字与 09-20 已提交版**逐字段相同**（175/139、79.4%→45.7%、
30→0、1/1+1/1）。所以检出侧不是待修的回归；**待修的是它红了没人知道**。

**根因是判据被"整条拿掉"而不是"降级成参考"**：`compare.e2e.js` 时代查出靶子是空壳
回显、检出侧恒 0，09-18 于是把判据换成 WAF 侧两条 —— 当时的论证成立（单注入点上
error/boolean 两侧同时触顶 100%，比较无区分度）。但落地时把检出侧从 `pass` 表达式里
删干净了，它遂退化为一张永不为红的装饰性表格。零检出时"拦截率下降"完全可能只是
"扫描器不再发可执行的东西" —— **结论方向反了也不会红**。

**修法**：检出侧作为**有效性前置**接回，两侧均须 ≥1；逻辑抽成
`metrics.js:evaluateAbExperiment()`（纯函数）供单测。健康路径行为一字不变（复跑对比过），
新增的只有红路径。

**两条变异各自验红**（`server/tests/waf.abCriteria.test.js`，8 条全绿）：
摘掉 `passed: valid && …` 里的 `valid` ⇒ 3 条红（含"A3 初版现场复现"那条直接引用
0/1 + 79.4%→45.7% 的旧产物数字）；把入口退回 `const pass = criterion1 && criterion2` ⇒
接线守卫红。**第一次跑就抓到守卫自己钉错文件**（拿入口源码去匹配 `metrics.js` 里的
实现），改完才绿 —— 守卫写错的方向和被守卫的缺陷同族。

**诚实边界**：入口的**红路径本机无真实现场** —— 需要一个"两侧零检出"的靶况才能触发，
本机造不出来。它由两层覆盖：纯函数用例（拿 09-25 旧产物数字直接喂）+ 静态接线守卫。
能给出真实现场的是下一次 A3 型回归或 CI，届时"实验不成立"那句才第一次被印出来。

**顺带修三处文档与代码互相矛盾**（都是"文档教用户走一条已经不通的路"）：
- `docs/waf_runbook.md` §4 标题就叫"对比两次报告检出率"，正文预期"开 tamper 的 vulns
  明显多于关"—— 那是 **09-18 已废弃的判据**；下一步又让用户编辑 `compare.e2e.js`
  并 `npm run waf-e2e`，而那个文件的头部自 09-18 就标着「已失效，请勿据此判断 tamper
  效果」。改指 `python e2e/waf-lab/compare-real.run.py`，并写清"两侧都必须 >0 是前提、
  不是成绩"。
- `CONTRIBUTING.md` 三处：`waf-e2e` 出现在**给贡献者的验收清单**里（同上，指向废弃夹具）；
  用例数写 `~1249` 而 `_facts.json` 实测 **2320**、前端 191 → 345；`recall-e2e` 写
  "18 场景全 PASS" —— 实为 **16 跑通 + 2 SKIP**（真实 MySQL 组需本机 3307 有 root/root
  的 mysqld，`real-lab-driver.js:140` 自己记着"自 09-10 新增以来从未真正跑通"）。清单上
  写一个本机复现不出的数字，等于让每个贡献者各自困惑一次。
- 附带：游离的 `tmp_acc.bin`（215 字节的 Azure `BlobNotFound` 错误页，全仓无引用）删除。


### 2026-09-25 批次 · 「注册成功」不等于「在干活」：一个 WAF 变换修了两次才真修好

**表面任务**：补上执行器缺失的 `t:utf8toUnicode`（超长 UTF-8 折叠），它被
`applyTransforms` 的 `.filter(t => T[t])` 静默丢掉，而 `droppedTransforms` 普查已经会把
"丢了哪个变换"打印出来。

**实际上这里有两层失效，第一层修完看起来像修好了**：

1. **T 里没实现** —— 注册函数即可，这一步做完普查里 `utf8tounicode` 归零；
2. **取名正则 `[a-zA-Z]+` 砍在数字上** —— `t:utf8toUnicode` 被截成 `utf` ⇒ 查不到 T ⇒
   照样丢。而**普查用的是 `[a-zA-Z0-9]+`**，它看见"已注册"于是报"无缺口"。
   ⇒ 出现最难查的状态：**报告说缺口已补，取值链上那个变换从未生效过**。
   修法不是再补一处正则，而是让声明侧与普查侧**共用** `declaredTransforms()`（判据与执行同源）。

顺带在第一版实现里查出第二个缺陷：`/((?:%XX){2,4})/` 的贪婪量词会把**下一个序列的字节**
一起吃掉 —— `%c1%bc%c1%bc`（`||`）只折出一个 `|`。改成逐字节推进才对。

**裁判看不见这类修复**：805 条官方回归用例里**没有一条**超长编码载荷，所以从"没实现"到
"实现且正确"，保真度数字一字不动（99.3% / 误触 2 / 未点名 0 全程不变）。这类编码层修复
不可能被那批用例裁决 ⇒ 改由 `selftest.mjs` 的 5 条**端到端差分断言**兜住：
`overlong ||` / `<<` / `!=` 必须被 942120 拦下，规范 `%7c%7c`、`%25%20` 的判定必须一字不变
（防过度折叠）。断言在**旧代码上跑红过**：摘掉 `T` 里那行注册 ⇒ 5 条同时 FAIL，留了失败现场。

**普查桶"空"必须是 `[]` 而不是 `undefined`**（`parseCrsFile`）：三个桶原来只在命中时才建
Set，补全之后字段直接消失 ⇒ 新写的"清单应为空"断言以 TypeError 退出，看上去像断言写错了，
而真正该被看见的事实是"缺口没了"。

**撤回上一轮的归因（同一个提交里写的结论被本次实测推翻）**：`crs-equivalence.mjs` 曾印着
"930 一致率 13.2%，根因是缺 normalizePathWin / cmdLine / utf8toUnicode"，数字出自一个
**用完就删掉的一次性探针**。现在把它做成命令（`CRS_EQUIV_FAMILIES=930 npm run waf-fidelity`），
当场重测：**38 例、应拦 33、逐规则 27.3%，剔除 21 例 `@pmFromFile` 词典规则
（930120/930121/930130）后 75.0%，误触 0** ⇒ 主因是**词典 operator 未实现**（占应拦侧 21/33），
缺变换只是次要因素；而 13.2% 这个数本身也复现不出来。一次性探针留下的不只是不可复现的
数字，还会有**跟着一起错的归因**。

**顺带把裁判机制补齐**（都是同一族"两处各写一份真相"）：
- 族 → conf 成对：`FAMILY_CONF` + 一次只裁一族；判定循环**显式传 `confPath`**
  （原来不传就落到默认 942，跑 930 时普查按 930、判定按 942 ⇒ 一份报告两套真相）
- "已点名的不支持项"从普查推导，不再写死 `942100/942101`（写死会让换族测量的分母含混）；
  报告里 `@detectSQLi 需要 libinjection` 这类 942 专属解释也改为普查生成
- 非门禁族（930）**只报数不判红**，产物另起文件名，不覆盖 README 引用的那份
- `KNOWN_REASONS` 表里删掉两条已被真修掉的错误归因（942440-19/20），942210-31/44 改为
  "归因未证实"并指向基线文件 —— 与基线 JSON 保持一致，不再有两份会各自烂掉的解释

**README 的 WAF 数字此前无人核对**：`facts:check` 只管测试数/覆盖率，README 记分板那行
（保真度 / 未点名 / 已消失 / 误触）不在任何门禁里 ⇒ 实测出「误触 4」而门禁早已是 **2**。
回填为 2，并让 `waf-fidelity` 跑完后**当场核对这一行**、不符即点名行号与两边数字。
只 WARN 不 FAIL：那张表里混着历史轮次存档，强制回填会诱使人去改历史数字。

**环境**：`cargo clippy` 确定性抛 ICE（rustc 1.98 + `-C incremental` 坏缓存），清掉
`src-tauri/target/debug/incremental/sqli_scanner_lib-*` 即恢复；与本批改动无关（零 Rust 改动）。

### 2026-09-24 批次 · 「静默」本身就是一类缺陷：配置入口、报告出口、标定阈值三处收口

**共同形状**：不是崩溃型 bug，而是"看起来一切正常、实际少做了一件事"。本轮七笔提交按同一
判据（把**读取点**与**写入点**两边交叉，而不是靠人记）扫出来的结果：

1. **浅合并下的嵌套配置组**（`69633c6` / `67871e9`）：`models.js:90,113` 是
   `{...defaults, ...input.config}` 的**浅**合并，所以请求体里出现某个组，该组就整体替换
   defaults 的同名对象；组内少转发一个子键，引擎看到的就是 `undefined`。REST 的
   `wafEvasion`（9 键重建 4 键）、`blindRobust.extractVerify`（13 漏 1）、
   `secondOrder.secondMethod/triggerMethod` 三处断口，加上 **CLI 是另一条独立入口**、
   只修 REST 等于没修（`--tamper` 让 `filterAdaptive` 从 true 变 undefined，而引擎判据是
   `=== true` ⇒ 关键词静默过滤型目标的自适应重跑整轮消失，扫描照常报绿）。
   同批把 `compactErrorTemplates` 从 `defaults.wafEvasion` 移到引擎真正读取的顶层，
   并删掉一个恒为真的死条件 `fullErrorTemplates`。
2. **报告的 markdown / CSV 出口**（`bd9a65b`）：HTML 侧一直有转义，`.md` 侧只防拆表的 `|`
   —— 参数名里的 `<img src=x onerror=…>` 原样进正文，而 pandoc / markdown-it 默认保留行内
   HTML ⇒ 在**读报告的机器**上执行；行内代码用 `\`` 转义反引号在 CommonMark 里是空操作；
   CSV 拖库列头是全仓最后一处无公式守卫的出口；`isInternalHost` 被
   `[::ffff:127.0.0.1]`（URL 规范化成 `::ffff:7f00:1`）绕过 ⇒ 报告里留下可点的回环链接。
3. **11 个"注释承诺可配、实际无人能设"的旋钮**（`ae38595` / `14fd87f`）：
   `http2` / `disableKeepAlive` / `xpAutoEnable` / `noSql.concurrency` 加上一批提取与统计层
   调优键。判据换成不依赖 CLI 的版本后新增 `server/tests/configOrphanKeys.guard.test.js`：
   可达 = 白名单 ∪ defaults ∪ CLI 写入 ∪ 前端声明 ∪ 同文件内部字段，**新孤儿即红、
   过期豁免也红**（它当场抓到我抄错的 5 条豁免）。`StackedDetector` 那个假旋钮
   （`sleepSecs`）不配新钥匙，改成认已有的 `timeBlindSleepSec`。
4. **白名单内"值形态不合被丢弃"也开始喊 warn**（`ad7da92`）：此前只有"键名写错"会 warn，
   `matchCode:200` / `skipParams:"id,page"` 这类一声不响，而后果完全相同。判据抽成纯函数，
   并钉住"一份合法的面板形态 payload 不产生任何丢弃告警"——加告警先算误报率。
5. **时间盲注标定探针量纲错**（`8cc9757`）：拿**绝对耗时**去比**增量下限**，把页面自身基线 μ
   白送给了探针。默认档可达：μ≈1.2s 的站上 1s 探针实测 1.5s 就"标定成功"，而判定需要
   ≥ μ+absFloor = 2.0s ⇒ 之后每次采样恒判未延迟，**只在开了标定的慢站上漏报**（既有三支
   测试的 base 都是 0，两种算法同解，故缺陷活到今天）。改成与检测实际阈值同量纲比较。
6. **docs/api.md 与代码口径对齐 + 守卫**（`9e63bdb`）：`retry`「默认 2」实为 3、
   `timeoutMs`「默认 10000」实为 30000、`maxColumnsGuess`「默认 10」实为 50。
   README 有 `readme:check` 盯着，REST 配置表此前一道门禁都没有。

**方法论（本轮四条硬教训）**：
- 一条修复要**逐入口**验：REST 与 CLI 是两条独立通路，只修一半等于没修；
- 断言不能只写"键存在"——`!== false` 型判据下 `undefined` 与默认开恰好同值，
  必须断"等于 defaults"并**反向**逐键发非默认值；
- 子代理给的引擎侧结论 4 条里 3 条不成立（`dumpTarget` 转义、`level=0`、`fillPayload`
  非字符串），全部经实测撤回 ⇒ 结论一律先复现再修；
- 新写的守卫必须**先在旧代码上跑红**再恢复修复（本批两支都留了失败现场）。


### 前端可达性：两条整通道 + 五个假暴露键接进面板；契约测试判据修正

**病灶（两个，同一族）**：

1. **整通道无入口**：`oob`（带外）与 `secondOrder`（二阶）在引擎与 REST 白名单里都支持，
   前端只在 `KNOWN_MISSING_UI_KEYS` 里当债记着 → Web / 桌面端用户永远测不到这两条通道
   （带外通道在「无回显 + WAF 拦 sleep/报错/union」的场景里是**唯一可达**的一条）。
2. **假暴露（本轮新发现）**：契约测试把「登记在 `SCAN_CONFIG_KEYS`」当成「有 UI 入口」，
   于是 5 个键长期处于「登记在案（故不算缺口）+ 面板从未渲染控件（故用户改不了）」：
   `noSql`（NoSQL/GraphQL/SSTI 整条通道）、`prefix`、`suffix`、`sessionFile`、`timeThresholdMs`。
   判据与危害不同源（判的是「登记没登记」、危害是「有没有开关」），所以 CI 一直绿。

**修复**：

- 新增「非 SQL 注入检测」「带外通道（OOB）」「二阶注入」三个分组，含危险动作告知：
  二阶开启即发出**真实写请求**、OOB 会启动接收端等待回连
- 请求控制组补 `timeThresholdMs` / `prefix` / `suffix`；会话持久化组补 `sessionFile`
- 契约测试新增**判据 ⑦**：登记为「UI 可控」的键必须在面板源码里**真有写入**
  （由 `handle*('k')` / `onChange({ k: … })` / `patchNested('k', …)` 等模式提取），
  并对 `patchNested` 这类新写入方式同步补 pattern —— 守卫看不见新写法就等于没守卫
- `KNOWN_MISSING_UI_KEYS` 移除 `oob` / `secondOrder`

**顺带修掉一个不可达能力**：`secondUrl` / `secondMethod` / `secondData`（读写分离二阶注入，
对标 sqlmap `--second-url`）。`SecondOrderDetector._trigger` 一直在读它们，但 REST clamp 不保留、
CLI 无处可设 → **三条路径全不可达**（与 `extractScope` 同一病灶）。现补 clamp 保留 + 面板入口，
并按**触发页同级**处理安全：`secondUrl` 同样过 `assertSafeHttpTarget` + `assertInScope`，
不通过则清空回退触发页（引擎侧 `so.secondUrl || url` 语义天然安全）。

**验证**：

- 新增 `server/tests/configNested.guard.test.js`（5 例）：把**面板会产生的形状**喂给 `sanitizeStart`，
  断言每个子字段都活到引擎（拼错一个字段名 = 面板显示已配置、引擎用默认值），含反向
  （非法类别过滤 / 越界 clamp / 非 http(s) URL 清空 / `allowWrites` 严格 true）
- 该测试首版自己抓出两条**我写错的断言**：`sanitizeStart` 不注入未传的键（默认值由引擎侧合并）；
  `clampInt` 越界行为是**夹到边界**而非回落默认值 —— 已按实测行为修正并留档
- 缺陷注入复验：判据 ⑦（撤掉 `prefix` 控件写入 → **恰好 1 红**）、`secondUrl` 可达性
  （撤掉 clamp → **恰好 1 红**且点名「secondUrl 必须落地」）
- 前端 332 通过 / 服务端 2239（2236 pass / 0 fail / 3 skip）；`typecheck` 前后端 0 错；
  `lint` 0 error；`arch:guard` 通过（面板 889 行 < 1200 上限）

**遗留**：OOB 与二阶的**端到端效果**需真靶场验收（CI 恢复后）。本批只保证「配置能到达引擎」，
不申明检出率变化。

### payload 声明式化收口（E5-2）与 README 口径守卫

**E5-2 交付**：681 条声明式条目外置到 `server/src/engine/payloads/registry.json`（每条一行，可直接 diff），
`payloadRegistry.js` 167.2 KB / 982 行 → 15.9 KB / 268 行，只留逻辑（高危池门禁 / `selectPayloads` /
版本过滤 / boundary 排序）。切换前后业务字段逐条等价。

三处配套（缺一条这批就不完整）：

- `arch-guard` 补 `.json` 字节判据 —— 数据换了容器，体积债不该因此隐身（原判据只扫 `.js/.mjs/.ts`，
  150 KB 会凭空消失、门禁报告看不出任何变化，那正是「判据被绕过」的形态）
- `eslint` `ecmaVersion 2022 → 2025`：`import data from './x.json' with { type: 'json' }` 在
  2022/2024 下解析失败（espree 实测），2025 起支持
- 新增 `server/tests/payloadRegistry.fingerprint.test.js`：条数 + id 序列（顺序即投放优先级）+
  内容指纹三层钉住数据，`note` 与行为指纹解耦。**起因**：既有 34 条测试对「模板正文被改坏」
  零覆盖 —— 实测把 `AND 1=1` 改成 `AND 1=9` 仍全绿（它们断言的是条数/id/level/risk）

**新增 README 口径守卫**（`scripts/readme-consistency.mjs`，10 判据 + 16 类自证样本）：
同一事实在手写文本里被说成几个版本、且没有任何判据 —— 这类漂移现有门禁全都看不见
（`tamper:parity` 管的是「对齐 sqlmap 官方清单 84/84」不是总数；`facts:check` 管测试数与覆盖率）。
判据分两层：① README 内部自洽（方言分层三处表述两两比对 + 跨层重复检测）；
② 对代码取数源（检测通道 ↔ `VULN_TAXONOMY`、tamper 数 ↔ 运行期注册数、payload 分项 ↔ `PAYLOADS` 系列）。
**刻意不纳入**「62 WAF 指纹」（`WAF_RECOMMEND_MAP` 有 64 键含 2 个非厂商项 → 取数口径两解，
加守卫会造出脆弱判据）与「1870+」（约数），理由写在文件头。

**顺带修正 4 处对外口径漂移**（均自 2026-08-23 快照后未更新）：

| 项 | 原值 | 实测 |
|---|---|---|
| 方言分层 | 4 真实 + 3 部分 + **11** 模板 | **6 + 3 + 9** |
| payload 主库 / 子句 / 注册表 | 1779 / 82 / **672** | **1769 / 137 / 681** |

第一处的危害不是「数字错」而是**对外低估自己** —— 4+3+11=18 与 6+3+9=18 都自洽，读者看不出破绽。
⚠️ payload 计数有两种口径：同一模板跨库/技术重复，**含重复 1769 条、去重仅 959 条**；README 用前者，
换口径等同改语义。该守卫**接线三处**（`ci.yml` lint job + `scripts/ci-local.mjs` GATES +
`package.json` 的 `check:all`，漏一处 = 空转）。

**验收**：缺陷注入复验 3 类（方言三数 / 检测通道双向集合 / payload 注册表数）注入后精确点名、
恢复后全绿；`build:engine` 打包 + 内置冒烟通过（确认 JSON import attributes 在 esbuild bundle 后可用）。

### 接线：T1 / T2 正式接进验链流程（保守回退，零额外请求）

此前 `core/waf/bypass/semantics.js` 与 `searcher.js` **没有任何生产调用点** —— 只被彼此和测试
引用。弹药库建好了但没接上枪，正是本仓最忌讳的形态（"配置里写了、实际没人跑"）。

**接线方式**：把「画像 → 候选池」抽成可单测的纯函数 `buildCandidateChains(静态链, 被拦词, opts)`：

1. 先走既有 `rankChainsByProfile` 重排静态链 —— **不重写第二套排序**；
2. 再追加定向生成的补充链。

`chainVerify` 侧只改两行（import + 一行调用），逻辑内聚在 `searcher`。

**保守回退（这次敢接线的前提）**：静态链整体保持在生成链之前。
→ 新逻辑无效时，前 `MAX_CHAINS` 条与改造前**完全一致**；且**零额外请求** ——
生成链只用已拿到的画像做纯计算，请求数仍由 `MAX_CHAINS` 截断决定。

**验证**（新增 7 例）：

- 无画像 → 候选池与改造前**逐字一致**（`deepEqual`，不是"看起来一样"）
- 静态链全被拦 → 定向生成的 `symboliclogical` 能顶上并被采纳，vendor 带 `bypass:` 标记
  （报告里可区分"静态推荐"与"定向生成"的来源）
- 静态链能过 → **不再花请求**验证生成链（实测该形态请求数为 0）
- 缺陷注入复验：注入 A（去掉生成链）→ **恰好 2 红**；注入 B（顺序颠倒）→ **恰好 2 红但不同的两条**
  （A 命中"生成链顶上"，B 命中"静态链先试"）→ 影响域可区分，无误伤
- `arch:guard` 确认 **无新增循环依赖**（`searcher` → `blockProfile` 单向）

⚠️ **踩坑**：`searcher.js` 在 `core/waf/bypass/` 子目录下，import 同级模块要写 `../blockProfile.js`
—— 首版写成 `./blockProfile.js`，两个测试文件整体加载失败（模块解析错误，报的是
"Cannot find module .../bypass/blockProfile.js"，不是逻辑错）。**新建子目录模块时 import 要往上一级。**

**遗留**：接线改变了候选池内容，属行为变更 —— 端到端效果需真靶场验收
（`pentest-lab` 的 `waf403` / `bl` 场景），攒到 10/1 交 CI。

### 新增：payload 声明式 schema 与校验器（E5 第一步 —— 只定义与校验，不切换加载源）

E5（payload 声明式 DSL）是个大改造，按比例分两步。本步**只定义 schema 并校验现有数据，
不改任何取数路径**：`payloadRegistry.js` 仍是唯一加载源，**零行为变更**。

**为什么必须先做这一步**：直接抽 YAML/JSON 的风险是「schema 与真实数据对不上」—— 681 条里有
多少可选字段、枚举实际取到哪些值、有没有既成事实的脏数据，不先量清楚就动手，
切换时只会把问题搬过去再爆一次。

交付 `server/src/engine/payloadSchema.js`：

- 枚举：`TECHNIQUE_VALUES` / `WHERE_VALUES` / `CLAUSE_VALUES` / `POSITION_CLAUSES`
- 区间：`LEVEL_RANGE`（1-5）/ `RISK_RANGE`（1-3）（沿用 sqlmap 分级约定）
- 校验：`validatePayloadEntry` —— 结构/枚举越界判 **error**；一致性可疑判 **warning**（不阻塞，
  避免把「我没理解的合法用法」误判成错误）
- DSL 化前提：`isJsonSafe`（YAML/JSON 装不下 undefined/函数/Symbol/BigInt）+ `toDslEntry`（往返无损）
- 防漂移：`KNOWN_FIELDS` —— 数据里出现的字段必须都在清单内，否则 DSL 化会**静默丢字段**

**实测结果（本步的核心产出就是这条判据）**：现有 **681 条全部通过校验**；id **零重复**；
**全部 JSON-safe**；`toDslEntry` 往返**深相等**；字段**无遗漏**；一致性 warning **0 条**。
→ **现有数据可被 DSL 无损表达」，把加载源切到 YAML/JSON 具备可行性。**

⚠️ **schema 被真实数据校准了两处**（首版判据太窄，被实测打回）：

1. `where:'position'` 的位置类子句漏了 `update` —— `mssql-bool-update-1` 正是
   `clause: ['update'], where: 'position'` → 补进 `POSITION_CLAUSES`。
2. 曾加「boolean 必须有 falseTemplate」的 warning —— **不成立**：boolean 条目有**两种合法形态**，
   成对型（template + falseTemplate）与**半边型**（template 内容本身就是假值半边，如
   `mysql-boolean-100` 的 `{ORIG}' AND '1'='2`，配对在上游完成）。单个条目层面无法区分
   「漏配」与「刻意半边」，加这条只会制造噪声 → 已移除并写明原因。

**验证**：新增 11 例单测；缺陷注入复验（枚举检查短路 → **恰好 1 红**；`KNOWN_FIELDS` 移除
`boundary` → **恰好 1 红**；撤销后 11/11 绿）；`typecheck`/`eslint`/`arch:guard`/`facts:check` 全绿。

**下一步（本步未做）**：把加载源切到 YAML/JSON —— 属行为变更，需单独评估与靶场验收。

### 新增：报告「攻击路径」叙事 —— 交付四件套补齐（内联 SVG，离线可用）

方案 §E3 的四件套里 CVSS / PoC 复现包 / 管理层摘要**都已实现**，唯独缺攻击路径叙事：
读者拿到的是一张漏洞列表，而不是「从哪个入口、经什么通道、拿到了什么、影响边界在哪」的一条链。

交付 `server/src/services/reportAttackPath.js`（照 `reportPoC.js` 的**叶子模块**模式）：

- `buildAttackPath(report)`：纯只读派生 —— 数据全部来自既有 report
  （`target` → `points` → `vulns` → `data.rows` → 影响面），**不新增任何探测**
- `attackPathMarkdown(report)`：返回**行数组**（与 `pocMarkdown` 契约一致）+ mermaid 代码块 + 编号步骤双轨
- `attackPathHtml(report)`：**内联 SVG** 纵向流程图

**为什么出图不用 mermaid**：报告是离线交付物（客户可能在内网打开），mermaid 依赖 CDN 的 JS ——
断网即整张图不显示。内联 SVG 自包含、可打印、可被邮件正文带入；markdown 侧保留 mermaid 代码块
（渲染器支持时更好看，不支持时是纯文本，**不会坏掉**）。测试对"自包含"做了机械断言：
SVG 段不得含 `<script>`、不得出现任何外部 URL 引用。

**诚实边界**（红线「不谎报」的延伸）：路径层级**只按报告里真实存在的证据推进** ——
没有 `data.rows` 就停在「已证实可注入」，**不虚构**「已提权 / 已写入 shell」；
止步时显式写明「利用链未在本报告中执行或未留存证据」。测试把这条钉死：
无 `data` 时**不得**出现「数据获取」段，且 note 必须包含「不等于目标安全」。

**接线约定**：`toHTML` 与 `toMarkdown` **同序**插入（结论可信度之后、漏洞清单之前）——
两种格式的叙事顺序必须一致，否则同一份报告换个格式导出，读者看到的"故事走向"就变了。

**验证**：
- 新增 10 例单测；报告相关套件 **138/138**（含 13 个既有测试）无回归
- 缺陷注入复验：注入 A（诚实边界三处分支短路）→ **恰好 1/2/3 红**；注入 B（去掉 label 转义）→
  **恰好 7 红**；撤销后 10/10 绿。两个注入的影响域互不重叠，无误伤
- **端到端**：用真实感 report 走 `ReportGenerator.toHTML()` 生成 HTML（16KB），
  5 个阶段全部渲染进 SVG、无外部引用
- 服务端全量 **2186 用例 / 2183 pass / 0 fail / 3 skip**（上轮 2176 → +10）
- `typecheck:server` ✅ · `eslint` ✅ · `arch:guard` ✅ · `facts:check` exit=0

**已知小债（未动，避免行为变更）**：`ReportGenerator._escape` 用**命名实体**（`&quot;`），
而共享的 `reportHtml.esc` 用**数字实体**（`&#34;`）—— 两套转义并存。都是安全的（无 XSS 面），
但口径不统一；统一它属行为变更，需单独评估（本模块用的是共享 `esc`，与报告其余部分一致）。

### 新增：WAF 对抗的「语义选弹」—— 给既有 tamper 库补机器可用的元数据

**先纠偏**：`docs/全方面优化方案` 原计划新建「语义等价变换库」，核实后确认**它已经存在** ——
`core/tamper/plugins/` 的 228 个插件已覆盖方案表格里的**每一类**等价变换
（逻辑算符 `symboliclogical`、比较算符 `equaltolike`/`equaltorlike`/`noequals`/`between`、
空白 `space2*` 60+、函数等价 `substring2mid`、字符串构造 `hexliterals`/`quote2hex`、
数字 `scientific`、结构 `misunion`/`0eunion`、版本注释 `versionedkeywords`/`modsecurity*`）。
照方案再写一份＝重复造轮子，且会立刻与既有链守卫（幂等 / terminal / dbms 过滤）脱节。

**真实缺口是元数据维度**：既有插件只有人类可读的 `description`，没有机器可用的
「消除哪些 token / 引入哪些 token / 付多少标点代价」。危害有实测证据 ——
`wafRecommend.js` 记录 `symboliclogical` 在 CRS 下是**负收益**（942120 正则直接含 `&&`/`||`），
即**收益方向无法从名字推断**，这才是"有弹药没枪法"的成因。

**本次交付**（`core/waf/bypass/semantics.js`，不复制任何变换逻辑）：
- 语义索引三维度：`eliminates`（字面消失）/ `mutates`（字面仍在但被打散，选弹须排除）/
  `reducesPunct`（降低最长非词字符连续串）
- 定向选弹 `selectByAvoiding(黑名单)`：mutates 命中即排除、eliminates 命中即加分、
  unclassified 在黑名单非空时保守排除；最终交既有 `TamperRegistry.validateChain` 把关
- 代价度量 `maxNonWordRun`：对齐 CRS 942460「4 连非词字符」的真实判据
- 启动期完整性断言：索引里写错插件名当场报错（防腐烂，对齐 `assertTamperNames` 既有做法）

**元数据接受机械检验**（新增 14 例，不看人工声明）：每条 `eliminates` 都用插件自身的
`transform` 实测兑现，且**样本先自检确实含该 token**（防断言空转）。检验当场打回 **3 处错误声明**
——全部是我写的，不是插件的问题：

| 错误声明 | 事实 | 处置 |
|---|---|---|
| `substring2leftright` 消除 substring | 只认 PostgreSQL 的 `SUBSTRING(x FROM y FOR n)` 拼写，**逗号形态空转** | 补 `applicablePattern` + 写明边界 |
| `dash2hash` 消除 `--` | `1-- -` → `1-- `，`--` **仍在** | 新增 `reducesPunct` 维度（4 连 → 1 连） |
| `space2span` 消除空格 | 替换文本 `<span> </span>` **本身含空格** | 改按 `mutates` 建模 |

**缺陷注入复验**：注入 A（让 mutates 排除路径真正不可达）+ 注入 B（制造一条不成立的 eliminates）
→ **恰好 2 条红**（机械检验 / mutates 排除），其余 12 条保持绿 → 恢复 14/14 绿。

**诚实边界**：228 个插件中精标 45、族派生 77、**未分类 106**（不假装全覆盖）；
`maxNonWordRun` 是**相对指标**（同一目标下比较两套链的优劣），不是 CRS 分值的精确复算
（本项目已实测 JS 的 `\s` 与 PCRE 存在差异）。

### 新增：定向变异搜索器 —— 按被拦词表**组合生成**候选链（A2 的真缺口部分）

**先核实、划清分工**：A2 原计划五步，核实后**前四步已存在**于 `core/waf/`：
拦截画像（`blockProfile.profileBlockedTokens`）、预算封顶（`maxProbes` / `MAX_CHAINS`）、
按画像重排（`rankChainsByProfile`）、逐链探针验证（`chainVerify.verifyTamperChains`，
且已有 `[A2-2026-09-21]` 接线）。→ 新模块**不重复其中任何一条**。

真缺口是：候选**只来自静态推荐表**（`wafRecommend` 的 3 条），所谓"定向"只是"3 条里挑"，
不是"按黑名单从 228 个插件里组合"。新增 `core/waf/bypass/searcher.js`：

- `planChainsByProfile(被拦词)` → 单插件 + 双插件候选；排序 = 针对性优先 → 覆盖被拦词多者优先 → 标点代价小者优先
- 兜底弹药（整串编码）**整体排最后** —— 它要求目标做预解码才有意义，不该霸榜（否则等于退回盲试）
- `mergeCandidateChains` → 静态链**保持首位**（保守回退：新逻辑无效时行为退化回改造前）

**过程中抓到并修复 2 个真实缺陷**（都不是本次新代码引入的）：

| 缺陷 | 事实 | 处置 |
|---|---|---|
| `TAMPER_COVERS` 有 **5 条腐烂条目** | `logical_operators` / `comment` / `versionedcomments` / `modsecversionedkeywords` / `charcode` 在注册表里**不存在** → 这些覆盖声明**从出生起就没生效过**，且没有任何门禁会因此变红 | 按本仓「显式登记 + 双向检查」模式引入 `UNREGISTERED_COVER_NAMES` 白名单，测试双向守卫（**不删条目、不猜作者意图改名**） |
| `selectByAvoiding` 把**清单当链** | 首版对它调了 `validateChain(usable)` —— 那是**链级**判据，`charencode`（terminal）之后的所有插件被静默截断；症状：拦 `and`/`or` 时 `symboliclogical` 整个丢失、候选池只剩编码兜底（选弹形同虚设） | 移除该调用（逐链校验的正确位置在 `searcher` 的 `push()`），并加断言「usable **不得**因含 terminal 插件而被截断」防回归 |

**`eliminatesAll` 又被机械检验打回一次**：首版按族规则 `/encode$/` 给整族声明「整串编码」，
实测族内 **14 个只有 6 个**成立 —— `htmlencode`（输出 `1&#32;AND&#32;1&#61;1`）、
`octalencode`、`floatencode`、`doubleencode`、`dbase64encode`、`unhtmlencode` 的关键词原样还在。
→ 改为**逐条实测精标** 6 个（charencode / chardoubleencode / charunicodeencode /
charunicodeescape / base64encode / hexentities），并加断言：声明 `eliminatesAll` 的插件
必须让 AND/UNION/SELECT 明文真的消失。**「从名字推断元数据 = 猜」再次应验。**

**缺陷注入复验**：注入 A（让 `eliminatesAll` 判定不可达）→ **恰好 1 条红**（兜底链测试）；
注入 B（把清单当链的回归）→ 恰好 1 条红（不得被截断）；两者撤销后 26/26 绿。

**验证**：新增 12 例（T2）+ T1 扩到 14 例；`typecheck:server` ✅ · `eslint` ✅ ·
`arch:guard` ✅ · `refs:check` ✅；既有 waf/tamper 套件 29/29 无回归。

### 修复：`tamper-waf-matrix` 的空转静音 —— 一个真门禁被 `continue-on-error` 吞掉

该 job 的 `if:` 只允许 `schedule` / `workflow_dispatch` 触发，**根本不在 PR/push 上跑**，
所以旧注释「带 continue-on-error 是为了不阻塞正常流水线」是个**过期前提** ——
`continue-on-error` 在这里买不到任何"不阻塞"的好处，唯一效果是让失败也报成绿。

读代码发现两步**性质不同**：

- `e2e/tamper-matrix/tamper-test.mjs` = **纯测量脚本**（输出绕过矩阵，无断言、不设退出码）
  → 保留 `continue-on-error`，但改名去掉"门禁"暗示，并**上传产物**
  （`results/` 都在 .gitignore 里，不传就从 CI 取不回，这步等于白跑）。
- `e2e/waf-lab/compare-real.run.py` → `compare-real.e2e.mjs` = **真断言门禁**
  （`process.exit(pass ? 0 : 1)`；`run.py` 忠实透传 rc）→ **去掉 `continue-on-error`**。

这与之前那次「`node <不存在的文件>` + continue-on-error = 空转门禁」**同源**：
上次修了**路径**，没修**静音**。

### 决策：fileRead 起不来沙箱判 **BLOCKED**；判据抽出可单测并补两种漏检形态

`acceptance` 里「隔离沙箱没起来」的判据原先只认一种形态（traceback 栈顶在 `mysql_sandbox.py`）。
实测（对 3 组输入做探针）证明它**漏检两种**，且这两种恰是 CI 容器最常见的：

| 形态 | 旧判据 | 现判据 |
|---|---|---|
| 沙箱内部抛错（traceback 在 `mysql_sandbox.py`） | ✅ | ✅ |
| 启动器 import 失败（traceback 在 `run-with-sandbox.py`） | ❌ 漏检 | ✅ |
| 无 traceback（容器缺 python/mysqld） | ❌ 漏检 | ✅（要求"从未就绪"） |

漏检后果是把「验证装置没起来」误判成 **FAIL** —— §G「把环境问题归给被测代码」的重演。

**口径**：判 **BLOCKED**，既非 SKIP（会让覆盖静默归零）也非 FAIL（会把人引去查产品代码），
但**与 FAIL 一样进 failed、非零退出** —— 变的只是语义标签。

⚠️ **形态③ 第一版写错、被真实数据打回**：第一版是「有 `[sandbox-run]` 前缀 + 无 PASS/SKIP」，
拿仓库里**真实的历史失败现场**（`e2e/results/last-failure-oob-real-lab.log`：沙箱就绪、PG 缺失）
与一个合成的**真回归样本**去验，发现它会把「沙箱正常、靶场正常、但断言真失败」也判成 BLOCKED
→ **真回归被掩盖**（放水方向，比漏检更坏）。改为**要求「就绪」这行不存在**。

**验证**：
- `e2e/lib/suiteVerdict.test.mjs` **12 例**，含 4 条**反例**（真回归不许被贴环境标签、
  真实历史现场不许被认领、SKIP 优先于沙箱判据、正常输出不许误判）。
- **缺陷注入**：把 `isSandboxDead` 短路成恒 `false` → 恰好 4 条变红（3 形态 + BLOCKED 归类），
  4 条反例**保持绿** → 恢复后 12/12 全绿。
- **接线**（避免"写了但永远不会跑第二次"）：`e2e/*.test.mjs` 不在 `server/tests` / `src/tests`
  的发现范围里 → 已在 ci.yml 的 lint job 与 `scripts/ci-local.mjs` 各加
  `node --test "e2e/lib/*.test.mjs"`。**必须用 glob**（`--test <目录>/` 会把目录当模块 require，
  实测 1 fail）。

### 新增：注入请求支持以 multipart/form-data 发送（补齐一项真实能力缺口）

**缺口**：引擎此前只能以 **urlencoded 或 JSON** 发出注入请求（`buildInjectionRequest` 的 body
分支就这两条路）。碰到**只吃 multipart** 的目标 → 目标解析不到字段 → **注入值从未进 SQL
→ 静默 0 检出**（不报错，属于最危险的一类：症状与"没洞"无法区分）。
注意：`-r` 导入侧（`requestCollectionParser`）**早就能认出** multipart 的字段名 ——
真正缺的一直是**发送侧**。

**修法**：目标请求头声明 `multipart/form-data` 时，按其 boundary 重建 multipart 报文
（文本字段 + 闭合段），未声明 boundary 时自动生成。
已知限制：只重建**文本字段**，file 类型字段以空值占位（字段名仍在）—— 注入面在字段名/文本值上，
对 SQL 注入检测无影响。

**验证**：
- 单测 **5/5**（`server/tests/injection.multipart.test.js`）：multipart 报文契约，
  外加两条回归（普通表单仍是 urlencoded、JSON 目标仍走 JSON 分支且点路径叶子被替换）。
- **缺陷注入复验**：让 multipart 分支不可达 → **恰好 3 个 multipart 用例变红**，
  回归用例不受影响；恢复后 5/5 全绿。
- 端到端：pentest-lab 新增 `/mp` 靶点（只接受 multipart，其它 Content-Type 一律 415）
  + `verify.mjs` 新增 `mp` 场景 —— 由 CI（有 MySQL）真验。

### 修复：前端导入 multipart / JSON 抓包拿不到字段名（与上条同源的另一端）

引擎发送侧修好后，UI 的**导入侧**还停在原地：`src/shared/requestParser.ts` 全无 multipart
分支，粘贴 multipart 抓包时 body 只走 `toJsonText` 的 `=` 启发式 —— 整份报文会被**塌成一个
以 boundary 行命名的垃圾键**，用户看不到任何真实字段名，比 CLI 修前更空。
（这与 CLI 是**两套独立解析实现**，口径会各自漂移；服务端 `requestFileParser.js` 早在
`[MULTIPART-R-FIX 2026-09-20]` 就修过了。）

**修法**：新增 `extractBodyFields()`，与服务端同口径分派三种 body 编码：

| 编码 | 字段提取规则 |
|---|---|
| `application/x-www-form-urlencoded` | `k=v&k2=v2` → 键值 |
| `multipart/form-data` | 文本字段取值；**文件字段取 `filename`**（二进制无注入语义） |
| `application/json` | 顶层叶子 + 嵌套叶子走点路径 |

同时新增 `bodyFields`（**只装来自 body 的字段**）：`params` 把 query / urlencoded / multipart /
JSON 四个来源混在同一个扁平对象里，调用方分不清哪个键该走哪条通道。`bodyText` 也改为按编码
分派 —— multipart 用字段重建 JSON（对用户可读且与引擎的重建口径一致），其它维持原行为。

**验证**：
- 新增 3 条用例（`src/tests/requestParser.test.ts`），先跑红证明缺口真实 → 实现后 22/22 绿。
- **缺陷注入复验**：把 multipart 分支短路成不可达 → **恰好 2 条 multipart 用例红**，
  JSON 用例不受影响（证明分支隔离正确）；恢复后全绿。
- 关联套件无回归：`targetForm.importRequest` / `targetForm.injectionMark` / `scanWizard` 共 39 例全绿。
- 门禁：`arch-guard`（337 行，无新增违规）、前后端 `typecheck`、`facts:check`（已重采指纹 +
  README 数字同步至 318/2425）全通过。

### 修复：facts 门禁「采集面 ≠ 校验面」——工作区有未跟踪测试文件时红灯永远修不掉

`facts:check` 的「采集源指纹」判据，在 `facts-sync.mjs` 里**扫磁盘**（工作区），
而它实际校验的是 **CI 的 git checkout**（只有已跟踪文件）。两侧面不一致，后果很硬：

- 工作区里**任何一个未跟踪的测试文件**都会让本机多算一个 →
  本机 `--refresh` 得 283、CI 得 282 → lint 报「采集源已改动」；
- 而按提示重采**只会再算一遍 283** → **这个红永远修不掉**，除非先把那个文件 commit 或删掉。

实测（2026-09-22）：并发会话留下未跟踪的
`server/tests/booleanBlind.baselinePoison.test.js` → 我 `--refresh` 得 283、CI `e0fd433`
得 282 → lint 红，且重采无效（连红两轮才定位到）。

**修法**：`listSources()` 末尾用 `git ls-files` 过滤，**只保留已跟踪文件** ——
与 `ref-integrity.mjs` 早在 `[判据以 git 跟踪为准，不是以磁盘为准]` 就确立的同一条口径对齐。
判据用「CI 拿不拿得到」，而不是「有没有被 ignore」。

**验证**：未跟踪文件仍留在工作区的前提下重采 → 指纹从 **283 → 282**（与 CI 一致），
`--check` 全绿。这是本项目最贵的一类错（**静默地没在做事**）的第 N 次变体，
同族：`continue-on-error` 空转 job、`ref-integrity` 曾经的「以磁盘为准」。

### 修复：acceptance 把"沙箱根本没起来"记成产品 FAIL，且失败现场会过期

全量 `ci:local` 里 `fileWrite` 报 `FAIL 文件落盘=false`，读起来像文件写入被改坏了。真因来自
那份保留下来的失败现场（上一批加的 `[DIAG-FIX]`）：隔离 mysqld 沙箱启动超时 45s 后 python 抛
`RuntimeError`，**一条断言都没执行**；单独 `--only=file-write` 连跑 3 次全绿。

- **定性**：沙箱没起来判 `BLOCKED` 而不是 `FAIL`。两者**一样进 failed、一样让门禁非零退出**，
  改的只是语义标签——让人一眼知道该查环境还是查代码。这是 TODO §G"把环境问题归给被测代码"
  的重演。匹配只用 ASCII 稳定标记（python 文件名 + `Traceback`），因为 `[mysql-sandbox]`
  那些行在本机 cp936 控制台下是乱码，按中文匹配必失效。三向验证：真实现场→BLOCKED；
  合成真实断言失败→不判（否则就是放水）；只有中文超时行无 traceback→不判（保守留 FAIL）。
- **现场卫生**：dump 加 `失败于 <ISO>`；**套件这次过了就删掉它的旧现场**。此前根本没有清理逻辑
  （`grep last-failure` 只有写入处一处，我一度以为有），于是一份三天前的日志会一直长得像
  "刚刚又红了一次"的证据——**留着比没有更坏**，它会把人往已作废的方向带。
- 环境抖动的**根因未消除**（多套件各起各的沙箱、挤同一 3308 端口与 datadir），记 TODO §T。

### 修复：pentest-lab 自检的两处「声明了却没人拦」

`e2e/pentest-lab/verify.mjs` 里发现两处同族断口：

1. **`must` 技术期望从不参与判定** —— 每个场景都声明了 `must: ['union','error','boolean']`
   这类期望，但判定式只看「有没有检出」（`union.length > 0`），`miss` 只输出一句 `miss=[...]`。
   于是「声明了 must 却只检出其中一部分」**永远不会变红**。
2. **`process.exit(0)` 是无条件的** —— 连 `FAIL(漏检)` / 误报也退 0。
   直接跑本脚本**永远是绿退出码**，它自己打的 PASS/FAIL 标签形同装饰
   （同 skill 陷阱 11「打印 + 无条件退出 = 假绿」）。

为什么更早没暴露：**acceptance 那条路是有效的** —— 它解析 stdout 的
`漏洞场景检出 N/M` 数字并断言 `vuln === total && fp === 0`。于是「聚合门禁绿」与
「脚本自己绿」长期并存，而**两个入口口径不一致本身就是缺陷**。

修法：`ok` 纳入 must（`union.length > 0 && miss.length === 0`）；
`tag` 增加 `FAIL(miss=…)` 形态；末尾按场景点名 `exit(1)`；
给描述里**明确写了技术**的 `noisy` 补 `must:['boolean']` ——
其余 9 个场景描述未声明技术，**故意不补**（把"实测出什么"固化成"期望出什么"＝把实现当规范，会制造假红）。

**验证**：基准 11 场景全 PASS（`漏洞场景检出 10/10；安全场景误报 0`，exit 0）；
注入 ①（must 改成不可能命中的 `nosql`）→ `❌ 1 个场景未通过：noisy` + exit 1；
注入 ②（场景指向不存在的路由）→ `FAIL(漏检)` + `9/10` + exit 1；撤销两处后恢复全绿。

### 更正：E1b 的 MISS 不是引擎能力边界，而是**标定错误**（已修，两点现均检出）

上一条把 `E1b-secondorder` 的 MISS 归因为「引擎二阶只覆盖 error 型回显」。那个**事实**本身没错
（`SecondOrderDetector.js:55-70` 确实只认触发页的 SQL 报错特征），但**拿它当本次 MISS 的原因**
是错的 —— 本条更正，并给出正确修法。

**查证（三条独立证据）**：

| # | 证据 |
|---|---|
| ① | 靶场 `/api/admin/orders` 的 SQL 是 `WHERE status='${req.query.status}'` —— 注入源是 **HTTP query** |
| ② | `/api/comment` 是 `INSERT INTO orders (username,item,address,status) VALUES (?,?,?, 'pending')` —— status 硬编码，且写入的字段只出现在 **SELECT 列表（输出）**，不进 WHERE |
| ③ | 实测：**不带任何前置写入**、直接扫触发页 URL → 命中 `union+error`，风险 High |

→ 写入**丝毫不影响**查询结构；「先 POST comment 再注入」里的 comment 是**无关动作**。
本点实为「**需 admin 会话的普通 query 注入**」。

**修正**：`selftest.mjs` 改名并改技术分类（`E1b-secondorder` → `E1b-admin-query`，
`second_order` → `union/boolean`，标定去掉无关写入）；`run-scan.mjs` 改为直接扫触发页 + admin 会话
cookie，不再用 `--second-order`；订正 `lab-app.mjs` 那句与实现不符的注释；
重跑 selftest 重建真值表 → **漏洞点 15/15、安全点 7/7 仍全部成立**（靶点 SQL 拼接形态一字未动）。

**验证（r1 + r2 两轮）**：`D1-postform` ✅ HIT（333 / 546 请求）、
`E1b-admin-query` ✅ HIT（`union+error`，dbms=MySQL，81 / 287 请求）→ 两条均 2/2。

**教训（比修复本身更值钱）**：靶场/标定里**注释与实现不符**，会把**分类错误**伪装成
**工具能力缺口**。若不追问"这个写入到底影响了什么"，就会去给引擎加一个根本没被需要的能力，
而且**永远修不好这个靶点**。

### 补齐 blackbox-lab 两个从未被扫描的靶点：1 个能检出、1 个暴露引擎能力边界

承接上一条查出的缺口（真值标定 22 点、实际只扫 20 点），本轮把两点接进扫描并实测：

| 靶点 | 结果 |
|---|---|
| `D1-postform` | ✅ **HIT**（r1/r2 两轮均检出 `[boolean,time]`，333 / 546 请求） |
| `E1b-secondorder` | ❌ **MISS**（244 / 455 请求，有实质扫描） |

**D1 的坑（不知道它会完全查错方向）**：`--body` 只吃 **JSON 串**。
按 urlencoded 写 `--body 'username=alice&password=x'` 会让 CLI 直接报
`Unexpected token 'u', "username=a"... is not valid JSON`、**报告根本不产出**，
于是 run-scan 静默算成 MISS（0.7s、`req=undefined` —— 这个耗时本身就是线索）。
正确写法是**扁平 JSON** `{"username":"alice","password":"x"}`：扁平形态会经
`resolveBodyChannel`（本项目此前的产物）判为「不含嵌套」→ 以 urlencoded 发出，正是靶场要的编码。

**E1b 的 MISS 是引擎能力边界，不是参数错**：`SecondOrderDetector.js:55-70` 的判定链是
「读触发页 → 写探针 → 再读触发页 → 看是否出现 **SQL 报错特征**」—— **只覆盖 error 型二阶**；
而该靶点是 **boolean 型差异**（手工 curl 实测：注入后触发页返回空结果、不报错，
真值表里的标定判据也是响应差异）。参数接对了、靶点也真可注入，但引擎**结构上判不出来**。

**处置：保留扫描接入 + 如实记录 MISS**，不把它退回 `scanGaps` 来美化口径 ——
「未覆盖」与「覆盖了但检不出」是两件事，后者是真实现状。修二阶 boolean 通道是独立话题，未做。

`scanGaps` 因此清零，`targets:check` 现在显示 blackbox-lab「扫描目标 **22/22 ✅ 全覆盖**」。
README 同步改为 22/22，并把「真值成立」与「引擎检出」明确分开陈述。

### 靶点清单判据推广到第二个靶场，立刻查出一处真缺口：blackbox-lab 有 2 个靶点从未被扫描

把上一条的判据从 redteam-lab 推广到 blackbox-lab（`scripts/lab-targets-check.mjs` 改为
**多靶场**配置）后，第一次跑就露出：

- `blackbox-lab` 的**真值标定是 22 点**，而 `run-scan.mjs` 的 POINTS 只有 **20 点**；
- 三条独立证据：① `run-scan.mjs:49` 的注释写「这两个点由 `run-scenario.mjs` 单独处理」；
  ② `find . -name "run-scenario*"` **零命中**（全仓唯一提及处就是那行注释）；
  ③ `out/` 里 20 个靶点各有 r1/r2/sqlmap 产物，**那两个点一个都没有**；
- 而 README 写「22 靶点（15 漏洞 + 7 安全对照）」「真值标定 15/15」→
  **「真值标定 15 个漏洞点」与「实际扫描 13 个漏洞点」长期被混为一谈**。

新增的第三类判据：**扫描清单 ⊆ 权威，且差集必须显式登记**（反向也查登记腐烂）——
不留「默认跳过」的口子，否则"真值标了、扫描没跑"这件事会一直静默。
`blackbox-lab` 的差集已登记（`D1-postform` / `E1b-secondorder` + 各自理由），
启动输出如实显示「扫描目标 **20/22（差集 2 个，已登记）**」。

同步修正三处：
- `run-scan.mjs:49` 的错注释（原文指向一个不存在的文件）改为事实陈述；
- README 补「扫描覆盖 20/22」并指向 TODO §W；
- TODO §W 记全过程 + 补齐所需的 args 草案（**未验证，明确标注勿照抄**）。

**缺陷注入复验（3/3 按预期 exit 1）**：扫描清单漏掉一个点 → 报「未登记理由」；
补上一个已登记的点 → 报「清单腐烂」；真值表缺一个 → 报「缺 1 个靶点」。

### 新增「红队靶点清单一致性」门禁：真值链断了没人会发现

redteam-lab 的评测结论（检出率 / 误报）建立在一条**真值链**上：

```
selftest.mjs ──生成──▶ ground-truth.json ──被读──▶ gate-check.mjs ◀── results-r2.json
     ▲                                                    ▲                     ▲
     └── id 集合必须一致 ──┐                               │                     │
                          │                               └── 分母只含 truth=true 的 vuln
     run-scan.mjs ────────┘（决定"扫哪些"）─────────────────────────────────────────┘
```

三份清单（`run-scan.mjs` / `selftest.mjs` / `ground-truth.json`）**各自手写**，彼此之间
没有任何判据。不同步的后果是**不对称**的：

- run-scan 多一个点、selftest 少一个 → 该点不进真值表 → **完全不计入分母** → 静默，
  而且结论看起来更漂亮（检出率不受影响，没人会去查）；
- 反向 → 那个不可观测的 id 恒判未命中 → 检出率被拉低 → 变红（至少有人会去查）。

新增 `scripts/lab-targets-check.mjs`（接入 `npm run targets:check` · ci-local 的 lint 组 ·
ci.yml 的 lint job），判据：

- **权威集合** = run-scan 与 selftest 的 TARGETS，两者必须**逐 id 相等**（"扫哪些"与
  "标定哪些"是同一件事的两面，不允许差集）；
- `ground-truth.json` 的 id 集合必须**等于**权威集合，且不留 `truth≠true` 的 vuln；
- 子集清单（`sqlmap-bench` 18 条 / `verify-fix` 10 条）必须 ⊆ 权威，**显式登记"为什么是子集"**，
  规模走**只减不增**基线（悄悄删几项会让对标结论的分母变小而无人察觉）；
- 任一文件解析不到 id 时**直接报错退出**（判据失效必须显形，不静默返回空集合）。

**当前实测**：权威 26（19 vuln + 7 safe）、真值表 26 条、两份子集均 ⊆ 权威且未低于基线
—— 真值链目前是完整的，但**此前没有任何东西会保证它**。

**缺陷注入复验（4 例，全部按预期 exit 1）**：

| 注入 | 门禁报出 |
|---|---|
| selftest 少标定一个靶点 | 权威清单不一致（点名 `F24-safe-static`） |
| 子集引用了不存在的 id | 权威集合之外的靶点 id：`ZZZ-ghost-point` |
| 子集缩到基线以下 | 低于基线 18（只减不增） |
| 真值表出现幽灵条目 | 真值表里有权威集合之外的「幽灵靶点」 |

注入脚本自身也断言「替换真的生效」（未命中即报「用例无效」）—— 这是本项目的既有教训：
**静默空跑的注入会误导归因结论**。

### 新增「ci.yml job 覆盖」自检：本地门禁不再可能静默少跑一段

与「引用完整性」同源：那道闸门查「引用的**文件**存不存在」，这道查「ci.yml 里的 **job**
有没有人执行」。起因是 `scripts/ci-local.mjs` 头部原写「不覆盖：需要 docker 的 job
（`docker`、…）」，只提了 1 个，而实际未覆盖的是 **3 个**（test-matrix / tamper-waf-matrix /
docker）—— 声明与实际不符，而且没有任何东西会因此变红，读者只会以为除 docker 外都覆盖了。
更实际的后果在将来：ci.yml 新增 job 时本地门禁**静默少跑一段**，谁也不会发现。

判据：**每个 ci.yml job 必须二选一** —— 要么被 GATES 覆盖，要么在 `EXCLUDED_JOBS` 里登记
并写清「为什么本机替代不了」。不留「默认跳过」的口子。反向也查：清单里登记了 ci.yml 已不
存在的 job（清单腐烂）同样报错。解析侧另有一道自保：jobs 段之后若冒出新的顶级键，直接报
「本结构变了，自检需要跟着改」，而不是静默漏检 —— 判据失效必须显形。

启动时打印一行（数字即判据）：
`job 覆盖自检：ci.yml 12 个 job → 本地覆盖 9 / 显式排除 3 / 未声明 0`

**缺陷注入复验（两例，都按预期 exit 2）**：
- ci.yml 末尾追加一个未声明 job → 「❌ ci.yml 里有 1 个 job 没有登记的归宿：zzz-injected-job」；
- `EXCLUDED_JOBS` 登记一个不存在的 job → 「❌ ……排除清单腐烂了（那个 job 可能已删除或改名）」。

顺带删掉文件末尾那句散文式声明（原写「CI 还有两个本机跑不了的 job」——但「两个」里只有一个
真是 job，且实际是 3 个），改为指向启动时那行可跑判据的输出，不再复述数量。

### 修复：验收报告的两段可信度断口（定向跑覆盖全量报告 / 无版本凭证）

与下一条同源（**结论看着正常，语义完全不同**），这次断在 `e2e/acceptance.mjs` 的**报告**上。

**断口 1（实测撞到，非推测）**：`--only=<id>` 定向门禁把结果写进**同一个**
`e2e/results/acceptance-report.md` —— 入库的全量报告位置。实测现场：那份文件变成一行
「✅ PASS fileWrite 真闭环」+ 汇总「**1 PASS / 0 FAIL**」，看着全绿，实际 12 个套件
只跑了 1 个；被覆盖的是已入库的全量结论（前一份 12 PASS），信息直接丢失。

**断口 2**：报告头只有时间戳，回答不了「这份 N PASS 是哪一版代码跑出来的」；
工作区 dirty 时跑出的报告照样入库，读的人会以为它对应某个提交。

修法三件：
1. 报告头加**版本凭证**：HEAD 短 sha + 未提交清单（dirty 时明写「本报告不对应任何提交」
   并列出前 3 个文件与总数）。**必须在开跑前采集** —— 跑验收本身会写 `e2e/*/results/*`，
   收尾时采集会把运行产物误读成「跑前的未提交改动」，反过来说谎。
2. 报告头加**套件范围判据**：`N/M 跑出断言`（N = PASS+FAIL），非全量时追加
   「⚠️ 判定：不完整 —— 不得当作该代码版本的整体验收结论」。判据是数字，不依赖文件名。
3. 只有**真全量**运行才写 `acceptance-report.md`；其余写 `acceptance-report.partial.md`
   并加进 `.gitignore`（本地产物不入库）。

**验证**：跑前 `md5sum` = `6a38c043042a3b07f7259eed64767f16` → 跑 `--only=report-contract`
→ 跑后 md5 **逐字相同**（全量报告未被覆盖），终端打印「套件范围：1/12 跑出断言（非全量，
未覆盖全量报告）」。报告头实测两行：

```
> 代码版本：`0ef2bc9`　⚠️ **工作区 dirty**（跑验收前有 9 个未提交改动：…）—— 本报告不对应任何提交
> 套件范围：**1/12 跑出断言**（定向 --only=report-contract）　｜　⚠️ **判定：不完整**
```

CI 侧无影响：`.github/workflows/*.yml` 与 `scripts/ci-local.mjs` 都不用 `--skip-heavy`，
走的一直是真全量路径，报告仍写 `acceptance-report.md`。

### 新增「采集源过期」判据：README 与 _facts.json 一致 ≠ 数字是新的（门禁假绿）

`facts:check` 只比对 README ↔ `docs/_facts.json`，**从不校验 _facts.json 自己是否过期**。
于是出现一种假绿：后继两批提交带来 +19 条用例（1985 → 2004），没人回填，
`_facts.json` 停在 1985、README 也写 1985 → 门禁报「一致」，而真实用例数早已是 2004。
（与 `continue-on-error` 的空转 job 同源：都是**静默地没在做事**。）

判据：把「决定跑哪些测试、总共多少条」的文件集合做**内容指纹**，随 `--refresh`
与数字**同批**落盘（`docs/_facts.sources.json`），`--check` 时重算比对。
用内容哈希而非 mtime —— CI 上 checkout 后所有文件同一时刻，mtime 判据必然全量误报。

两个设计决策：
- **指纹缺失不静默通过**：文件不存在时报「没有依据」并 exit 1，而不是跳过检查。
- **基准过期时拒绝 `--fix`**：`_facts.json` 自己过期时按它改 README，等于把旧数字再抄一遍；
  故 stale 时 fix 不落盘，明确要求先 `--refresh`（顺序反了就是抄旧数）。

边界（写在脚本注释里，勿当万能）：只覆盖测试文件 + 驱动采集的配置；
依赖版本 / `.env.test` / 被测源码改动不在此判据内（改源码不改用例数，那是覆盖率门禁的职责）。

**顺带修正 README 三处陈旧结论**（逐条实测核对后改，非顺手改）：
- 「利用工具」行写「fileRead 已跑通，其余仍为 mock 单测」，但同文件「利用能力实测口径」表
  已记 fileWrite / UDF-os-shell 均为真闭环 —— **同一份 README 自相矛盾**。
- `npm run acceptance` 注释写「10 套件」，实际 `e2e/acceptance.mjs` 的 SUITES 是 **12** 个。
- P1-E 标「根因已定位，未修」，实际 `blindExtractor.js` 的分层裁决早已落地；
  按实情改写并补上**边界**：修的是「静默误用荒谬上界」，真超 4K 的字段仍判失败（有意护栏）。

### 修复：9 个「CLI 能设、引擎真读、REST 收不到」的扫描配置键（静默假阴性）

`sanitizeStart` 的返回 `config` 只由白名单键构成，未知键原来只留一行 `logger.debug`
（默认 info 级等于没有）。后果不是报错，是**调用方拿到 200 + 正常 scanId + 一句「未检出」**：
请求成功了，开关根本没进引擎。假阴性对扫描器是最贵的一类错。

既有两支守卫都抱不到它：`configWhitelist.guard` 的真值来源是 `defaults.js` 顶层键，
而这批键根本不在 defaults.js 里（只由 CLI 写入）；`configWhitelist.passthrough` 只遍历
`KNOWN_CFG_KEYS`，自然也不会去看没进白名单的键。源码注释里已留着 6 处
「此前不在白名单被静默丢弃」——一直是人肉发现一个补一个。

改成**可跑的两端交叉判据**（`server/tests/configReachability.guard.test.js`）：
CLI 侧 `config.X =` ∧ 引擎侧 `config.X`/`ctx.config?.X` − `KNOWN_CFG_KEYS`，
再对每个键**真调 `sanitizeStart`** 断言落地。第一轮抱出 9 个，全部接通：
`testPath` `testHeaders` `noCast` `flushSession` `hex` `unionFrom` `dumpWhere` `unionCols` `paramDel`。

过程里两次自我更正，都写进了代码注释：
- `hex` 最初被我当 grep 噪声跳过（`hex` 一词在 `server/src` 有上百处无关命中），
  是守卫测试第一次跑就把它指出来 —— 判据必须能跑，不能靠人眼看；
- 我最初给 `unionFrom` 写了句"大概由别处覆盖"的豁免，实测它被
  blindExtractor/DBFingerprinter/Extractor/injection **四处**读取，豁免已撤回。

接通时补的真校验（这些值会进 SQL 或进请求 URL，不是顺手重构）：
`unionCols` 收敛 1..200 整数（引擎按 `Number()` 当固定列数，`abc`→NaN 会进二分）；
`paramDel` 只收 `; , | ^ ~` 单字符（取**窄集合**：宽集合写错是静默改请求形状）；
`hex`/`flushSession` 收严格布尔（引擎按 `=== true` 判定，放过 `1` 又变回"收了不生效"）；
`dumpWhere` 拒分号（分号是把"一个条件"变成"第二条语句"那一步）。

未知键的提示从 `debug` 提到 `warn` 并明说"这些设置不会生效"。
顺带查实一个新形状：`BACKFILL_SCALAR_KEYS` 的透传循环**不看** `KNOWN_CFG_KEYS`，
所以白名单对这批键只管告警不管放行 —— 缺陷注入实测确认后，新守卫加了
「BACKFILL ⊆ KNOWN」一条把它钉住。

### 修复：版本回显定库在严格类型库上恒失效（HSQLDB 现已能识别）

先修测量手段：`e2e/multi-engine-lab/verify.mjs` 原来**只记技术位、不记定库结果**，且靶场
默认挂 CRS（UNION 哨兵整条 403）→ 版本回显通道在那里从没被执行过。于是"HSQLDB/Derby
定不了库"长期没有可跑的验证手段（H2 那次结论靠临时手写探针，跑完就没了）。现在报告带
`定库=` 列（与真实引擎不符还会报"误判"告警），并新增 `NO_WAF=1` 一档——用来分开
"探针跑不动（真缺陷）"与"探针没被送达（靶场挡的）"，这两件事在原报告里长得一模一样，
都是 `dbms=null`。报告标题强制带口径，两档数字不可互换。

打开后显形两个互相独立的缺陷：

① **死探针**：`func` 是裸常量串 `'HSQLDB'`，而 09-16 为堵 DB2 误判把 `sig` 收紧成
`/HSQLDB\s+\d/`——常量里没有数字，**回显了自己也匹配不上自己的 sig**。不是探针跑不动，
是判据写死了不可满足。改成 exclusive 探针：区分力来自"只在自家库存在的 FROM 子句"而非
字面量（正面回应 DB2 教训）。HSQLDB 真机回显 `"HSQLDB 103"`，同一条放 H2/Derby 直接报错。
为此给 `DB_VERSION` 加可选字段 `from`，其优先级高于方言伪表与用户 `--union-from`
（覆盖掉就没区分力了），其余 16 个库的探针构造一字不变。

② **标记落错列**：`idx = echoCols[0]` 无条件取第一个回显列。真机实测同一条探针放
`name`(VARCHAR) 正常回显、放 `id`(INTEGER) 报 `incompatible data types in combination`
整条 UNION 失败 → 严格类型库上这条通道恒失效，且症状与"跑不动"完全相同。H2 一直能过
是因为它以 MODE=MySQL 运行会隐式转类型，不是判据对了。按代价收敛：只对声明了 `from`
的候选换列重试（其余 16 库请求数零变化；全候选换列会把 206 请求推到 ~240）。

结果：`定库=HSQLDB` ✅、H2 依旧 ✅，安全对照仍零误报、检出场景仍 3/3。
两点不完美如实记下：**hsqldb 的 `str` 技术位从 `[union,error,boolean]` 变 `[union,boolean]`**
（漏洞仍检出、计数不变，是定库成功后跳过冗余报错重探的归因策略问题，待单独定口径）；
**Derby 仍未识别**——探针单独可执行（`"DERBY 24"`，且 Derby 只吃 `CAST(.. AS CHAR(n))`、
`VARCHAR` 反而报错，均实测），但组合成引擎实发形状后仍 echo=N，下一步查 Derby 对 select
列表里裸 `NULL` 的语法限制是否波及**所有** UNION 探针（该现象尚未在引擎实发形状上复现，
不当结论用）。

守卫升级：`dbmsExtend6.test.js` 原来只查"func 里有没有标识串"+"sig 能否命中一个手写的
漂亮串"，所以①这类缺陷可以长期全绿。新增静态不变量 **sig 要求 `\d` 时 func 必须有数字
来源**（必要条件检查，不替代真机验证）。缺陷注入复验：把 func 改回 `"'HSQLDB'"` → 该测试
立刻红并点名到条目。

### 修复：`-r` 导入 multipart 抓包时整份 body 塌成一个垃圾键（静默 0 检出）

`-r`（Burp/curl 导入）是实战喂目标最主要的方式，而这条路上**解析器是对的、接线是坏的**：
`parseRequestFile` 正确抽出 `{username, caption, avatar}`，但 `applyRequestFile` 丢开这些
字段、把**原始 body** 交给 `bodyToJsonString` 的 urlencoded 启发式。multipart 里没有 `&`、
只有 `name="…"` 里的 `=`，于是整份 body 塌成**一个**键，键名为
`--<boundary>\r\nContent-Disposition: form-data; name`；同时那个
`Content-Type: multipart/form-data; boundary=…` 被原样保留 —— 发出去的是"声明 multipart
却带一坨 urlencoded 垃圾"，目标必然取不到参数 → **扫描正常跑完、0 检出、零告警**。

修法：解析器新增 `bodyFields`（只装来自 body 的字段；原有的 `params` 把 query 和 body 混在
一个扁平对象里，调用方无法区分），multipart 时用它构造 body，并**删掉那个已经对不上的
Content-Type**，让引擎按 urlencoded 重发同一批字段名与值。这是"降级但说实话"：很多框架
两种编码都吃；不吃的那批由 warn 明确告知"未检出 ≠ 没有洞"，而不是让人以为目标干净。

**为什么既有测试全绿却没拦住**：`requestFileParser.multipart.test.js` 测的是被调函数，
断点却在调用链的下一环。**只测被调函数、不测调用链，就会出现"测试全绿而入口是坏的"**。
新增 `requestFile.importWiring.test.js` 一律从 `applyRequestFile` 进、从引擎收到的注入点出
（5 条，含 urlencoded/JSON 两条"别波及既有路径"的对照）；缺陷注入复验：把 multipart 判定
短路 → 第 1、2 条同时红。

真 multipart 发送仍未支持（`injection.js`/`httpClient` 里 0 处 FormData，已核实），
连同"前端 `requestParser.ts` 连 multipart 分支都没有"一起记在 TODO §O，并写明动手前
必须先补 multipart 靶场——`buildInjectionRequest` 是全项目最吃重的函数。

### 修复：CLI 的嵌套 JSON body 被摊平成不可注入的畸形值（同一份抓包 CLI 少测注入点）

`--body` 的文档语义是「JSON 对象字符串」，但 CLI 一律摊进 `bodyParams`，而 TargetParser
对每个值做 `String(v)`。同一份 body 实测两端：

```
--body '{"user":{"id":1,"name":"alice"},"tags":["a","b"],"plain":"x"}'
  CLI（bodyParams） →  user="[object Object]"  tags="a,b"  plain="x"
  REST（jsonBody）  →  user.id  user.name  tags.0  tags.1  plain
```

前两个值结构上不可能注入（没有 payload 能把 `[object Object]` 变成合法 SQL）。断的不是
引擎（`_discoverJsonLeaves` 早已实现），是 CLI 的接线。

修法保守：**只有真含嵌套才切 jsonBody**，扁平 body 继续走 bodyParams(urlencoded)——
否则会把"表单接口但用 JSON 语法写了扁平 body"的既有扫描全改成 application/json，
那是回归不是修复。判定抽成 `cli/config.js` 的 `resolveBodyChannel` 单点定义
（`-r` 导入抓包那条路共用，不在两处各写一份）。REST 侧同一个坑只加 warn 不改行为：
自动路由会让两个字段语义纠缠，但"我传的东西其实没被测"必须可见。

验证：`server/tests/cli.jsonBody.test.js` 6 条。主用例刻意不测纯函数，而是走
`parseArgs(argv)` → `runSingleScan` → 捕获递给 `ScanManager.start()` 的真实 input →
再接 TargetParser 看点位（只测纯函数挡不住"忘了放进 input"）。缺陷注入复验：从 input
摘掉 `jsonBody` → 两条同时红。另用一次性靶场拿**真 CLI 二进制**端到端打出
`dbms=MySQL` + `param=user.id` 的 union/error 两条检出（206 请求、0 拦截）。

### 修复：随机化电池的 ORDER BY 形态恒被剔出分母（探针选错，非引擎缺陷）

`battery.json` 里 `c00/c20/c34-orderby` 长期 `status:"unobservable"`。看着像自证机制在
正常工作，实际是我自己把分母做空的：orderby 复用了 `AND 1=1`/`AND 1=2` 这对布尔探针，
而 `ORDER BY id AND 1=1` 与 `AND 1=2` 在这张表上分别退化成 `ORDER BY id` 与常量 `ORDER BY 0`
（同序）；取 name/price 时字符串转数值恒 0，两探针更完全同序 —— 没有哪个检测器能看见。
电池宣称 6 种形态，实际恒测 5 种。换成列索引有效性对（`, 1` 合法 / `, 9999` 报错，
即 sqlmap `--order-by` 的信号）。

**同 seed、同 cases 的严格对照**：召回 17/17（剔 3 条）→ **20/20（剔 0 条）**，
三条 orderby 全部以 `[error,boolean]` 真检出，Wilson 95%CI 下界 81.57% → **83.9%**。
分母补全而下界更高，是更强的数字而不是更大的数字。


### 新增「引用完整性」门禁（CI 里写的路径必须真实存在）

起因是一次**空转门禁**：`ci.yml` 的 `tamper-waf-matrix` job 里写着
`node e2e/tamper-matrix/run.js` 与 `node e2e/waf-lab/run.js` —— 两个文件**都不存在**
（真入口是 `tamper-test.mjs` / `compare-real.run.py`）。更隐蔽的是它们都带
`continue-on-error: true`，于是 `node <不存在的文件>` 每次报 Cannot find module
却**从不拦人** —— 这两个 job **从未验证过任何东西**。是靠人工 grep 才发现的。

新增 `scripts/ref-integrity.mjs`，校验三处引用源里的本地路径是否真实存在：
- `.github/workflows/*.yml` 的 `run:` 步骤（含多行块，能识别 `cd X && node Y` 的基准目录偏移）
- `package.json` / `server/package.json` 的 `scripts`（含 `npm run <name>` 交叉引用存在性）
- `e2e/run-all.mjs` 的靶场注册表 `entry` 字段

接入：`npm run refs:check` · `npm run check:all` · `ci-local.mjs` 的 lint 组 · `ci.yml` 的 lint job。

**缺陷注入复验（4 例，全部按预期报红）**：
① ci.yml 路径改回不存在的 `run.js` → 报「第 313 行」；
② `run-all` 的 `entry` 改成不存在 → 报出条目；
③ `package.json` 引用不存在的 npm script → 报「脚本引用」；
④ **自指注入**：把 ci.yml 里 `ref-integrity.mjs` 自己写成拼错的名字 → 门禁抓到自己
（证明校验范围确实覆盖了它自身的接入点）。

**过程中修正的两处自身缺陷**（否则会天天报假红，比没有更糟）：
- 初版不认 `cd server && node index.js` → 把 3 个**相对子目录**的正确路径误报为缺失；
  改为按 `&&`/`;`/`|` 切段并跟踪 `cd` 目标。
- 缺陷注入② 首次"注入成功"实为**替换未命中而静默通过**——真实 entry 与我预设的字符串不同，
  这也印证了"注入必须断言替换真的生效"。

### WAF 归因修正（拦住数值点 union 的是 942190，不是 942361）

TODO §I「改起始形状把 num/blind 的 union 拿回来」立项时假定拦路虎是 942361
（`^[\W\d]+\s*?(?:alter|union)\b`，PL2，判**起始形状**）。四版探针实测（100+ 形态，
每格同时记录「CRS 拦不拦 / MySQL 认不认 / 标记值能否取回」三个独立事实）**推翻了这个前提**：

- 真凶是 **942190（PL1）**，含 `union\b[\s\x0b]*(?:all|(?:distin|sele)ct)\b` —— 判的是
  「union↔select 相邻」，与起始形状无关；942361 是 CRS 里更**松**的兄弟规则。
- 942190 带 **`t:removeCommentsChar`**，注释在匹配前已删除 → 全部 `/**/` 填充失效
  （30 种填充 0 通过；唯一逃过 942190 的 `UNION/*!*/SELECT` 落到 942500，换个坑而已）。
- 非 ASCII 空白（NBSP / U+2000–200A / 表意空格 / BOM 等 18 种）：MySQL **一律不认作空白**
  （语法错），这条路物理上不通。
- 绕开 union 字面量的五类等价手法（boolean / subquery / error / time / stacked，17 种）
  被 **942130 / 942440 / 942120 / 942131 / 942151 / 942160 / 942140 / 942350** 逐一精准拦住。

结论定性：**不是 tamper 链不够好，是 CRS 在 PL1 对 SQLi 全覆盖** —— 每格都有对口规则守着。
`num`/`blind` 丢 union 是**正确行为**（如实反映 WAF 强度），非缺陷。TODO §F 的归因表同步修正
（原记 942361）；§F 中「09-10 那次为何算进过 10」的注释猜测也随之失效（注释拆相邻性对
942190 无效），如实留白不再编因果。

四版探针留档：`e2e/waf-real/probe-union-shape.mjs`、`probe-union-shape2.mjs`、
`probe-union-ws.mjs`、`probe-nounion.mjs`（纯发请求 + 直连真库，各几秒，可复跑复核）。

### 架构门禁基线收紧

`server/src/core/httpClient.js` 已瘦到 **1251 行**，基线仍卡在 1256（门禁自报「已瘦 5 行，
可下调」）。基线是「只减不增」的技术债显式登记，留着宽松额度等于给后续膨胀留后门 →
下调至 1251。门禁复跑绿。

### 诊断可信度（归因文案不再把人带向错误方向）

`Exploiter.myOsShell` 的 echo 探针（纯 ASCII 数字 marker）原为**单次**判定：为空即写
「典型：Windows 本地化 whoami 的 GBK 输出」。但 marker 是纯 ASCII，它的空捕获**不可能是
编码问题** —— 这句话在「判据偶发抖动」时会把排障引向编码方向。改为最多两次重试，把三种
成因分开：echo 命中+原命令 null → 真·不可字符化；首空后命中 → 判据抖动（**不写编码归因**）；
两次都空 → 探测通道不可靠（新增 `probeInconclusive`，且**不**写 `udfInstall`，因为两次空
≠ 未注册）。缺陷注入复验：撤掉重试 → 新增两条变红、原语义那条仍绿。

### 靶场侧噪声源（`--test-path` 白烧请求 + redteam 喂假 SQL 错）

- **闭合探测在 404 路径上白烧约 40 请求**（`Detector.probeBoundary`）：闭合前缀的前提是该
  路径真执行了 SQL；路径不存在时后端没路由到查询代码，13 个候选只是同一张错误页（Express
  还回显 URL）→ 噪声 boundary → 触发整轮指纹/列数探测。现于基线请求后早退：
  `kind==='path'` 且 `400≤status<500`（排除 401/403/429 —— 鉴权/限流 ≠ 路径不存在）。
  真存在注入的路径不会是 4xx，故不影响真实检出；留 `boundarySkipReason` 供排障。
  实测来源：`/api/sleep` 开 `--test-path` 时 path 点拿到 boundary `%"`。
- **redteam-lab `/shop/semi` 的 URIError 喂假信号**（D15 靶点）：4 处裸调 `decodeURIComponent`
  （同文件已备好 `decodeSafe` 却没接上）。payload 含裸 `%` 时抛 URIError，被外层 `run()`
  兜成 `500 + SQL_ERROR: URIError` —— 不是「挂连接」，但等于靶场亲手给扫描器的 error 通道
  喂假信号（该看 UNION 结果行，却看到伪 SQL 错误）。改用 `decodeSafe` 后实测报错文本全部
  转为真实 MySQL 错：`id=1%` → `syntax ... near ''`；`id=1%zz` → `Unknown column 'zz'`。
- 附带纠正：TODO 原判「redteam / real-mysql / multi-engine / pentest-lab 同一形态」经实测
  **不成立** —— 这 4 个靶场均已具备防护，只有 `/shop/semi` 真中招。

### 测试可信度（消除两条既有 flaky 的假红）

两条 flaky 同根：**拿固定墙钟给异步扫描流水线设上限**，等价于在测机器负载。负载一高就红，
而同一文件孤立跑却全绿——这种「时红时绿」比稳定红更有害，会训练人对红视而不见。

- **`tamper.f20.test.js` `runScanUntilDone`**：固定 `8000ms` 超时在 `--test-concurrency=3`
  全量门禁下不够，报「scan did not finish in time」。实测同一文件孤立跑 3 次 10/10 全绿，
  全量负载下 8/10 → 放宽到 `30000ms`（`TAMPER_SCAN_TIMEOUT_MS` 可覆盖），语义不变。
- **`scanManager.scheduling.test.js`**：轮询预算 `200×5ms=1s`（测试注释自承"飘到 1.6s"）→ `6000×5ms=30s`。
  该文件自 2026-09-18 起记录为「连跑 3 次 2/1/2 个失败，从不全绿」，本次结案。
- **验证**：`tamper.f20` 10/10 ×3、`scheduling` 4/4 ×3；全量 `npm test` →
  **1896 用例 / 1895 pass / 0 fail / 1 skip**（112s）。

### 检出正确性（黑盒靶场真 MySQL 实测，非 mock 推演）

同一病根「目标回显注入值 → 所有『响应 vs 基线』的比较被污染」在三条链路上复发，全部修掉：

- **闭合探测**（`engine/Detector.js`）：LIKE 搜索框等回显型点上 13 个闭合候选全部判不相似 →
  boundary 回退空串 → 该点 union+boolean 技术位全灭。现相似判定先剔除被回显的 payload，
  并在「一条都不命中」时改用**不依赖基线**的等长真假对差分判据（正常站点零额外请求）。
- **版本回显定库**（`engine/DBFingerprinter.js`）：回显型页面里有两份 `__S__…__E__`
  （被回显的 SQL 文本 + 真实结果行），`match` 恒取前者 → 18 库 sig 全落空、整条通道失效。
  现取标记前先剔除本条 payload 回显。
- **时间向量定库**（`engine/payloads/index.js`）：向量把闭合引号写死在模板里，字符串上下文上
  「向量顺序即优先级」被打乱 → 真 MySQL 判成 ClickHouse（误判直接决定 payload 族/注释符/
  提取语句选哪一套）。现统一用 `{BD}`（该点闭合前缀）填充。
- **指纹缓存粒度**（`engine/ScanManager.js`）：整台目标共享一份，而检测是多点**并发**跑的 ——
  排在最前的若是 path/header 点（探针全 404），那份 null 就被后面每个点继承 → 时间盲注点整点
  漏检。现按点类别（main/header/path）分桶，且未定库结果允许后续点重试（有预算上限）。
- **预筛选不再剪掉数值型时间盲注点**（`engine/ScanManager.js` `_timeProbeValues`）：时间探针
  只有带前导 `'` 的形态，「恒 200 固定页 + 数值上下文」的点两个探针都无信号 → 整点被剪。
  现每种方言补一条数值上下文变体（每点 +1 探测请求）。
- **`--cookie` 现在真的是注入面**（`bin/cli/config.js`、`bin/cli.js`）：此前只进 `auth.cookie`
  （会话携带），`--cookie uid=1 --level 5` 解析出 0 个注入点 → 0 请求 → 报告「未检出」，
  看起来像一次干净的低风险扫描。是否投放仍由 level≥2 门控决定（与 sqlmap 同语义）；
  已升为注入点的键不再经 `auth.cookie` 重复附加（同名两份时结论不可复现）。

### 对目标的自伤风险（一处能力被刻意移除）

- **H2 移出盲探时间向量**：H2 的 `SLEEP()` 以毫秒计、MySQL 同名函数以秒计；原
  `SLEEP({SLEEP}000)` 写法在补上闭合前缀后于数值上下文的 MySQL 完全合法 —— 排前向量因故未延时
  时等于让目标库睡 1000~15000 秒（连接池被我们自己占死）。单位不对称无法两全，H2 定库改由报错
  签名承担，并加防回归断言：盲探向量不得出现任何 `{SLEEP}0+` 放大写法。
- **闭合探测不再重试**（`engine/Detector.js`）：能让目标挂住的探针重发大概率还是挂，
  默认 retry=3 × 30s 会把单点闭合探测拖成数分钟，且重复发送同一攻击特征正是风控封 IP 的触发点。

### 实测口径变化

- blackbox-lab（真 MySQL 8.0.28，22 靶点）：实战档 r2 **9/13 → 13/13**，默认档 r1 **10/13**，
  两档安全点误报均 **0/7**；A3-like 从「蹭误判才命中的 time」变成 `union+boolean`（风险 Medium→High）。
- redteam-lab R1 18/19、R2 19/19、误报 0/7（零回归）；服务端单测 1887 用例 0 fail、前端 315/315、
  `tsc` 0 错、eslint 0 error。
- 工具链：`scripts/facts-sync.mjs` 采集服务端数字时显式钉 `--test-reporter=tap`
  （node:test 的 reporter 选型随 TTY 探测漂移 → 本地 `--refresh` 必失败）。

### 定库判据：从「sig 能不能区分」换成「表达式只在自家库跑得动」

- **H2 改用 exclusive 探针 `H2VERSION()` 并前置到 MySQL 之前**（`engine/payloads/index.js`）。
  真引擎 A/B（`e2e/multi-engine-lab`，H2 2.2.224 经 JDBC，须 `{waf:false}` 才让 UNION 探针过靶场 CRS）：
  修复前 18 条探针全部 `echo=N` → **`dbms=null`（定库失败）**；修复后
  `verFp H2 echo=Y 取到值="2.2.224" sig命中=true` → **`dbms=H2`**。真 MySQL 8.0.28 三点
  （`A1-numeric`/`A3-like`/`C2-blindtime`）仍全部 `dbms=MySQL`、3/3 检出、0 误报，前置不抢库。
  与 `engine/extractionMaps.js` 早已使用的 `H2VERSION()` 对齐。
- **一次公开更正**：本批先前把这条写成「H2 的 `version()` 回显命中 MySQL 的裸版本号 sig → 真 H2 被定成
  MySQL」。实测**不成立**——H2 没有 `version()` 标量函数，MySQL 系 WRAP 的 `CAST(x AS CHAR)` 在 H2 上
  直接报错，那条路径运行时不可达；实际症状是定库失败而非误判。`TODO.md` §A 已按实测改写并留证据。
- 单测侧把「假引擎能执行哪些探针表达式」显式建模（`tests/boundary.echoTarget.test.js` 新增正/反两条
  exclusive 守卫，`tests/fingerprint.mariadb.test.js` 的 mock 加 `supportedFuncs`）。不给这层，mock 等于
  「谁探测都回同一个版本」，会把真实判据（跑不动 → 无回显）抹平 —— 上面那次错误归因正源于此。
- 新测得的欠账（记录未修）：HSQLDB / Derby 两台**关掉 WAF** 后仍 `18/18 echo=N → dbms=null`，
  即版本回显定库对这两台整条失效；`multi-engine-lab` 默认开着 CRS，UNION 哨兵探针全被 403，
  该靶场从未跑到这条通道（见 TODO §A 验收口径 2/3）。

### 门禁可信度：掐掉两条假绿

- **`acceptance` 的 SKIP 不再算 PASS**（`e2e/acceptance.mjs`）：`pass: passed || skipped` 让
  fileRead / fileWrite 在 `secure_file_priv=NULL`（MySQL 8 默认）时以「✅ PASS」进报告并计入顶部
  汇总，一行断言都没跑却算通过，与同仓 `run-all.mjs` 的「跳过的不算通过」自相矛盾。现改为
  `PASS / SKIP / BLOCKED / FAIL` 四态分列，SKIP 带原因、不进失败也不冒充通过。
  本机默认环境实测：**8 PASS / 0 BLOCKED / 0 FAIL / 3 SKIP**（此前同一环境报的是「11 PASS / 0 SKIP」）。
- **撤掉 9 条 eslint 目录/文件级 ignore**（`eslint.config.js`）：被挡住的包括门禁总控
  `e2e/acceptance.mjs` 自己 —— 它因此从未被 lint 过，`tally is assigned but never used`、
  `ntlm-lab` 里 `reject` 未声明（真实缺陷：靶场端口被占时抛 ReferenceError 而非可读错误）都没人看见。
  纳回后 25 条 `no-unused-vars` 全部清零，`eslint .` 现 0 error / 6 warning、退出码 0。
- **WAF 口径的量纲与写死基线**：`waf-verify.mjs` 原输出 `检出 ${det}/${total} 个技术位` 把「技术位合计」
  与「场景数」塞进同一个分数（README 于是抄成「10/5」），改为「技术位合计 8（5 个注入场景…）」；
  `waf-auto-check.mjs` 里写死的「人工 dash2hash 基线 = 10」改成从 `waf-real-report.json` 现读，
  读不到就显示「未采集」。

### 实测口径变化（WAF 绕过率下修，附规则级归因）

> **本节已被 2026-09-19 晚些时候的执行器修复推翻，保留作历史记录。** 用 CRS 官方回归集查出
> 自实现 SecRule 执行器两处结构性缺陷（`(?i)` 内联大小写标记被吃掉、链节点 `TX/MATCHED_VARS`
> 未实现）后，保真度 60.7% → 99.3%，同一批探针在同一份规则上的结论完全变了：
> PL1（默认部署档）off=on=8（挂链无可证增益），PL3（全规则档）0/0（无可证绕过）。
> 故「off 2 → on 8」这类「绕过生效」的表述是宽松执行器白给的假收益，README 已按新基线重写，
> 本节及以下 TODO §F 的归因不再作为对外口径。

- **对外数字从 10（人工挂链）/ 11（自动选链）下修到 8 / 8**（整跑 acceptance 一次 + 单独复跑一次，
  两次一致）。丢的两格是 `num`/`blind` 的 union，**逐条手工探针定位到 CRS 规则原文**：
  942361 是 `^[\W\d]+\s*?(?:alter|union)\b` —— 打的是**参数值起始形状**，数值点 `id=1…` 必命中、
  `alice'…` 不命中；`/**/`、`%0a`、`%09`、双空格、`UNION ALL` 八种换分隔符形态全部 403，
  而它们不套 WAF 时 MySQL 全部正常执行。`dash2hash` 只规整尾部注释符，对这条无效。
  本批改动已排除（回退动过的 4 个引擎文件重跑，结果逐字相同）。
- 另一层口径：942361 官方注释属 **PL2**，而本仓自实现执行器默认全规则（≈PL3 最严档）→
  **8/8 是「最严档」数字，CRS 默认部署档（PL1）的绕过率未测**（TODO §I 已把两档测量列为待办）。
  旧数字 10/11 无留档报告可核对，故只作口径下修，不断言"能力退化"。

### 门禁可信度：掐掉一条环境耦合造成的假红

- **`server/tests/engine.e2e.test.js` 不再复用 4567 端口上的外部引擎**。旧实现把端口写死 4567，
  且 `startEngine()` 发现该端口有实例就直接复用 —— 只要本机跑着一个带 `SCAN_API_TOKEN` 的实例
  （手动起的 server / 桌面版 sidecar / 上一次门禁残留），受保护端点就全部返 401，而用例断言的是
  2001 → **稳定红，且与被测代码毫无关系**（反向验证：另起一个无 token 实例请求同一路径
  返回 `{"code":2001}`，证明引擎契约本身没问题）。
  现改为三条：① `net.listen(0)` 取空闲端口；② 自己 spawn 一个带一次性 token 的实例
  （不再读宿主环境的 `SCAN_API_TOKEN`）；③ 所有请求显式带 `x-api-token`。
- **新增两条鉴权契约用例**（无 token / 错 token 访问受保护端点必须 401）：鉴权链路此前只在
  `release-smoke` 里被覆盖，服务端单测里没有；现在这两条同时是上述修复的回归钉。
- **验证**：单文件连跑 **5 次 7/7**；服务端全量单测 **1893 / 1892 pass / 0 fail / 1 skip**
  （修复前同一环境为 1887 / 1884 pass / **2 fail**）。
- 残余风险写实：`listen(0)` 拿到端口到子进程 bind 之间有极小时间窗被抢占，届时 spawn 会
  `EADDRINUSE` → 健康检查超时并报错，**不会**像旧实现那样静默连上一个来路不明的引擎。

### 发布阻断修复（补记录 + 补测试）：带 token 部署时前端两个主路由打不开

- `server/index.js` [SPA-DEEPLINK-FIX]：启用 `SCAN_API_TOKEN` 后，前端自己的 `/scan`、`/exploit`
  被 `API_SEGMENTS` 白名单当成 API 拦掉 —— 浏览器直接访问/刷新/收藏这两页拿到的是
  `{"code":401,...}` 一段 JSON，页面打不开（`/`、`/history`、`/report/:id` 反而没事）。
  开发模式（Vite 代理）与不带 token 时都看不到，所以此前从没暴露。
  判据收紧为四条**同时成立**才放行：GET + 裸路径（无子路径）+ `Accept` 含 `text/html`
  + `dist/index.html` 真实存在。数据接口（`/api/...` 基址与 `/scan/<id>/...` 子路径）不受影响。
- 新增 `server/tests/spaShellAuth.test.js`（4 条）：放行生效、不得扩大到 API 客户端（无
  `Accept: text/html` 仍 401）、不得扩大到子路径、数据接口带 token 正常返回业务码。
  **已做缺陷注入验证**：临时撤掉修复后**仅第 1 条 FAIL、其余 3 条仍绿**（说明四条边界各测一面，
  不是一红红一片），恢复后 4/4。
- 注：本条此前只存在于工作区未提交，README/CHANGELOG 均无记录，属「修了但没留痕」。

### 修复：盲注长度二分「顶到上界」时拿上界当长度（TODO §B）

`binaryProbe` 早就给出 `capped` 标记，但 `blindExtractor._binarySearch` 只 `return r.n + 1`，
把标记丢了 —— 判据失效时会**按上界逐字节提取**（历史事故：上界 65531，一个 5 字符的值
要提 6.5 万字符）。

修的时候发现「顶到上界」**有两种成因**，探测层面无法区分，一刀切判失败会打死正常长值
（实跑挂了 2 个用例），故分层裁决：

| 位置 | 含义 | 处置 |
|---|---|---|
| 主段（hi=255） | 也可能只是真实长度 ≥256 | 只打 `ctx.blindLenCapped`，交 `_extendLength` 预检 `>255` 裁决 |
| 延伸段，`blindMaxLen` 由用户显式配置 | 用户已授权「最多提这么长」 | 按 maxLen 截断提取（旧行为不变） |
| 延伸段，撞上默认护栏 4096 | 用户没授权过这么长 → 判据失效 | 判失败（-1 → 该字段返回 null） |

失败原因经 `ctx.blindLenCapped` 上浮，由 `scan/extract.js` 写进 `report.summary.constraints`。
新增 `server/tests/blindLenCapped.test.js`（3 条）；缺陷注入（撤销延伸段终审）→ **只有第 1 条红**
且实际值是一整串 4096 个垃圾字符，另两条（显式 blindMaxLen 截断 / 真长值 300 字节延伸）仍绿。

### 修复：concurrent-isolation 的确定性红 + 门禁「未跑」不可见（TODO §G）

- `e2e/concurrent-isolation/e2e.mjs` 建 MySQL 池**写死** `port:3306/user:root/password:'root'`，
  而 `run-all` 按 `deps:['sandbox']` 把它交给 `run-with-sandbox.py`（沙箱在 3308，注入
  `MYSQL_*`）。「声明走沙箱」与「实际连宿主」自相矛盾 → 两条 MySQL 扫描 `dbms=null techs=[]`。
  现统一读 `MYSQL_*` 契约；另加环境自检（连不上 / 库内 0 张表 → 显式 BLOCKED，退出码 2），
  不再把环境问题判成「并发串扰」归给被测代码。
  **实测**：沙箱路径下，写死 3306 时沙箱注入的空口令连不上宿主 → 退出码 2；改后 PASS（3/3 union 命中）。
- `run-all.mjs` 汇总新增「未跑（缺依赖，本轮零断言）」单列：此前缺依赖的靶场被直接过滤，
  连 SKIP 都不显示，「通过 6 / 失败 0」是假绿。
- 顺带：`--only` 只认空格形式，写 `--only=名字` 会**静默退化成跑全部**（实测想跑 1 个 0.5s
  套件结果跑了 21 个，含 77s 红队）。现两种写法都认并打印「定向模式」。

### 修复：CRS 执行器保真度门禁唯一的 FAIL（96% / 23 条未点名分歧 → 99.3% / 0）

- **病根**：CRS v4.1.0 的 pattern 用 PCRE 的组级大小写开关 `(?i:…)`。本仓跑在
  **Node 22.22.2（V8 12.4）**，该语法属 ES2025 regex modifiers（要 V8 13 / Node 23+），
  `new RegExp('(?i:…)', 'i')` 直接抛 `Invalid group` → 执行器 catch 后返回 null →
  **942160 / 942220 / 942250 / 942361 / 942450 五条规则恒不命中**，官方回归集漏 23 条
  （`sleep()/benchmark()`、整数溢出、`EXECUTE IMMEDIATE`、`^[\W\d]+\s*(alter|union)`、`0x` 十六进制）。
  ⚠️ 代码里原先有条注释断言「ES2025 已收进 JS，记进 regexBad 是误报」—— 实测打脸，
  那是把未来语法当现状，已改正。
- **修法**（`e2e/waf-real/crs-engine.js`）：新增 `toJsRegex()`，`(?i)` 删除、`(?i:…)` 降级为
  `(?:…)`（本执行器恒以 `flags:'i'` 编译，二者语义等价）；**运行期 `execOp` 与装载期普查探针
  共用同一个函数**，不再两套真相。反向开关 `(?-i:…)` 无法用全局 flag 表达，遇到即主动放弃
  （继续保守跳过 + 普查记一笔），不伪造大小写不敏感。
- **保留 try/catch**：降级只覆盖今天已知的两类构造；将来 CRS 升版引入别的 PCRE 语法时应
  「该规则不命中 + 普查记一笔 + 门禁 FAIL」，而不是让保真度脚本崩掉（崩掉反而看不见原因）。
- **缺陷注入验证**：撤销降级 → 保真度 **13.2% / 600 条未点名 → FAIL**；恢复 → **99.3% / 0 → PASS**。
- **影响面复测**：WAF 两档基线未退化 —— PL1 `8/8/8`、PL3 `0/0/0`（`waf-bits-baseline.json`
  无需收紧）；PL4 逐规则一致率 92.9% → **96.1%**，整体检出 96.9% → **98.8%**。

### README 口径校正（三处，按 2026-09-19 23:14 本机实测）

| 位置 | 原写 | 实测 / 现状 |
|---|---|---|
| 「WAF 绕过能力实测口径」整节 | off 2 → on 8、自动 11（PL3 归因） | **整节重写**：旧数字出自保真度 60.7% 的执行器，已作废；现按 PL1 `8/8/8`、PL3 `0/0/0` 两档基线表述 |
| 验收门禁「最近一次全量结果」 | 8 PASS / 3 SKIP | **10 PASS / 2 FAIL / 0 SKIP**（12 套件），两个 FAIL 的定位与处置已写进正文 |
| 测试数 / 徽章 | 1887 用例、2199 | **1893 用例、2207**（由 `npm run facts:refresh` + `facts:fix` 自动同步，`facts:check` 现一致） |

## [1.1.0] - 2026-09-18

### 安全加固（破坏性变更，请务必阅读「升级注意」）

- **默认鉴权（fail-closed）**：引擎新增统一 token 解析 `resolveApiToken()`。
  - 优先级：`SCAN_API_TOKEN_FILE`（Docker/K8s secret）→ `SCAN_API_TOKEN` → 回环监听允许无鉴权。
  - **监听非回环地址（含容器必需的 `HOST=0.0.0.0`）且未配置 token 时，引擎拒绝启动**并打印修复指引；
    确知风险可用 `SCAN_API_ALLOW_NO_TOKEN=1` 显式放行（启动打显著告警）。
  - `docker-compose.yml` 的 `SCAN_API_TOKEN` 改为必填（`${VAR:?}`），未设置时 compose 直接报错。
- **CSP 修复（影响 Docker 单端口部署）**：安全响应头按响应类型分流——
  `/api`、`/sqlmap` 仍为 `default-src 'none'`；前端静态资源改为放行 `'self'`（含 MUI 所需的
  `style-src 'unsafe-inline'`）。修复前 Docker/单端口部署打开即白屏（本地 Vite 与桌面端不受影响，
  故开发期难以发现）。
- **桌面端（Tauri）引擎连接加固**：
  - sidecar 端口不再写死 4567——被占用时自动改用空闲端口；
  - 引擎生成一次性 token（`crypto.randomBytes(32)`）经 stdout `ENGINE_TOKEN=` 回传，
    壳通过 `get_engine_info` 命令交给前端自动注入，本机其它进程无法再直连该引擎；
  - sidecar 缺失/启动失败不再 panic，改为广播 `engine-exit` + 前端「重启引擎」入口；
  - 引擎默认 `ALLOWED_ORIGINS` 增加 `http://tauri.localhost`、`tauri://localhost`。
- **静态外壳与 API 鉴权分离**：启用 `SCAN_API_TOKEN` 后，前端外壳（dist 静态资源与 SPA 路由）不再被
  token 中间件拦截（此前 `GET /` 直接返回 401 JSON，Docker/单端口部署下 **Web UI 完全打不开**）；
  所有数据接口（含不带 `/api` 前缀的 `/scan/*`、`/exploit/*`、`/sqlmap/*`）仍需 token。
- **桌面端 sidecar 可打包了**（此前无法构建）：
  - `npm run build:sidecar`（`scripts/build-sidecar.mjs`）走 Node SEA 路线：
    cjs bundle → SEA blob → postject 注入 → 冒烟（起 exe 断言 `/api/health`=200 与
    `ENGINE_TOKEN` 回传）。产物 `src-tauri/binaries/sqli-engine-<target-triple>[.exe]`（Windows x64 约 86 MB）。
  - 为什么不用 pkg：本机实测 `@yao-pkg/pkg --target node20-win-x64` 无预编译 base binary，
    退化为源码编译 Node 并因缺 NASM 失败。
  - 修复 `--format cjs` 产物不可运行：CJS 下 esbuild 不提供 `import.meta.url`，
    引擎入口定位前端产物时抛 `ERR_INVALID_ARG_TYPE`（此前该格式从未被验证过）。
  - 修复 `tauri.conf.json` 缺 `bundle.externalBin`：即使产出了 exe，`tauri build` 也不会打进安装包，
    运行时 `shell().sidecar("sqli-engine")` 找不到可执行文件。
  - `build:tauri` / `package:win` / `package:mac` 三条链已补上 sidecar 构建步骤。
  - **实测打包结果**：`npx tauri build --bundles nsis` 成功产出
    `SQL注入检测工具_1.1.0_x64-setup.exe`（26.4 MB，内含 90 MB sidecar 的 LZMA 压缩）；
    产物结构验证：`target/release/sqli-scanner.exe`（壳）+ `sqli-engine.exe`（sidecar）同目录，
    启动后日志 `[引擎] sidecar 已启动：127.0.0.1:4567`，`sqli-engine.exe` 进程在线。
  - ⚠️ **MSI（WiX）在当前用户目录下会失败**：`light.exe` 无法处理含全角括号的路径
    （`C:\Users\Admin（无密码）\AppData\...`）。因此 `package:win` 默认改用 NSIS；
    需要 MSI 时请在纯 ASCII 路径下构建。
  - **桌面版「直连 SQLite」已可用（B1，全内联方案）**：此前 sql.js 在 bundle 中为 external，
    SEA 单文件不含它，桌面直连 SQLite 会**静默回退**到内存自检驱动（扫得出结果但不是真库）。
    现改为**全内联**：
    - `scripts/build-engine.mjs` 新增 `--inline-sqljs`：sql-wasm.js 打进 bundle（不再 external）；
    - `sql-wasm.wasm` 作为 **SEA asset** 内嵌（`sea-config.json` 的 `assets`）；
    - 新增 `server/src/core/sqlJsLoader.js` 统一三种形态下的定位：SEA 用
      `require('node:sea').getAsset()` 取出 wasm 后经 `initSqlJs({ wasmBinary })` 直喂
      ——sql.js 一收到 `wasmBinary` 就跳过 `__dirname + readFileSync`，因此**零外部文件**。
    - 构建期硬断言：SEA asset 键名与 `sqlJsLoader.js` 的 `SQL_WASM_ASSET` 必须一致，
      且 `tauri.conf.json` 不得声明 sql.js 相关 `bundle.resources`（防两套依赖不同步）。
    - 冒烟升级：exe 在**全新空目录**下运行（旧版用 `cwd=dist-engine` 掩盖了外部依赖），
      并真跑一次直连 SQLite 扫描、按 SSE 事件断言 `detection_found ≥ 1`，
      同时检查引擎日志无「回退到内存自检驱动」告警 —— 负向验证：未内联版本该断言确实报 FAIL。
    - 为什么绕这么一圈：SEA 的 `require` 被劫持为「只认内建模块」，`require('sql.js')` 抛
      `No such built-in module: sql.js`，`NODE_PATH` 同样无效（实测四种方案对照）。
- **sqlmap `--eval` 默认禁用（A4）**：该参数会让 sqlmap 在服务端执行 **Python 表达式**（等价代码执行）。
  旧实现只打一条 warn 就透传；`POST /api/sqlmap/start` 的 body 是原样透传的，因此无鉴权部署下
  任何可达客户端都能提交表达式。现改为**双条件门控**：`SQLMAP_ALLOW_EVAL=1` **且**引擎已启用
  API 鉴权（`SCAN_API_TOKEN`）；不满足直接拒绝并给出启用条件（不静默丢弃参数）。
- **会话落盘注入点原始值加密（A5）**：`sessions/*.json` 的 `points[].originalValue` 在注入点为
  Cookie / 自定义认证头时等同于会话凭据，而 compose 还把 sessions 目录挂在 named volume 上。
  现**写盘封存（AES-256-GCM，`enc:v1:` 前缀）+ 读盘解封**，内存保持明文 ⇒ 断点续跑语义不变。
  密钥来源：`SCAN_SESSION_KEY` → 由 `SCAN_API_TOKEN` 派生 → 进程随机兜底；
  解不开的场景（换 key / 旧随机 key）把该点降级为「待重扫」，不会把密文当参数值发出去。
- **CI 门禁加固**：Docker 冒烟增加「无 token 必须 401」「静态资源 CSP 必须含 'self'」两条断言。
- **Rust 门禁可在本地复现（B4）**：
  - 新增 `src-tauri/rust-toolchain.toml` **单点锁定**工具链版本（`1.98.0` + `rustfmt`/`clippy`）。
    此前 CI 用 `dtolnay/rust-toolchain@stable` 会滚动到最新 stable，而 rustfmt 的换行/宏排版
    在小版本间会变、clippy 也会新增 lint → 会出现「本机格式化通过、CI 报 fmt 失败」这类
    不可复现的红。CI 同步改为 `@master` + `toolchain: 1.98.0`，两边完全同版本。
  - 修复 `src-tauri/src/lib.rs` 两处 `cargo fmt --check` 违规（纯排版：`.env(...)` 多行化、
    `invoke_handler!` 宏参数换行），均为 A3 加固时引入、此前**无任何门禁覆盖**。
  - 新增 npm scripts：`lint:rust`（fmt --check + clippy -D warnings）、`fmt:rust`、
    **`check:all`**（ESLint + 前后端 tsc + 架构门禁 + Rust 门禁，一条命令复现 CI 主门禁）。
  - 门禁灵敏度已实测：故意插入 `x == x` 会被 clippy 判 `error: equal expressions as operands`
    （退出码 101），证明「0 warning」不是空跑。
- **新增发布冒烟 `e2e/diag/release-smoke.mjs`**（已接入 CI 的 `release-smoke` job）：在临时沙箱里以
  **生产配置**（token + 托管 dist + 引擎常驻）跑完整链路——鉴权、跨站、CSP 分流、静态资源可达、
  真靶场扫描（API 与 CLI 两条路径）、五种报告交付物与退出码语义，共 30 项断言。

### 修复

- 报告导出确定性：`POC_CACHE` 由 WeakMap（键＝对象引用）改为稳定字符串键 + 容量上限，
  修复「同一份报告多次导出逐字节一致」偶发失败（实测修复前 3 次挂 1 次，修复后 5 次全过）。
- 拖库行切分（MySQL 系）：`GROUP_CONCAT` 显式行分隔符、分页下推进子查询、
  `CONCAT_WS` 的 NULL 安全包装，修复「多行落成 1 行且跨行串列」。
  - 真库实测：MySQL 8.0.28 的 `SEPARATOR` 只接受字面量（`SEPARATOR CHAR(30)` 为 1064 语法错误），
    改用 `0x1E`/`0x0A`；聚合结果的 `LIMIT/OFFSET` 对聚合输出无意义，已下推到源表行。
- 网络失败不再被判负：新增 `isNetworkFailureError()` 与 `addNetworkErrorPoint()`，
  注入点全部检测器因传输层失败时标记为未决（报告 `reliable=false`），不再写成「已检测、无漏洞」。
- 本地/私网目标默认绕过环境变量代理（`proxyBypassLocal`，默认开），
  修复装了系统代理时本地靶场扫描出现假阴性。
- ESLint 全量 31 处未使用导入/变量清理（大文件拆分遗留），并修复 `e2e/blackbox-lab/lab-app.mjs`
  中 `res` 未定义导致 WAF 拦截路径抛 `ReferenceError` 的缺陷。

### 依赖

- 服务端 `npm audit fix`：qs / body-parser 相关 3 项中危清零（当前 0 vulnerabilities）。

### 升级注意

1. **容器/非回环部署必须设置 `SCAN_API_TOKEN`**（或 `SCAN_API_TOKEN_FILE`），否则引擎起不来。
2. Web 端启用鉴权后需填写一次 token：首次 401 会弹出输入框（写入 `localStorage.scanApiToken`），
   或构建期注入 `VITE_SCAN_API_TOKEN`。
3. 桌面端升级后由应用自动注入端口与 token，无需手工配置；若从旧版升级，建议重新打包 sidecar。

## [1.0.0] - 2026-09-01

- 首个完整版本：Web / Docker / Tauri 桌面三端、CLI、9 类检测技术、拖库与利用能力、
  225 个 tamper 插件、报告导出（HTML/JSON/Markdown/SARIF/CSV）。
