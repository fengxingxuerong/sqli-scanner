# Changelog

本项目版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
