# 全方面验证报告 · 2026-10-22（从头实跑，不引用历史结论）

> 方法：所有结论来自本轮**新执行的命令输出**（退出码 / HTTP 真实响应 / 靶场真值对照），
> 不采信 README、CHANGELOG、既有 e2e 报告里的数字。凡旧数字与本轮实测不一致处，一律在本报告点名。
>
> 环境：Windows 10 / node v22.22.2（系统）+ v24.18.0（构建用）/ npm 10.9.7 /
> MariaDB 10.11.19（含 `--secure-file-priv=D:/tools/mariadb/files`）/ PHP 8.3.0 /
> JDK 17.0.2 / Python 3.9.4。靶场源码本轮从 codeload 现拉，解压于
> `%TEMP%\verify-labs\`（juice-shop-20.3.0 / VAmPI-master / DVWA-master /
> Damn-Vulnerable-GraphQL-Application-master）；Benchmark 沿用 18:25 已起的实例
> （HSQLDB 9001 + Tomcat 8443 自签）。

## 一、静态门禁（28 项，全绿）

| 组 | 项 | 结果 |
|---|---|---|
| 代码质量 | `npm run lint` | exit 0 |
| 类型 | `npm run typecheck`（frontend + tests + server 三段） | exit 0 |
| 架构守卫 | arch / nesting / complexity / typecoverage / duplication / deadcode / errorstyle / debt（各含 `--selftest`） | 15/15 exit 0 |
| 一致性 | readme / facts / refs / modules(+selftest) / version / greenguard(+selftest) / e2e:wiring(+selftest) / artifact:drift | 11/11 exit 0 |

## 二、单测（两栈全绿）

| 侧 | 命令 | 结果 |
|---|---|---|
| 前端 | `npx vitest run` | 66 文件 / **574 tests 全过** / 0 fail / exit 0 |
| 服务端 | `cd server && npm test` | 100 suites / 3730 个测试节点 / **3724 pass / 0 fail**（其余 skipped/todo）/ exit 0 |

## 三、外部裁判真靶场（5 个，4 个跑通 1 个环境未就绪）

| 裁判 | 栈 | 结果（本轮实测） |
|---|---|---|
| VAmPI 5000/5001 | Python+Flask+SQLite | 真值 **2/2**（union/error/boolean 三通道）、同源复检 2/2、安全端点 **0/5 误报**、Bearer 5 端点 0 未测 ✅ |
| DVWA 8099 | PHP 8.3 + MariaDB 10.11 | 真值 **5/5**（low GET / blind low / **high cookie** / **medium POST** / blind medium POST）、同源 1/1、impossible 档 **0 误报**（两档各 150 请求）✅ |
| Benchmark 8443 | Java17 + Spring + HSQLDB | 三套清单全跑：**187 真值全检出、157 安全零误报**；`{call}` 形态 7 条单列（0/4 已知边界）✅ |
| DVGA 5013 | Python+Flask+Graphene | GraphQL 查询串内联注入 **1/1**（union/error/boolean）、安全点 search(keyword) **0 误报**、无 filter 结构对照 0 请求 ✅ |
| Juice Shop 3199 | Node+SQLite | **未跑通（4 轮尝试）**：① npm 10 装依赖崩 `edgesOut`；② npm 9 同崩；③ pnpm 装成功但 Angular 构建要求 node ≥22.22.3（换 node 24 后 `@codemirror/state` 解析失败）；④ 按 `lib/startup/validatePreconditions` 期望路径补占位静态资源，仍被 `customizeEasterEgg`/`customizeApplication` 接连索要 `JuicyBot.png`/`JuicyChatBot.png`/`threejs-demo.html` 等 UI 资产。⇒ 该靶场依赖**完整 Angular 构建**，无法只部署 API 层 |

> ⚠️ **后续更正（D137，2026-10-23）**：上格「未跑通 / 无法只部署 API 层」的结论**已被推翻**。
> 真因三条，全部可复现：① 源码树**缺整个 `data/` 目录**（partial 解压）——`JuicyBot.png` /
> `threejs-demo.html` 等资产本就在 `data/` 里，「接连索要资产」是缺目录的症状；`tar -xzf juice.tar.gz`
> 重解压即恢复。② 前端依赖必须**扁平**安装：`npm install` 在该 lockfile 上崩
> `Cannot read properties of null (reading 'matches')`；默认 strict 布局的 `pnpm install` 缺
> `@codemirror/state`（上游未声明、靠 npm 提升才可见）；`npx pnpm@9 install --shamefully-hoist`
> + `npx ng build --configuration production`（42s）即产出 validatePreconditions 需要的四个文件名。
> ③ 必须用 **Node 22**：Node 24 在 Windows 下扫该靶场搜索路由会触发 libuv
> `fs-event.c:72` 断言**当场崩进程**，裁判侧只见 ECONNREFUSED（引擎 validity-guard 正确判为不可信）。
> 结论：`--only=juice-shop` → **2/2 真值、0/4 误报**，该裁判不再是环境缺口。
> 台账条目：`juice-shop-runnable-local-d137`（status=refuted，附可复现命令）。

Benchmark 三套明细（本轮）：
`cases.json` 74（43 真值 + 24 安全 + 7 call）→ 43/43、0/24；
`cases-query.json` 210（111 + 99）→ 111/111、0/99；
`cases-header.json` 67（33 + 34）→ 33/33、0/34。

## 四、CLI 全链路（真扫）

`node server/bin/cli.js -u "http://127.0.0.1:8099/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie "security=low" -p id`
→ 检出 High、报告落盘、**退出码 2**（发现 Critical/High）。`--help` exit 0。

## 五、acceptance 验收门禁（本轮实测）

前置：MySQL ✅（建 `sqli_lab` 后）、`secure_file_priv=D:\tools\mariadb\files` ✅。

**汇总：16 PASS / 6 FAIL / 3 SKIP，exit=1。**

| # | 套件 | 失败事实 | 现场 |
|---|---|---|---|
| 1 | 独立刁钻靶场（11 场景） | **漏洞场景 8/11**；10 个场景未通过：ua/ck/bl/enc/json_deep/empty/mp 全部 `miss=[boolean]`（只检出 error），noisy/waf403/rdr **完全无检出** | `e2e/results/last-failure-pentest-lab.log` |
| 2 | 真 MySQL 靶场 | **3/11 PASS**：num/str/like/orderby `miss=[union|boolean]`，blind/b64url/noisy/time **完全漏检**，stacked 唯一 PASS（6158ms），safe/echo 0 误报 | `e2e/results/last-failure-real-mysql-lab.log` |
| 3 | 报告契约 | `✗ union 技术应被检出（显式 UNION 注入点）（["error"]）` | `e2e/results/last-failure-report-contract.log` |
| 4 | CRS 人工挂链 A/B（PL1） | `off=4 / on=4`，基线 `off≥8 on≥8`；tamper **无可证增益**；blind 0/1 全拦 | `e2e/results/last-failure-waf-real.log` |
| 5 | CRS 自动选链绕过（PL1） | 技术位 4 < 基线 8 | `e2e/results/last-failure-waf-auto.log` |
| 6 | fileWrite 真闭环 | 引擎自报 `{"ok":false,"wrote":true,"verified":false}` —— **wrote 与 verified 自相矛盾**；文件系统侧 `文件存在=false` | `e2e/results/last-failure-file-write.log` |

### ⚠️ 推翻记录：第 1、2 项 FAIL 不是引擎缺陷（2026-10-22 23:20，D126）

**原结论（已作废）**：「boolean 通道在低信噪比响应上失效」——刁钻靶场 8/11、
真 MySQL 3/11 被判为引擎能力退化，归因到「判定过严 / MariaDB 与 MySQL 方言差异」。

**反证**（同代码、同机器、只改测试库状态）：

| 测试库状态 | pentest-lab | real-mysql-lab |
|---|---|---|
| 只有库、无表（acceptance 当时正是这个状态：我只 `CREATE DATABASE sqli_lab`） | **1/11**，逐条复现 acceptance 的 10 个失败 | **3/11** |
| 跑过 schema 初始化（users 6 行 / products 4 行） | **11/11** | **11/11**（含 `time` 6291ms、`stacked` 6155ms） |

根因：靶站直接 `SELECT ... FROM users / products`；缺表时每条查询都 SQL 报错 ⇒
真/假条件响应同形（都落到错误页）⇒ boolean / time 拿不到信号。
**环境缺失被伪装成了能力退化**，而报告只写「真值漏检」，把排障引向了引擎。

**新结论**：boolean / time 通道在 MariaDB 10.11 上正常（11/11 覆盖 noisy / rdr /
waf403 / empty / blind / b64url / time / mp / json_deep / enc / bl）。
真缺陷在 e2e 侧：**套件不校验 schema 是否存在，缺表时报「漏检」而不是 SKIP/自愈**。

**已修（D126）**：`e2e/lib/sqliSchema.mjs` 统一幂等初始化（缺库建库 / 缺表建表 /
空表灌种子，既有数据不覆盖），由 `init-db`、`pentest-lab`、`real-mysql-lab`、
`acceptance` 前置四处共用；11 条单测 + 缺陷注入复验（改坏 missing 判定 → 3 红）。
复验：**空库** `acceptance --only=pentest-lab,real-mysql-lab` → 前置行打印
`schema 自愈：新建表[users、products] 灌种子[users、products]`，**2 PASS / exit 0**。

**旁证（排除"规则/资产缺失"解释）**：
`node scripts/fetch-crs-assets.mjs --verify-rules` exit 0，REQUEST-942/930 与
CRS v4.1.0 入库快照逐字节一致；`CRS 执行器保真度` 套件 PASS（99.6%，误触 2）。

**SKIP（环境不满足，不计通过）**：OOB 真机（5432 无 PG）、OOB interactsh 隧道、
Juice Shop（未就绪）。

## 六、已确认的缺口清单（按严重度）

### P0 · 门禁红 / 能力声明不成立
1. ~~**boolean 通道在低信噪比场景大面积失效**~~ —— **已推翻（见上「推翻记录」）**：
   实测是测试库缺表，有表时两套件均 11/11。D126 已修 e2e 前置，本项不再成立。
2. **WAF PL1 场景检出 4/8 < 基线 8/8**（人工链与自动链均红）。tamper off=on=4 ⇒
   「挂链有增益」在当前环境不成立；blind 场景被 CRS 全拦（0/1）。
3. **显式 UNION 注入点的 union 通道漏报**（report-contract：技术位只有 `["error"]`）。
4. **fileWrite 自报与事实矛盾**：`wrote:true / verified:false / 文件存在=false`。
   环境侧看，`remotePath` 落在 `%TEMP%\mysql-fw-lab\out`，而 mysqld 的
   `secure_file_priv` 指向 `D:\tools\mariadb\files\` —— **写路径与授权目录不一致**
   直接导致 INTO OUTFILE 被拒；但不能因此原谅自报 `wrote:true`：未验证落盘
   就不该置 wrote，这正是本仓自己定义的「中间层自报成功、无人校验外部事实」缺陷形态。

### P1 · 验证基线不可复现（文档与实测脱节）
5. **Benchmark 数字三处不一致**：README 顶部「20/504 子集、真值 4/12」；底部
   「D117 累计 327 有效、真值 178/178、安全 0/149」；本轮三套实跑 **344 有效
   （187 真值 / 157 安全）+ 7 call**。三者互不相等，需按新口径重算并统一。
6. **Juice Shop 起法在本机不可复现**（4 轮均失败，细节见上表）。README 记的
   「本机已验证链」缺 5 个坑：`npx tsc` 必须 `-p typescript@x`（裸包名报
   `could not determine executable`）；主依赖树缺 `possible-typed-array-names`
   （npm install 报成功、运行时崩）；frontend lockfile 与 npm 10 **和** 9 均崩在
   `edgesOut`（只有 pnpm 能装）；Angular CLI 硬门槛 node ≥ 22.22.3；启动前置检查
   + `customizeApplication` 要求**完整前端产物与多张图片资产**，不能用占位绕过。
   ⇒ 新机器照 README 走不通；该裁判的 e2e 在 CI 里若也 SKIP，则「Juice Shop 2/2 检出」
   这条历史结论**本轮无独立复现证据**。
7. **acceptance 隐性前置未入文档**：不建 `sqli_lab` 库则 MySQL 前置报
   `ER_BAD_DB_ERROR`；`secure_file_priv` 为 NULL 时文件读写相关套件静默 SKIP。
8. **DVWA README 的手工复核 curl 全部缺 `&Submit=Submit`**：新版 DVWA 的
   `source/low.php` 只在 `isset($_REQUEST['Submit'])` 时执行查询。按 README 照抄
   （`?id=1`、`?id=1'`）得到的是空响应，会误判成「靶场坏了」。本轮已实测：
   带 `Submit` 后 admin 回显 / SQL 语法错误 / UNION 回显 1,2 三通道全部正常。

### P2 · 本轮未验证的面（不等于不存在，等于没有证据）
9. **桌面端（Tauri/Rust）零验证**：cargo 1.98 可用，但本轮未跑 `lint:rust` /
   `build:tauri` / `src-tauri` 产物冒烟。
10. **生产构建** `vite build`、**REST API**（4567 起停 + SSE）、**MCP stdio 模式**、
    **SEA 单文件打包**（`build:engine` / `build:sidecar`）、**性能预算**
    （`perf:budget`）、**sqlmap 同题对标**、**WAF 真机容器**（本机无 Docker）——均未覆盖。
11. **7 个参考靶场永久在门禁外**（`e2e/reference-labs.json`）：blackbox-lab、
    ntlm-lab、sqli-labs（**作者自撰靶场，真值自证**）、fullchain-lab、
    sqlmap-benchmark、cross-module-lab、dvga-lab。
12. **CI 与本机门禁漂移**（reference-labs.json 自曝）：greenguard /
    coverage-calibration 的 selftest 只在 `scripts/ci-local.mjs` 的 lint 组，
    `.github/workflows/ci.yml` 一步都没跑。

### P3 · 仓库纪律
13. 工作区存在**未提交的 D125（triage）批次**（`git status` 有 7 个 `??` 新文件 +
    多个 M），与本轮验证并行存在并发写入风险。
14. `docs/_claims-ledger.json` 24 条中 5 条 `refuted`（detect-benchmark-redteam-26、
    waf-bypass-legacy-claim、external-judge-dvga-d114、graphql-inline-injection-gap、
    external-judge-benchmark-d114）——按 §3.5 协议第 3 步应已完成重做，本轮未逐条核对
    重做后的新证据是否已替换所有引用点。

## 七、建议的处置顺序（按 ROI）

| 序 | 批次 | 内容 | 完成判据 |
|---|---|---|---|
| 1 | D126 | **boolean 通道加固**：先用 `pentest-lab` 的 `noisy` / `rdr` 两个最小样本复现，再定位是 Z 检验阈值、基线样本数，还是缺少「响应稳定性预筛」；MariaDB vs MySQL 8 做一次 A/B 归因 | `pentest-lab` 11/11、`real-mysql-lab` 11/11 |
| 2 | D127 | **fileWrite 自报修复**：`wrote` 只由外部事实（文件存在 + 标记内容）置位；套件路径改为读 `@@secure_file_priv` 动态对齐 | `acceptance --only=file-write` PASS，且缺陷注入复验（写失败时 `wrote` 必须 false） |
| 3 | D128 | **WAF PL1 口径处置**：4/8 vs 基线 8/8。要么 bisect 到退化引入点，要么按实测收紧基线并在 CHANGELOG 记推翻链（保留旧数字，§3.5 第 4 步） | `waf-real` / `waf-auto` 绿，且基线文件与 CHANGELOG 同步 |
| 4 | D129 | **文档数字统一**：Benchmark 三处口径、DVWA 手工 curl 补 `Submit`、acceptance 前置写入 README | `readme:check` / `facts:check` 绿 + 三处数字一致 |
| 5 | D130 | **e2e 环境固化**：四个靶场起法收敛成一个幂等脚本（含 node/php/java 版本门槛检查）；Juice Shop 改用 docker 镜像或预构建产物 | 新机器一条命令起全五裁判，`acceptance` 零 SKIP |
| 6 | — | **CI 门禁漂移**：greenguard / coverage-calibration selftest 接入 `ci.yml` | CI 日志出现这两项 |
| 7 | — | **桌面端冒烟**：`lint:rust` + `tauri build`（或至少 `cargo check`） | 退出码 0 |

## 八、复现命令索引

```bash
# 静态
npm run lint && npm run typecheck
for s in arch:guard nesting:guard nesting:selftest complexity:guard ... debt:selftest; do npm run $s; done
npm run readme:check && npm run facts:check && npm run refs:check && npm run e2e:wiring -- --selftest

# 单测
npx vitest run
cd server && npm test

# 外部裁判
VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 node e2e/vampi-lab/run.mjs
DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs
DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs
node e2e/benchmark-lab/run.mjs
BENCHMARK_CASES=e2e/benchmark-lab/cases-query.json node e2e/benchmark-lab/run.mjs
BENCHMARK_CASES=e2e/benchmark-lab/cases-header.json node e2e/benchmark-lab/run.mjs
JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs

# 验收
node e2e/acceptance.mjs

# WAF 资产（排除"环境缺规则"这一解释）
node scripts/fetch-crs-assets.mjs --verify-rules
```
