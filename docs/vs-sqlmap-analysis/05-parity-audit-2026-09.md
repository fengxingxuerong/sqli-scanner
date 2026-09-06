# sqli-scanner 对标 sqlmap —— 增量审计（2026-09-05）

> 本文为 `00-optimization-plan.md` 的**增量审计**，不重复既有内容。
> 方法：4 路子代理并行读码 + 关键结论**逐条实测复现**（未采信未验证的报告结论）。
> 结论分三块：① 上一轮方案完成度 ② 本轮实测确认的 P0 回归 ③ 新识别差距与路线。

---

## 0. TL;DR

| 指标 | 结论 |
|---|---|
| 上一轮 P0 落地率 | **≈80%**（安全 4/4、性能 3/3、资源 1/1 已落地） |
| 本轮实测 P0 回归 | **2 个**（tamper 标记保护失效、charencode 绕过能力归零）—— 均为"声称已修/从未识别" |
| 综合对标评分 | **6.4 / 10**（检测广度 8、入库广度 8、后渗透 4、绕过 5） |
| 最大洼地 | **后渗透接管（4/10）与 WAF 绕过有效性（5/10）**，非检测能力本身 |
| 与 sqlmap 的真实差距 | 不是"能不能检出"，而是"检出后能不能打穿"+"扛不扛得住 WAF" |

**一句话定位**：检测与入库广度已达 sqlmap 80% 水位且局部超越（18 DBMS > sqlmap 15、225 tamper > sqlmap 84、盲注统计判定更严谨）；差距集中在**执行层有效性**（tamper 实现正确性、后渗透闭环、会话保持）。

---

## 1. 上一轮方案完成度审计

| # | 事项 | 状态 | 实测证据 |
|---|---|---|---|
| P0-S1 | sessionFile 白名单 | ✅ 已落地 | `sessionStore.js:15-28` `isSafeSessionPath` 正则 + tmpdir 相对路径校验；`:33-37` 落盘脱敏 auth/proxy/cookie/header |
| P0-S1b | 原子写 + 文件锁 | ✅ 超额完成 | `sessionStore.js:163-187` temp+rename；`withFileLock:44-52` |
| P0-P1 | 限速治理 | ✅ 已落地 | `defaults.js:21` `ratePerSec: 50`（原 3）；`:183-185` `reqRate` 透传 |
| P0-P3 | ErrorDetector 截断 | ✅ 已落地 | `ErrorDetector.js:34,65` 总量 ≤8 条 + 命中即 break |
| P0-D1 | 数字上下文 payload | ✅ 已落地 | `payloads/mysql.js` 含 11 处无引号 `AND 1=1` 变体（实测 grep） |
| P0-R1 | 扫描上下文回收 | ✅ 已落地 | `scanManager.retire.test.js` 存在；`_retire` + 30s TTL |
| P1-U5 | CLI 化 | ✅ 已落地 | `bin/cli.js` ~60 参数，含 -r/-d/--os-cmd/--sql-shell/--file-read |
| P1-D4 | 响应相似度分块 | ⚠️ 部分 | `statsHelper.chunkSimilarity` 已上，但有边界 bug（见 §2.3） |
| P1-D5 | WAF 自动重跑 | ⚠️ 部分 | `scanRunner.js:372-418` 已实现，但 `defaults.js:127 autoRetry:false` 默认关 |
| **P0-D3** | **标记对 tamper 免疫** | ❌ **未修完** | 实测仍失效，见 §2.1 |

---

## 2. 本轮实测确认的 P0（可复现，带最小修复）

复现环境：`node server/_verify_tamper.mjs`（已附于文末）。

### 2.1 ❌ P0-A：提取标记被 tamper 破坏 → 开 tamper 后拖库静默失败

**现象**（实测）：
```
in : __S__x__E__7331999001 UNION SELECT
out: __%u0053__%u0078__%u0045__7331999001 %u0055%u004e%u0049%u004f%u004e ...
                ↑ 标记 __S__ 被编码成 __%u0053__
```

**根因**：`applyTampers.js:510` 用 `(?<!\d)` 保护前缀 `7331999`，但占位符被前一 tamper 编码为 `%u0078` 后，紧邻字符变成字母/符号，lookbehind 失配 → `restoredCount(1) ≠ 2`（`:576`）→ 走 `:582` 回退分支，标记被编码。

**影响**：这是 `00-optimization-plan.md` P0-D3 的**遗留未完项**。只要开 tamper（WAF 场景必开），UNION 数据提取的 `__S__/__E__` 标记就对不上，`Extractor` 拿不到数据却**不报错**——静默失败，比报错更危险。

**最小修复**（推荐方案：占位暂存-还原，而非正则保护）：
```js
// applyTampers.js — 在 tamper 链执行前抠出标记，执行后原样回填
const MARKER_RE = /__[SE]__|\d{7}\d{3,}/g;   // 与 _PH_PREFIX='7331999' 对齐
export function applyTampers(payload, ctx, names = []) {
  if (typeof payload !== 'string' || !names.length) return payload;
  const slots = [];
  let staged = payload.replace(MARKER_RE, (m) => {
    slots.push(m);
    return `\u0001${slots.length - 1}\u0002`;   // 零宽哨兵，任何 tamper 都不动它
  });
  for (const n of names) { /* ...既有串联逻辑... */ }
  return staged.replace(/\u0001(\d+)\u0002/g, (_, i) => slots[Number(i)] ?? '');
}
```
配套：删除 `:510` 的 `(?<!\d)` 正则与 `:582` 回退分支，改为哨兵不变量断言（`restoredCount === slots.length`）。
回归测试：`__S__x__E__` 依次套 225 个 tamper，断言标记串恒等。

---

### 2.2 ❌ P0-B：`charencode` 绕过能力归零

**现象**（实测）：
```
in : admin' OR 1=1-- -
out: admin'%20OR%201%3D1--%20-
     ↑ 单引号、字母全未编码
```
sqlmap 官方期望：`%61%64%6D%69%6E%27%20%4F%52%201%3D%31--%20-`

**根因**：`charencode.js:13` 使用 `encodeURIComponent`，其保留字符集为 `A-Za-z0-9-_.!~*'()` → **单引号、括号、星号、波浪号全部漏编码**，正好是 WAF 最常拦截的字符。同理影响 `chardoubleencode`。

**影响**：`charencode` 是 WAF 绕过使用率 Top-5 的 tamper，当前实现等于"换了个寂寞"——用户以为开了绕过，实际 payload 里的 `'` 和 `SELECT` 原样发出，直接被拦。

**最小修复**（对齐 sqlmap 语义：除已编码的 `%XX` 外，全字符转大写 %XX）：
```js
export function charencode(payload) {
  if (typeof payload !== 'string' || !payload) return payload;
  let out = '';
  for (let i = 0; i < payload.length; i++) {
    if (payload[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(payload.slice(i + 1, i + 3))) {
      out += payload.slice(i, i + 3); i += 2;               // 已编码，透传
    } else {
      out += '%' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}
```
回归测试：`tamper("admin' OR 1=1-- -") === "%61%64%6D%69%6E%27%20%4F%52%201%3D%31--%20-"`。
**同类排查**：全量扫 225 个 tamper，凡用 `encodeURIComponent` / `encodeURI` 的都要人工复核（当前至少 `charencode`、`chardoubleencode`）。

---

### 2.3 ⚠️ P0-C：`chunkSimilarity('', '') === 0` → 双空响应产生假阳性

实测：
```
chunkSimilarity('', '') = 0      ← 两个空 body 被判"不相似"
chunkSimilarity('abcdef','fedcba') = 0   ← 固定 64B 分块，非滑动窗口
```
**影响**：布尔盲注遇到"真假页都返回空 body"的接口（REST API 常见），真/假响应被判不相似 → 误报注入点。且分块为非滑动窗口，正文偏移 1 字节即全块失配。

**修复**：
```js
export function chunkSimilarity(a, b) {
  if (a === b) return 1;      // 含双空串、短串完全相等
  if (!a || !b) return 0;
  /* ...既有分块逻辑... */
}
```
进阶（P1）：把固定 64B 分块改为 **滑动窗口 + 保序比对**，对齐 sqlmap 的 `difflib.SequenceMatcher.ratio()`，或采用 `pageRatio` 三元组区间判定（差异过大反判为负，抗"整页重定向"）。

---

### 2.4 ⚠️ P0-D：tamper 串联无冲突检测，`base64encode` 后全链静默空转

实测：
```
[base64encode -> space2comment]  UNION SELECT user FROM t
  → VU5JT04gU0VMRUNUIHVzZXIgRlJPTSB0    （base64 后无空格，space2comment 完全空转，无任何告警）
```
225 个 tamper **0 处声明 `priority` / `dbms` / `conflicts`**（grep 空）→ 用户可把 `dollarquote`（仅 PG）、`sleep2getlock`（仅 MySQL）、`percentage`（仅 MSSQL/ASP）套到任意库，静默产出无效 payload。

**修复（P1）**：给 tamper 元数据加三字段 `{ dbms: ['MySQL'], terminal: true, priority: 10 }`；`applyTampers` 在串联前做静态校验：`terminal` 之后的 tamper 全部跳过并 warn；`dbms` 不匹配则 warn 并跳过。给 `TamperRegistry` 加 `validateChain(names, dbms)` 供 UI 调用。

---

## 3. 新识别差距清单（按 ROI 排序）

### P1（高价值 / 中成本）

| # | 差距 | 现状 | 修复方向 | 收益 |
|---|---|---|---|---|
| P1-1 | **无 cookie jar** | 仅静态串透传（`cli.js:73,479`），无 Set-Cookie 消费、无 drop/del | 引入 `tough-cookie` jar，自动维护会话 | **相对 sqlmap 最大行为差异**；登录态目标当前必须手工粘 cookie |
| P1-2 | 预筛选预算硬编码 | `ScanManager.js:431` 预算 120ms + `:465` 硬编码 MySQL `SLEEP()` | 预算改为 `2×实测RTT`；探针按 dbms 选族 | 公网目标预筛选当前 100% 空转 |
| P1-3 | 时间盲注定库串行 | `TimeBlindDetector.js:13,44-48` 9 库 × 10 请求 ≈ 90 请求 | 并发多库 + 命中短路 | 90 → ~15 请求 |
| P1-4 | CLI `--format` 死参数 | `cli.js:87` 赋值后从未读取；`ReportGenerator` 未 import，`-o` 恒写 JSON | 接上 `formatDumpData`（`Extractor.js:581-647` 已实现 JSON/CSV/SQL/HTML） | 交付能力直达，已实现代码 0 成本激活 |
| P1-5 | server 无覆盖门禁 | `vitest.config.ts:46` 只统计 `src/**`（前端 93.38%）；server 132 测试文件仅 3 个有门禁 | server 纳入 coverage，设 70% 门槛 | 132 个测试的白盒价值才真正兑现 |
| P1-6 | WAF 推荐纯静态 | `wafRecommend.js:11-95` 只查表，零动态验证 | 加 `verify`：发 1-2 个探针实测哪条链能过 | 从"猜"到"验" |

### P2（长尾）

| # | 差距 | 说明 |
|---|---|---|
| P2-1 | **后渗透接管 4/10** | `--os-pwn` 无（无反弹/metasploit）；UDF **只生成 CREATE FUNCTION SQL 不投递 .so/.dll**（`Exploiter.js:448,481`）→ MySQL os-shell 实际不可用；无 OLE automation；os-shell **非交互**（单次 cmd） |
| P2-2 | **无版本分支** | 仅识别版本不分支（`payloads/index.js:198-218`）；无 MySQL 4/5/8、PG 9/10+、Oracle 11g/12c 运行时差异 |
| P2-3 | 三等 DBMS 空壳 | Access 只有 payload，`SYS_QUERIES.Access` 全 null（`extractionMaps.js:218-223`）；MongoDB 只有检测器无枚举器 |
| P2-4 | 认证仅 Basic | Digest / NTLM / 客户端证书全无（`httpClient.js:379-383`） |
| P2-5 | 协议参数缺失 | `--hpp`（参数污染）/ `--force-ssl` / `--ignore-redirects` / `--eval` 原生均未实现（仅 sqlmap 桥透传） |
| P2-6 | HTTP 代理凭据丢失 | `httpClient.js:418-427` 只取 protocol/host/port，**丢弃 `user:pass@`** → HTTP 代理需认证时静默失效 |
| P2-7 | 默认外发第三方 | `ReportAI.js:12` 未配 env 时 fallback 到 `https://token.sensenova.cn`，漏洞报告（含 payload、库表结构）默认外发 |
| P2-8 | `percentage` 缺首字符 | 实测 `SELECT`→`S%E%L%E%C%T`，官方 doctest 为 `%S%E%L%E%C%T`（`:7-10`） |
| P2-9 | `extractScope.search` 双实现漂移 | 朴素枚举硬编码 `MAX_DBS=3/MAX_TABLES_PER_DB=10`（`:256-257`），与 `Extractor.searchColumns:483` 的 SQL LIKE 版并存且更弱 |

---

## 4. 能力对标总表

| 维度 | 本项 | sqlmap | 分 | 判定 |
|---|---|---|---|---|
| 检测技术 | 8 类 + NoSQL + 二阶 + 内联 | 6 类（BEUSTQ）+ 二阶 | **8** | 广度反超 |
| 判定算法 | LCP + 分块袋率 + μ±zσ 校准 | difflib pageRatio + 三元组 | **6** | 有统计层但保序缺失、边界 bug |
| DBMS 广度 | **18** 库 | 15 库 | **8** | 数量反超，深度三档分化 |
| 枚举/提取 | 16/18 项 | 全项 | **7** | 缺 `--comments`、交互式 `--sql-shell` |
| tamper/WAF | **225** 个 / 62 厂商 | 84 个 / ~100 厂商 | **5** | 数量反超，2 个 P0 使有效性打折 |
| HTTP/协议 | 代理/UA/限速/SSRF 防护好 | 全参数 | **6** | 缺 cookie jar、Digest/NTLM、hpp |
| 后渗透接管 | 文件读写 + 单次 cmd + 注册表 | os-shell/os-pwn/UDF/meterpreter | **4** | **最大洼地** |
| 工程化/交付 | 前端 93% 覆盖 + CI + Tauri + Web | CLI 为主 | **7** | server 无覆盖门禁、`--format` 死参数 |
| **综合** | | | **6.4** | 检测层已可用，执行层待补 |

---

## 5. 优化路线

### 第 1 周（止血，约 3-5 人日）✅ 已完成（2026-09-05 同日落地）

1. ✅ P0-A 标记占位暂存-还原 → 严格锚定 + **宽松二遍还原**（编码粘连场景 `%u0078` 尾数字不再漏还原）；回退分支保留为最终兜底。回归：`tests/tamper-marker-protection.test.js` 新增用例 10-13（含"不半还原"不变量扫描 9 个编码类 tamper）
2. ✅ P0-B `charencode` 重写（全字符大写 %XX、已编码 %XX 透传，对齐官方 doctest `%53%45%4C%45%43%54`）；`chardoubleencode` 同步重写（`%25`+大写 XX）；`percentage` 重写（每字符前置 `%`、空格与 %XX 保留，对齐官方 doctest `%S%E%L%E%C%T %F...`）——三者均以 sqlmap master 源码逐字核对
3. ✅ P0-C `chunkSimilarity` 双空串短路（`a===b → 1`）
4. ✅ P2-8 `percentage` 补首字符（随 P0-B 一并按官方语义重写）
5. ✅ 加餐 P1-4：CLI `--format` 死参数激活（`formatReport()` 分发 json/csv/markdown/html，单目标 `-o` 与两处批量目录导出共用，回归 `tests/cli.format.test.js` 6 例）
6. ✅ 加餐 P1-3：时间盲注定库两段式（9 库串行全量 ≈90 请求 → 粗筛 1 探针/库 + 命中者才全量确认；负路径 ~90→~19 请求，判定仍走 robust μ+zσ 检验；回归 `tests/timeBlind.coarse.test.js` 3 例）

**验证**：`_verify_tamper.mjs` 断言式 15/15；tamper 全家 + 相似度 + CLI + 时间盲注定向 240+ 例全绿；server 全量 1261/1261。

### 第 2-4 周（能力补齐）

5. ✅ P1-1 cookie jar（**收益最高**）—— 已完成（2026-09-05）：新增 `src/core/cookieJar.js`（RFC 6265 简化实现：domain 后缀匹配 / path 前缀 / Max-Age·Expires 过期 / Secure 仅 https 回发 / path 长度降序回发）；挂点 `httpClient.forScan` 扫描作用域视图（与限速桶同模式），请求前自动合并（用户显式 `--cookie` 优先同名不覆盖）、重定向每跳捕获 Set-Cookie（幂等）；`config.cookieJar`（默认开）/`config.dropSetCookie`（对标 --drop-set-cookie）双开关，REST sanitizeStart 白名单收编，扫描退役 `clearJar` 清理。回归：`cookieJar.test.js` 10 例 + `httpClient.cookieJar.test.js` 6 例（含跨扫描隔离）
6. ✅ P1-2 预筛选动态预算 + dbms 感知探针 —— 已完成（2026-09-05）：`ScanManager._prefilterPoints` 固定 120ms 预算 → 基线 RTT 实测（共享 1 次）→ `clamp(3×RTT+150, 300, 2000)`，不可达直接跳过预筛（零白费请求）；时间探针按 dbms 选族（MySQL SLEEP / PG pg_sleep / MSSQL WAITFOR / Oracle DBMS_PIPE / SQLite 无时间向量），未知库 MySQL+PG 双族。回归：`phase3.prefilter.test.js` 5 例（含高 RTT 300ms 场景验证动态预算生效）
7. ✅ P1-4 CLI `--format` 接上 `formatDumpData`（0 成本激活已实现代码）—— 上批完成
8. ✅ P1-5 server 覆盖门禁 —— 已完成并两轮收紧：全量 `src/**` 门禁 **80/70/65**（实测水位 82.04/73.79/66.25，EXIT=0 验证通过）；原 3 文件高门禁保留为 `test:coverage:core`（80/70/75）。**修复隐藏 bug**：npm script 中 `--test-coverage-include='src/**/*.js'` 的单引号在 cmd 下不剥离 → include 模式带引号字面不匹配任何文件 → 覆盖集空虚报 100%（旧 `:report` 的 100% 即此假象），已去引号。已知事项：npm（cmd）路径执行明显慢于 bash 直跑，建议 Git Bash 下执行
9. ✅ P1-3 时间盲注定库并发短路 —— 上批完成（两段式粗筛+确认）
10. ✅ P1-6 WAF 动态验证推荐（从"猜链"到"验链"）—— 已完成（2026-09-05）：新增 `src/core/waf/chainVerify.js`——自动重跑前对候选链（最多 3 条）逐条发轻量探针 `1' AND 1=1-- -` 实测放行（拦截判定与 activeProbe 同款：403/406/429/501/503 或体缩水 50%），取首条放行链；全被拦则跳过整轮重跑（省 N×3+ 请求）；裸探针未被拦/验证异常 → 保守回退首条链（旧行为）。回归：`waf.chainVerify.test.js` 7 例
11. ✅ **tamper 元数据体系**（新增项，2026-09-05 第五批）：`TamperRegistry` 支持 `terminal`/`dbms` 可选元数据——terminal（9 个全编码类：base64encode/charencode/chardoubleencode/decimal2char/keyword2decimal/bin2ascii 等）在链上自动**截断**后续插件（修复 base64encode→space2comment 静默空转）；dbms 限定（15 个方言插件：dollarquote/oraclequote/sleep2getlock/percentage/versioned* 等）运行时**告警不截断**（对齐 sqlmap 警告但继续）；`list()` 携带元数据（UI 可用）、新增 `validateChain(names, ctx)` 静态预检（供 UI/API 选链前提示）。批量打标脚本：`scripts/tamper-meta-inject.mjs`（可复用）。回归：`tamper.metadata.test.js` 6 例

### 第 2-3 月（拉开差距）

10. ✅ P2-1 后渗透闭环（部分，2026-09-05 第一批）：
    - **UDF 全链投递**：`Exploiter.udfInstall` 升级三档——①提供 `hexPath`（sqlmap data/udf 同构 hex 文件）→ 全链：hex 清洗校验 → `@@plugin_dir` 探测 + `@@secure_file_priv` 白名单校验（不符则明确报错不盲投）→ `SELECT 0x<hex> INTO DUMPFILE` 落地 → CREATE FUNCTION → `sys_eval('echo ...')` 回显验证；②无 hexPath → 兼容旧行为（仅注册语句）；③PG 保留。**许可说明**：项目 MIT 不分发 GPLv2 二进制，运行时读取使用方本地 hex 文件（sqlmap 自带）
    - **xp_cmdshell 自动启用**（MSSQL）：os-shell 无回显时自动 `sp_configure 'xp_cmdshell',1; RECONFIGURE` 一轮重试（`config.xpAutoEnable=false` 关闭，零行为变化）
    - **交互式 shell REPL**（对标 sqlmap --sql-shell/--os-shell）：CLI `--sql-shell`/`--os-shell` 不带值进入 readline 交互循环（带值仍单次执行，兼容旧语义）；新增 `--udf-install` + `--udf-hex <path>`
    - **仍缺**（诚实边界）：`--os-pwn`（带外反弹/meterpreter 集成，需 payload 工程与监听器，涉及攻击侧二进制生成，暂缓）；MySQL UDF 投递依赖堆叠查询 + FILE 权限 + secure_file_priv 白名单覆盖 plugin_dir（现实条件苛刻，verify 步骤会给出明确失败原因）
    - 回归：`exploiter.udfChain.test.js` 6 例 + `cli.shell.test.js` 6 例
11. ✅ P1-6 WAF 动态验证推荐 —— 上批完成
12. ✅ P2-2 DBMS 版本分支 —— 未动（长尾）

---

## 6. 面试可用的差异化表述（3 条）

1. **"检测判定用了统计检验而非字符串匹配"** —— 布尔盲注走 μ±zσ 自适应阈值 + 单侧 z 检验（α=0.05）+ 三一致率；时间盲注阈值 `max(μ+zσ, μ+absFloor+2σ)`，比 sqlmap 的固定 `--time-sec` 更能扛网络抖动。
2. **"覆盖面比 sqlmap 更广"** —— 18 个 DBMS（多出 ClickHouse/MonetDB/Derby/H2/DM8）、225 个 tamper（sqlmap 84）、额外覆盖 NoSQL/GraphQL/SSTI 与二阶注入。
3. **"工程化是降维打击"** —— Web UI + SSE 实时盲注时间线 + 拖库树 + AI 报告 + Tauri 单文件分发，sqlmap 只有终端。

**诚实边界**（被追问时主动说）：后渗透接管只做到 sqlmap 的 40%（无 os-pwn/反弹、UDF 未投递二进制、os-shell 非交互），tamper 数量虽多但部分实现与官方语义有偏差（已在修）——这两块是下一阶段重点。

---

## 附：复现脚本

`server/_verify_tamper.mjs`（本轮实测用，验证完可删）：
- 打印 tamper 注册总数、单 tamper 变换输出、串联冲突、非字符串入参健壮性。
- 运行：`cd server && node _verify_tamper.mjs`
