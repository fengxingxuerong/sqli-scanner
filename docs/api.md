# sqli-scanner REST API 文档

> 引擎默认监听 `127.0.0.1:4567`。所有端点同时挂载在 `/api`（Web 版，Vite 代理）与 `/`（Tauri 版直连）双前缀下，契约完全一致。
> 统一响应包：`{ "code": 0, "data": <任意>, "message": "ok" }`；`code !== 0` 表示业务错误，HTTP 状态码恒为 `200`（业务错误通过 `code` 表达），鉴权失败例外（HTTP `401`）。

---

## 1. 通用约定

- **Content-Type**：请求体为 `application/json`（除导出端点返回裸文本/文件外，所有响应亦为 JSON）。
- **监听地址**：默认 `127.0.0.1`，仅本机可达；容器 / 局域网需显式 `HOST=0.0.0.0`（务必同时配置 `SCAN_API_TOKEN` 与 `ALLOWED_ORIGINS`）。
- **端口**：默认 `4567`，`PORT=xxxx` 覆盖。
- **CORS**：仅放行白名单源（Vite 开发服 + 本机直连 + Tauri 同源），可通过 `ALLOWED_ORIGINS`（逗号分隔）覆盖；无 `Origin` 头（curl / 服务端 / Tauri webview）默认放行。

---

## 2. 认证（SCAN_API_TOKEN）

引擎支持**可选** API Token 纵深防御：设置环境变量 `SCAN_API_TOKEN` 后，除「完全只读的公开元数据」外的所有端点（**含扫描报告 / 导出 / SSE 实时流**）均需鉴权。

### 2.1 传递方式（二选一）

| 方式 | 示例 |
|------|------|
| 请求头 `x-api-token` | `x-api-token: <token>` |
| 请求头 `Authorization` | `Authorization: Bearer <token>` |

### 2.2 公开只读路径（无需 token）

| 路径（GET） | 说明 |
|------|------|
| `/health`、`/api/health` | 健康检查 |
| `/payloads`、`/api/payloads` | 只读 Payload 模板 |
| `/tampers`、`/api/tampers` | tamper 插件清单 |
| `/exploit/capabilities`、`/api/exploit/capabilities` | 利用能力清单 |
| `/sqlmap/status`、`/api/sqlmap/status` | sqlmap 可用性预检 |

### 2.3 报告 token 护栏（重要）

一旦设置了 `SCAN_API_TOKEN`，以下端点**必须携带 token**，否则返回 `401`：

- `GET /scan/:id/report`、`GET /scan/:id/report/export`
- `GET /sqlmap/:id/report`
- `GET /scan/:id/events`、`GET /sqlmap/:id/events`（SSE）
- 所有 `POST` 端点（start / stop / exploit/*）

> 未设置 `SCAN_API_TOKEN` 时以上护栏自动失效（保持本地开发便利），生产 / 局域网部署请务必设置。

---

## 3. 错误码

| code | 含义 |
|------|------|
| 0 | 成功 |
| 401 | 需要 API Token（仅当设置了 `SCAN_API_TOKEN`，且请求未携带） |
| 1001 | `INVALID_TARGET` 无效目标（URL 缺失 / 协议非 http/https） |
| 1002 | `UNSUPPORTED_METHOD` 不支持的请求方法 |
| 1003 | `INVALID_PARAM` 入参非法（JSON 非法 / 配置字段越界 / techniques 非法等） |
| 2001 | `SCAN_NOT_FOUND` 扫描不存在或已结束 |
| 2002 | `ENGINE_BUSY` 引擎忙（并发扫描达上限，默认 8） |
| 3001 | `HTTP_TIMEOUT` HTTP 请求超时 |
| 3002 | `HTTP_ERROR` HTTP 请求错误 |
| 4001 | `DETECT_FAILED` 检测失败 |
| 5001 | `EXTRACT_FAILED` 数据提取失败 |
| 6001 | `OOB_RECEIVER_START_FAILED` OOB 接收端启动失败 |
| 6002 | `OOB_DISABLED` OOB 未启用 / 接收端未启动 |
| 6003 | `TAMPER_INVALID_NAME` tamper 插件缺唯一 name |
| 6004 | `SECOND_ORDER_DISABLED` 二阶注入未开启却调用 |
| 6005 | `EXPLOIT_UNAUTHORIZED` 利用操作未声明 `authorized:true` |
| 9001 | `UNKNOWN` 服务器内部错误 / 未知错误 |

---

## 4. 端点清单

### 4.1 健康与元数据（公开只读）

#### `GET /health`

```bash
curl http://127.0.0.1:4567/api/health
```

```json
{ "code": 0, "data": { "status": "up", "version": "1.0.0" }, "message": "ok" }
```

#### `GET /payloads?dbms=&technique=`

返回只读 Payload 模板；`dbms` + `technique` 同时给出时返回对应模板数组，仅 `dbms` 返回该库全部技术模板，均不传返回全部（含 `fingerprint`）。

#### `GET /tampers`

```json
{ "code": 0, "data": [ { "name": "space2comment", "description": "…" } ], "message": "ok" }
```

#### `GET /exploit/capabilities`

```json
{
  "code": 0,
  "data": {
    "sqlShell": ["MySQL", "MariaDB", "PostgreSQL", "SQL Server", "Oracle", "SQLite"],
    "fileRead": ["MySQL", "MariaDB", "PostgreSQL", "SQL Server", "Oracle(需目录对象)"],
    "fileWrite": ["MySQL", "MariaDB", "PostgreSQL", "SQL Server"],
    "osShell": ["PostgreSQL(COPY PROGRAM)", "SQL Server(xp_cmdshell)", "MySQL(sys_eval UDF)"],
    "enabled": true
  },
  "message": "ok"
}
```

#### `GET /sqlmap/status`

```json
{ "code": 0, "data": { "available": true, "maxConcurrent": 2 }, "message": "ok" }
```

---

### 4.2 扫描（内置引擎）

#### `POST /scan/start`

启动一次扫描，返回 `{ scanId }`。入参兼容两种形态（均归一化）：

- 文档契约形态：`{ "target": { "url", "method", "bodyParams", "cookieParams", "headerParams" }, "config": {} }`
- 前端扁平形态：`{ "url", "method", "bodyParams", "cookieParams", "headerParams", "config": {} }`

```bash
curl -X POST http://127.0.0.1:4567/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "http://target/page?id=1",
    "method": "GET",
    "bodyParams": {},
    "cookieParams": {},
    "headerParams": {},
    "config": {
      "concurrency": 4,
      "timeoutMs": 10000,
      "retry": 2,
      "timeThresholdMs": 1500,
      "ratePerSec": 3,
      "enableExtract": false,
      "techniques": ["union", "error", "boolean", "time"],
      "proxy": null,
      "auth": { "basic": { "username": "", "password": "" }, "cookie": "", "headers": {} },
      "wafEvasion": { "randomUA": false, "jitterMs": 0, "obfuscate": false, "tamper": { "enabled": false, "plugins": [], "intensity": "medium" } }
    }
  }'
```

**直连模式（对标 sqlmap -d）**：不走 HTTP 请求，直接连数据库执行 SQL。适用于数据库直连场景（内网/本地数据库）。

```bash
curl -X POST http://127.0.0.1:4567/api/scan/start \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "direct",
    "connectionString": "sqlite:///tmp/test.db",
    "sqlTemplate": "SELECT * FROM users WHERE id={INJECT}",
    "config": {
      "level": 2,
      "risk": 2,
      "enableExtract": true
    }
  }'
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `mode` | `"direct"` | 直连模式标识（有 `db` 或 `connectionString` 时自动识别） |
| `connectionString` | string | 数据库连接串（支持 `mysql://` / `postgres://` / `mssql://` / `oracle://` / `sqlite://`） |
| `db` | object | 替代 `connectionString`：`{ connectionString, driverType, initSql }` |
| `sqlTemplate` | string | SQL 模板，含 `{INJECT}` 标记（引擎替换标记后执行） |
| `driverType` | string | 驱动类型：`memory`（零依赖自检）、`sqljs`/`sqlite`（真实 SQLite，需 sql.js）、`pglite`（真实 PostgreSQL WASM，无需 Docker，`npm install @electric-sql/pglite`）、`mysql`/`postgres`/`mssql`/`oracle`（需注册驱动） |

```json
{ "code": 0, "data": { "scanId": "abc123" }, "message": "ok" }
```

配置字段经白名单 + 边界 clamp 收敛（`concurrency` 1-10、`timeoutMs` 1000-60000、`retry` 0-5、`timeThresholdMs` 100-60000、`level` 1-5、`risk` 1-3、`crawlDepth` 0-3 等），未知字段忽略。

**进阶配置字段**（均已在白名单 `KNOWN_CFG_KEYS` 内，可选）：

| 字段 | 类型/范围 | 说明 |
|------|------|------|
| `level` | 1-5（默认 1） | 检测等级：payload 复杂度 / 边界探测强度 |
| `risk` | 1-3（默认 2） | 风险等级：1 仅 union/error/boolean；2 含 time/stacked/oob；3 额外 OR 变体 |
| `ratePerSec` | number（默认 30） | 请求限速（req/s），0=不限速；按 scanId 独立令牌桶 |
| `concurrency` | 1-10（默认 4） | 并发检测线程数 |
| `retry` | 0-5（默认 3） | 失败重试次数（含指数退避）。[P0-FIX 对标 sqlmap] 2→3；本表此前仍写 2 |
| `timeoutMs` | 1000-60000（默认 30000） | 单请求超时。[P0-FIX 对标 sqlmap] 10s→30s（慢目标上短超时会把正常响应判成失败，并压缩时间盲注判定窗口）；本表此前仍写 10000 |
| `prefix` / `suffix` | string，≤200 字符，默认空 | 注入点原值前 / payload 后拼接（对标 sqlmap `--prefix`/`--suffix`），用于闭合引号/括号 |
| `sessionFile` | 文件名或临时目录路径 | 显式会话文件（白名单校验，拒绝绝对路径/`..`）；下次传同名文件即续跑 |
| `sessionDefault` | bool（默认 false） | 自动落盘 `sqli-session-latest.json`，同 URL 扫描自动 resume（SSE 推 `point_skipped`） |
| `oob` | object | `{ enabled, callbackBase, httpPort(1-65535), timeoutMs(1000-60000), dnsOob(bool), dnsDomain(≤253), dnsPort(1-65535) }`；需 `techniques` 含 `oob` 且 `enabled=true` 才启动接收端（错误码 6001/6002）。`dnsOob=true` 且 `dnsDomain` 非空时，检测器在 HTTP 回调轮未命中后追加 **DNS 外带轮**（生成 `<token>.<dnsDomain>` 触发查询，对标 sqlmap `--dns-domain`）；DNS 端口/域名也可用环境变量 `OOB_DNS_PORT` / `OOB_DNS_DOMAIN` 兜底（REST 配置优先） |
| `crawlDepth` | 0-3（默认 0） | 站内链接爬取深度（对标 sqlmap `--crawl`） |
| `crawlForms` | bool（默认 false） | 解析页面表单生成 body 注入点 |
| `wafEvasion` | object | `{ randomUA, obfuscate, jitterMs(0-5000), tamper: { enabled, plugins[], intensity: low/medium/high } }`；tamper 链按数组顺序应用 |
| `skipStatic` | bool（默认 false） | 对标 sqlmap `--skip-static`：静态参数预筛选（同值去重 + 哨兵探测） |
| `prefilter` | bool（默认 true） | 参数预筛选（1-2 个廉价探测排除明显无注入点参数，省 50-75% 请求） |
| `autoDynamicBlock` | bool（默认 true） | 对标 sqlmap 动态内容感知：基线两两分块比对标记高频差异块为动态块，后续相似度比对自动排除 |
| `predictOutput` | bool（默认 true） | 对标 sqlmap `--predict-output`：同目标跨点复用常见值二分提取结果 |
| `matchString` | string，≤500 | 对标 sqlmap `--string`：真页面必含文本（锚点判定优先于相似度比对） |
| `notString` | string，≤500 | 对标 sqlmap `--not-string`：假页面必含文本 |
| `matchText` | bool | 对标 sqlmap `--text-only`：剥标签后纯文本不一致即信号 |
| `matchCode` | bool 或 `{true:100-599, false:100-599}` | 对标 sqlmap `--code`：真假状态码不同即信号 |
| `matchRegexp` | string，≤500 | 对标 sqlmap `--regexp`：真响应命中、假不命中即信号 |
| `trueRegexp` / `falseRegexp` | string，≤500 | 分别限定真/假侧需命中的正则 |
| `matchTitle` | bool | 对标 sqlmap `--titles`：真假 `<title>` 不同即信号 |
| `blindRobust` | object | 统计判定分支参数：`{enabled, booleanSamples(1-10), baselineSamples(1-20), timeConfidenceZ(0-5), minStableRatio(0-1), adaptive, concurrency(1-16)}`；详见 `defaults.js` |
| `secondOrder` | object | 二阶注入参数：`{enabled, triggerUrls[], cookieParams}` |
| `noSql` | object | 非 SQL 注入（NoSQL/GraphQL/SSTI）：`{enabled, kinds['nosql','graphql','ssti']}` |
| `extractConcurrency` | 1-16（默认 4） | 盲注二分提取并发度 |
| `dumpMaxRows` | 1-50000（默认 50000） | 全量拖库行数上限 |
| `dumpRowLimit` | 1-1000（默认 100） | 单次拖库行数（分页续拉） |
| `dumpConcurrency` | 1-16（默认 4） | 多表拖库并发度 |
| `dumpDatabaseConcurrency` | 1-16（默认 2） | 跨库拖库并发度 |
| `timeBlindSamples` | 3-10（默认 5） | 时间盲注采样次数 |
| `maxColumnsGuess` | 1-100（默认 50） | UNION 列数猜测上限（`defaults.js:104`；本表此前写 10） |
| `useRegistry` | bool（默认 false） | 启用声明式 payload 筛选，对标 sqlmap XML `<test>` 元素；`selectPayloads({ dbms, technique, level, risk, clause, boundary })` 从 672 条声明式条目中筛选匹配 payload |
| `timeBlindCalibrate` | bool（默认 false） | 启用时间盲注标定探针，自动测量目标响应延迟基线 |
| `timeBlindCalibrateMin` | 1-30（默认 1） | 时间盲注标定最小 sleep 秒数 |

> 注：`timeProbeSleepSec`/`timeExtractSleepSec` 等时间标定字段未在 REST 白名单内，仅能通过服务端 defaults 定制。

**注入点精确标记**：参数值末尾加 `*`（URL 查询 / 路径段 / body / cookie / header 均可），引擎仅测试被标记参数（对标 sqlmap `-p`），`*` 剥离后作为原始值。例如 `"id": "1*"`、`?id=1*`、`/users/1*/profile`。

**请求文件导入**：前端 TargetForm 提供「从请求文件导入」按钮，支持粘贴或上传 Burp/curl HTTP 请求文本，自动解析 URL、方法、请求头、请求体及 Cookie，无需手动填写；CLI 对应 `-r request.txt`。

#### `GET /scan/:id`

实时报告快照（扫描过程中）或完整报告（同 `/report` 结构）。

#### `GET /scan/:id/events`

SSE 实时进度流，事件结构 `{ type, scanId, ts, payload }`，事件类型见 [§6](#6-sse-事件类型)。

#### `POST /scan/:id/stop`

```json
{ "code": 0, "data": { "stopped": true }, "message": "ok" }
```

#### `POST /scan/:id/point/:pointId/retest`

单点重测：带新 config 只重跑指定注入点（调参验证省分钟级等待）。`pointId` 需来自同一份报告；
引擎按 `location:param` 锁定单点（跨扫描 pointId 不稳定），请求量从数百降到几十。

请求体（均可选，仅覆盖想调整的项）：

```json
{ "config": { "level": 3, "risk": 2, "techniques": ["boolean", "time"] } }
```

响应：

```json
{
  "code": 0,
  "data": {
    "scanId": "新扫描 ID（事件流/报告与普通扫描一致）",
    "point": { "id": "…", "location": "url", "param": "id", "encoding": null },
    "configApplied": { "level": 3, "risk": 2, "tamper": null, "techniques": ["boolean", "time"] }
  },
  "message": "ok"
}
```

错误码：`1002` 基线扫描不存在 / `1002` 注入点不存在（pointId 需来自同一报告）/ `1002` 基线缺目标信息；重测自动剥离子项 `extractScope`（避免重复枚举与误触发写入），scope 与 SSRF 校验与全扫一致。

#### `GET /scan/:id/report`

完整报告（`ReportModel`）：

```json
{
  "code": 0,
  "data": {
    "scanId": "abc123",
    "target": { "baseUrl": "…", "method": "GET", "bodyParams": {}, "cookieParams": {}, "headerParams": {}, "config": {} },
    "startedAt": "…", "finishedAt": "…",
    "dbms": "MySQL",
    "points": [ { "id": "p1", "location": "url", "param": "id", "originalValue": "1", "confirmed": true, "technique": "union", "dbms": "MySQL" } ],
    "vulns": [ { "id": "v1", "pointId": "p1", "technique": "union", "dbms": "MySQL", "riskLevel": "High", "payloads": ["…"], "description": "…", "evidence": "…", "trace": null } ],
    "data": { "databases": [], "tables": {}, "columns": {}, "rows": {} },
    "riskLevel": "High",
    "summary": { "totalPoints": 1, "totalVulns": 1, "byTechnique": {}, "byRisk": {} }
  },
  "message": "ok"
}
```

#### `GET /scan/:id/report/export?format=json|html|csv|markdown|db-json`

导出报告，返回**裸内容**（非 `{code,data,message}` 包装），`Content-Disposition` 附带文件名。

| format | 说明 |
|------|------|
| `json` | 完整报告 JSON |
| `html` | 内联样式单页 HTML |
| `csv` | 漏洞表 + 拖库数据（BOM 头，Excel 不乱码） |
| `markdown` | Markdown 报告（适合贴工单） |
| `db-json` | 仅拖库数据部分（`report.data`） |

#### `POST /scan/:id/report/ai`

调用 AI 生成漏洞报告描述与修复建议。

```bash
curl -X POST http://127.0.0.1:4567/api/scan/abc123/report/ai \
  -H 'Content-Type: application/json' \
  -d '{ "keyIndex": 0, "modelIndex": 0 }'
```

| 参数 | 类型 | 说明 |
|------|------|------|
| `keyIndex` | 0-2 | 预置 API key 索引（默认 0） |
| `modelIndex` | 0-2 | 模型索引：0=deepseek-v4-flash, 1=sensenova-6.8-flash-lite, 2=glm-5.2（默认 0） |

```json
{ "code": 0, "data": { "success": true, "model": "deepseek-v4-flash", "content": "…", "usage": { "promptTokens": 500, "completionTokens": 200 } }, "message": "ok" }
```

可通过环境变量覆盖默认选择：`AI_REPORT_KEY_INDEX`（默认 0）、`AI_REPORT_MODEL_INDEX`（默认 0）、`AI_REPORT_TIMEOUT_MS`（默认 30000）。

#### `GET /scan/:id/report/ai/configs`

返回所有 9 种 key+model 组合的配置预览（3 key × 3 model）。

```json
{ "code": 0, "data": [ { "keyIndex": 0, "modelIndex": 0, "label": "Key#0 × deepseek-v4-flash", "model": "deepseek-v4-flash" }, … ], "message": "ok" }
```

---

### 4.3 扫描（sqlmap 高级模式）

#### `POST /sqlmap/start`

```json
{
  "target": { "url": "http://target/page?id=1", "method": "GET", "data": "id=1", "cookie": "…", "headers": "X-A: 1\nX-B: 2" },
  "config": {
    "sqlmap": { "level": 1, "risk": 1, "techniques": ["B","E","U","T"], "tamper": [], "dbms": null, "threads": 1, "dump": false, "osShell": false, "fileRead": null, "proxy": null, "timeoutMs": 30000, "retry": 3, "randomUA": false, "flushSession": false, "freshQueries": false, "unionCols": null }
  }
}
```

返回 `{ "code": 0, "data": { "scanId": "sq1" }, "message": "ok" }`。参数以数组形式 spawn 传给 sqlmap（防注入）。
新增参数：
- `flushSession` (bool)：清空 sqlmap 会话缓存重新扫描（`--flush-session`）
- `freshQueries` (bool)：绕过查询结果缓存，每次重新执行 SQL（`--fresh-queries`）
- `unionCols` (string)：限定 UNION 探测列数范围，如 `"1-15"`（`--union-cols`）
- `unionChar` (string)：UNION 探测使用的字符，如 `"null"`（`--union-char`）
- `unionFrom` (string)：UNION 查询 FROM 子句，如 `"dual"`（`--union-from`）
- `smart` (bool)：仅当 payload 在响应中产生显著变化时才深入检测（`--smart`）
- `noCast` (bool)：禁用 CAST 提取（`--no-cast`）
- `hex` (bool)：使用 hex 转换提取数据（`--hex`）
- `noEscape` (bool)：禁用字符串转义（`--no-escape`）

#### `GET /sqlmap/:id/events` / `POST /sqlmap/:id/stop`

与内置引擎同一套 SSE / 停止契约。

#### `GET /sqlmap/:id/report`

```json
{
  "code": 0,
  "data": {
    "status": "completed",
    "logs": [ { "level": "success", "text": "…", "ts": "…" } ],
    "vulns": [ { "param": "id", "technique": "U", "raw": "…" } ]
  },
  "message": "ok"
}
```

---

### 4.4 利用模块（破坏性，需 `authorized: true`）

所有 `POST /exploit/*` 端点强制校验 `authorized === true`，否则返回 `code: 6005`（`EXPLOIT_UNAUTHORIZED`）。

#### `POST /exploit/sql`

```json
{
  "target": { "url": "…", "method": "GET" },
  "point": { "originalValue": "1" },
  "dbms": "MySQL",
  "authorized": true,
  "sql": "SELECT 1"
}
```

#### `POST /exploit/file-read` / `POST /exploit/file-write` / `POST /exploit/os-shell`

- `file-read`：额外字段 `path`。
- `file-write`：额外字段 `content`、`remotePath`。
- `os-shell`：额外字段 `cmd`。

---

## 5. 扫描状态机

`pending → running → completed | stopped | error`。

并发上限默认 `8`（`MAX_SCAN_API_CONCURRENT` 覆盖）；扫描进入终态（completed/stopped/error）自动释放并发槽位。

---

## 6. SSE 事件类型

| 事件 | 说明 | payload 摘要 |
|------|------|------|
| `scan_started` | 扫描开始 | `{ scanId, engine?, target? }` |
| `point_discovered` | 发现注入点 | `{ point }` |
| `point_testing` | 正在测试注入点 | `{ pointId, technique }` |
| `point_skipped` | resume 跳过已完成点 | `{ pointId, reason }` |
| `detection_found` | 检测命中 | `{ pointId, technique, result }` |
| `extraction_progress` | 拖库进度 | `{ db?, table?, rows }` |
| `scan_completed` | 扫描完成 | `{ scanId, vulnCount?, logCount? }` |
| `scan_stopped` | 已停止 | `{ scanId }` |
| `scan_error` | 扫描失败 | `{ scanId, message }` |
| `sqlmap_log` | sqlmap 原始输出行 | `{ level, text }` |
| `sqlmap_vuln` | sqlmap 确认注入点 | `{ param, technique, raw }` |
| `waf_detected` | 识别到 WAF | `{ vendors: [], suggestions: [] }` |
