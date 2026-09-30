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
{
  "code": 0,
  "data": {
    "status": "up",
    "version": "1.1.0",
    "versionSource": "package.json(root)",
    "node": "24.18.0",
    "authEnabled": true,
    "exploitEnabled": false,
    "ratePerSec": 10
  },
  "message": "ok"
}
```

`version` 与 `package.json` 同源（构建期/启动期解析，不再写死字面量）。
字段口径：只放布尔与计数，不放绝对路径/环境变量原文 —— 这条端点是公开只读的。

#### `GET /scans?limit=50`

服务端历史清单（**需要 token**：清单含目标 URL 与结论）。数据来自两处合并，同名以内存为准：

- 台账 `data/ledger/`（每次 API 扫描完成/停止时自动登记，`SCAN_LEDGER=0` 关闭）
- 引擎内存里在途/刚结束的扫描

```json
{
  "code": 0,
  "data": {
    "total": 2,
    "scans": [
      { "scanId": "…", "target": "http://…/item?id=1", "startedAt": "…", "finishedAt": "…",
        "points": 1, "vulns": 1, "dbms": "MySQL", "verdict": "vulnerability_detected",
        "status": "completed", "source": "ledger" }
    ],
    "ledgerRoot": "D:/…/server/data/ledger"
  },
  "message": "ok"
}
```

`source` 区分 `live`（引擎内存）与 `ledger`（磁盘台账）。

#### `GET /payloads?dbms=&technique=`

返回只读 Payload 模板；`dbms` + `technique` 同时给出时返回对应模板数组，仅 `dbms` 返回该库全部技术模板，均不传返回全部（含 `fingerprint`）。

#### `GET /tampers`

```json
{ "code": 0, "data": [ { "name": "space2comment", "description": "…" } ], "message": "ok" }
```

#### `GET /exploit/capabilities`

**清单由服务端的接管能力表（`Exploiter` 的 `TAKEOVER_CAPS`）推导**，不再是手抄数组
（2026-09-29 起）—— 手抄一份就会出现「清单说有、动作说没有」，而接口自己正是那份清单，
这类漂移在接口层永远查不出来。

```json
{
  "code": 0,
  "data": {
    "sqlShell": ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite", "ClickHouse"],
    "fileRead": ["MySQL", "PostgreSQL", "SQL Server", "Oracle"],
    "fileWrite": ["MySQL", "PostgreSQL", "SQL Server"],
    "osShell": ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite"],
    "matrix": {
      "MySQL": {
        "fileWrite": { "supported": true, "risk": "HIGH", "requiredPriv": "FILE 权限 + secure_file_priv 放行（可写 webshell）" }
      }
    },
    "enabled": true
  },
  "message": "ok"
}
```

- 正向字段（能力 → 支持的 DBMS 列表）只收 `supported: true` 的条目；
- `matrix` 是完整能力表（DBMS → 各能力的 `supported` / `risk` / `requiredPriv` / `note`），
  调用方可据此在 UI 上给出「这条能力要什么权限、有多高危」；
- `enabled` 是 `EXPLOIT_ENABLED` 开关的**当前值**（每次请求现读）。

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

> 注：`timeProbeSleepSec` / `timeExtractSleepSec` / `timeBlindSleepSec` 已在 REST 白名单内（2026-09-24 接入），
> 可直接在 `config` 里传；此前"只能改服务端 defaults"的说法已过期。

**授权范围（`config.scope`）**：渗透第一红线，非空即硬拦（不提供"只告警"模式）。支持的条目写法：
`example.com`（含子域）· `=example.com`（仅裸域）· `*.example.com` / `.example.com` · `10.0.0.0/8`（IPv4 CIDR）·
`2001:db8::/32` · `https://a.example.com/portal`（主机 + 路径前缀）· **`127.0.0.1:8140`（主机 + 端口，端口必须相等）**。
带端口的写法是描述本地/内网靶站的自然形式，此前会被整串当主机名而永不匹配。
范围之外 → `code 1004` 且**不发出任何请求**；目标 302 出圈同样被逐跳拦截。

SSRF 与 scope 是两条独立判据：`SSRF_ALLOW_PRIVATE=1`（打内网靶站时用）只豁免回环/私网，
`0.0.0.0/8`、`169.254.0.0/16`（云元数据）、组播/保留段属硬底线，任何 `ALLOW_PRIVATE` 部署都不放行；
确需点名放行某段用 `SSRF_ALLOW_CIDRS`。

**枚举/拖库（`config.extractScope`）**：对标 sqlmap `--dbs/--tables/--columns/--dump/--current-db/…`
（REST 侧 2026-09-23 才收进白名单）。形状：`{ mode, dbs?, tables?, cols?, keyword?, excludeSysdbs? }`，
`mode` ∈ `dbs|tables|columns|dump|dumpAll|search|schema|users|passwords|currentDb|currentUser|hostname|isDba|privileges|roles|count|commonTables|commonColumns`。
传了合法 `extractScope` 即隐含打开 `enableExtract`（与 CLI `enableExtract: args.dump || enumActive` 同一口径）——
否则接口会回 200 + 空 `report.data`，把"没枚举"说成"库里没东西"。

**参数级别与"给了没测"**：`cookieParams` 需 `level≥2`、`headerParams` 需 `level≥3`（或 `testHeaders:true`）
才会被解析成注入点。低 level 下这些参数**不会**被测试，报告 `summary.constraints` 里必须出现
"cookieParams 未被测试（收到 N 个…）"这类说明 —— 静默跳过比报错更贵，因为它产出的是一个看起来正常的阴性报告。

#### `GET /scan/:id`

**请求文件导入**：前端 TargetForm 提供「从请求文件导入」按钮，支持粘贴或上传 Burp/curl HTTP 请求文本，自动解析 URL、方法、请求头、请求体及 Cookie，无需手动填写；CLI 对应 `-r request.txt`。

#### `GET /scan/:id`

实时报告快照 + **运行态**。运行态必须与报告同源可见：`ScanManager` 的状态（running/paused/…）
记在扫描条目上而不在报告里，此前这条端点只回报告，于是"在不在跑/有没有暂停"在 HTTP 层
无法观测（只能靠 SSE 长连接），`pause` 的返回就成了自证。

```json
{
  "code": 0,
  "data": {
    "scanId": "abc123",
    "status": "running",
    "source": "live",
    "state": { "scanId": "abc123", "status": "running", "paused": false, "retired": false,
               "startedAt": "…", "finishedAt": null, "points": 1, "vulns": 1, "dbms": "MySQL", "elapsedMs": 4200 },
    "target": {}, "points": [], "vulns": [], "data": null, "riskLevel": "…", "summary": {}
  },
  "message": "ok"
}
```

上下文被回收（完成后 `SCAN_RETIRE_TTL_MS`，默认 30s）之后回读台账，此时 `source="ledger"`、
`state.retired=true`。

#### `GET /scan/:id/events`

SSE 实时进度流，事件结构 `{ type, scanId, ts, payload, seq }`（帧内含 `id:` 行），事件类型见 [§6](#6-sse-事件类型)。
断线重连带 `Last-Event-ID` 时回放游标之后缓冲的事件；终态事件（completed/error/stopped）后服务端主动收尾。

#### `POST /scan/:id/stop`

```json
{ "code": 0, "data": { "stopped": true, "status": "stopped" }, "message": "ok" }
```

三种情形可区分（与 pause/resume 同一口径）：未知/已回收 → `code 2001`；
已是终态（completed/error/stopped）→ `code 0` + `{ stopped:false, alreadyFinished:true, status }`，
**不会**把正常跑完的扫描改写成"被停止"。

#### `POST /scan/:id/pause` / `POST /scan/:id/resume`

暂停在**请求边界**生效：暂停期间不再向目标发包。此前它只在「点边界」生效，而一个点是几十上百个
包 —— 点了暂停流量照发，接口却回成功，这就是「自证」。

```json
{ "code": 0, "data": { "paused": true }, "message": "ok" }
```

- 未知 id / 上下文已回收 → `code 2001`（`SCAN_NOT_FOUND`）；
- `pause` 打在不在运行中的扫描上 → `code 2001` + `{ "paused": false }`（"扫描不在运行中，无法暂停"）；
- `resume` 打在未暂停的扫描上 → `code 2001` + `{ "resumed": false }`（"扫描未处于暂停状态"）。

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

完整报告（`ReportModel`），附 `source`（`live` 内存 / `ledger` 台账回读）。
扫描上下文完成后仅保留 `SCAN_RETIRE_TTL_MS`（默认 30s），之后由台账兜底 —— 历史报告的
可读性不依赖浏览器缓存。

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

#### `GET /scan/:id/report/export?format=json|html|csv|markdown|md|db-json|sarif`

导出报告，返回**裸内容**（非 `{code,data,message}` 包装），`Content-Disposition` 附带文件名。
历史扫描（内存已回收）同样可导出：读台账里的原始报告，走同一条渲染路径，不另写一套格式。

| format | 说明 |
|------|------|
| `json` | 完整报告 JSON（`target` 脱敏形态） |
| `html` | 内联样式单页 HTML |
| `csv` | 漏洞表 + 拖库数据（BOM 头，Excel 不乱码；公式前缀转义） |
| `markdown` / `md` | Markdown 报告（适合贴工单） |
| `db-json` | 仅拖库数据部分（`report.data`） |
| `sarif` | SARIF 2.1.0（供代码扫描平台/GHAS 消费） |

失败形态（这是**文件下载**端点，不能用 200 表达失败，否则前端 `res.ok` 会把错误体存成报告文件）：

| 情形 | 响应 |
|------|------|
| 扫描不存在/未落台账 | `404` `{code:2001}`，且**不带** `Content-Disposition` |
| `format` 不在白名单 | `400` `{code:1002}` |
| `db-json` 而本次没有枚举/拖库数据 | `400` + 指明下一步（带 `config.extractScope` 或 `enableExtract` 重扫）；不再回 200 + `"null"` 的 4 字节空附件 |

#### `GET /scan/:id/diff?base=<scanId>`

与**基线扫描**对比（复测场景：同一目标前后两次扫描差了什么）。`base` 必填 —— 缺失时回
`code 1` 并指明正确写法 `/api/scan/<id>/diff?base=<scanId>`；任一份报告不存在 → `code 2001`
（消息区分"当前扫描不存在"与"基线扫描不存在"）。

```json
{
  "code": 0,
  "data": {
    "base": { "id": "…", "finishedAt": "…", "vulnCount": 3, "riskLevel": "high" },
    "current": { "id": "…", "finishedAt": "…", "vulnCount": 1, "riskLevel": "medium" },
    "fixed": [], "added": [], "remaining": []
  },
  "message": "ok"
}
```

对比单位不是 `vuln.id`（跨扫描不稳定），而是**点位指纹**（`location:param` + 技术通道）：
`fixed` = 基线有、这次没有；`added` = 这次新出现；`remaining` = 两边都有。

#### `POST /scan/:id/report/ai`

调用 AI 生成漏洞报告描述与修复建议。**不接受任何请求参数**——key/model 组合仅由服务端
环境变量控制（防他人通过 API 选择不同 key 烧配额）。限速：每 IP 每分钟 3 次（429）。

```bash
curl -X POST http://127.0.0.1:4567/api/scan/abc123/report/ai
```

环境变量（真实取数源 `server/src/services/ReportAI.js`）：`AI_REPORT_API_BASE`（OpenAI
兼容 endpoint，数据外发 opt-in——未设置时返回 409，不会静默外发）+ `AI_REPORT_KEY_1..3`
（至少 1 个即启用，失败/429 自动同角色降级再跨角色降级）。角色流水线固定为
analyst→writer→reviewer；超时由路由硬编码 120s（`reportAiRoutes.js`）。

```json
{ "code": 0, "data": { "success": true, "model": "deepseek-v4-flash→glm-5.2→sensenova-6.8-flash-lite", "content": "…", "reviewNote": "✅ 已经过安全审阅角色校验", "pipeline": "analyst→writer→reviewer", "usage": null }, "message": "ok" }
```

> 命中报告缓存（TTL 内同指纹复扫）时返回体额外带 `"cached": true`。

#### `GET /scan/:id/report/ai/configs`

返回 3 个角色的固定配置预览（role→model 映射在服务端写死）。

```json
{ "code": 0, "data": [ { "role": "analyst", "model": "deepseek-v4-flash", "desc": "漏洞分析+风险评估", "label": "deepseek-v4-flash (漏洞分析+风险评估)" }, … ], "message": "ok" }
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

### 4.4 利用模块（破坏性，需 `EXPLOIT_ENABLED=1` + `authorized: true` + 声明授权范围）

四条动作端点（`/exploit/sql`、`/exploit/file-read`、`/exploit/file-write`、`/exploit/os-shell`）共用一套门槛：

1. 服务端 `EXPLOIT_ENABLED=1`（默认关闭；**每次请求现读**，改 `.env` 后无需猜是否生效）；
2. 请求体 `authorized: true`（前端勾选语义，仅作审计，安全边界是 ①+ token）；
3. **声明授权范围**（`scope` 或 `scanId` 至少其一，否则 `code: 1007`）——
   与 `SCOPE_VIOLATION(1004)` 是两件事：`1004` = 范围给了但目标越界，`1007` = 根本没给范围；
4. 独立限速桶（默认 5 req/s，`EXPLOIT_RATE_PER_SEC` 可调）→ 超限回 `code: 4290`；
5. 目标过 SSRF；给了 `scope` 时按 `scope` 校验，给了 `scanId` 时沿用该次扫描登记的范围。

**写类端点额外加严**（`/exploit/file-write`、`/exploit/os-shell`，会不可逆地修改目标状态）：

6. 必须提供**显式 `scope`** —— 不接受仅凭 `scanId` 间接推断范围（`scanId` 可能已回收、也可能指向另一台主机），否则 `1007`；
7. 必须声明 `confirmDestructive: true`，否则 `6005`（与 `config.productionMode` / `confirmDestructive`、
   `secondOrder.allowWrites` 同一口径）。

> 读类端点（`sql` / `file-read`）只需第 1–5 条；`confirmDestructive` 对它们无意义，
> 传了也不会改变行为。`/exploit/capabilities` 是公开只读端点，不受上述门槛约束。

#### 形态 A：引用扫描结果（推荐）

```json
{ "scanId": "abc123", "pointId": "p1", "authorized": true, "sql": "SELECT VERSION()" }
```

> `scanId` 形态可省 `scope`（沿用该次扫描登记的范围）——但**写类端点除外**：
> `file-write` / `os-shell` 必须显式给 `scope` + `confirmDestructive: true`。

服务端从该扫描上下文解析 `target` / `point`（含 `boundary`、`echoCols`、`encoding`）与定库结果，
并**沿用扫描作用域的 HttpClient**（cookieJar / `auth` / CSRF / safeUrl / 限速桶）——
需要登录态的目标，利用请求不会再被 401 弹回。响应额外带 `resolvedFrom`，说明实际用了哪个点位：

```json
{
  "code": 0,
  "data": { "ok": true, "type": "select", "delivered": true, "value": "8.0.28",
            "resolvedFrom": { "scanId": "abc123", "pointId": "p1", "location": "header",
                              "param": "x-section", "dbms": "MySQL", "sessionInherited": true } },
  "message": "ok"
}
```

扫描上下文已被回收时回 `code 2001` 并提示改用形态 B 或重扫（不静默降级成"猜一个点位"）。

#### 形态 B：手工给 target + point

```json
{
  "target": { "url": "…", "method": "GET" },
  "point": { "originalValue": "1", "location": "url", "param": "id" },
  "dbms": "MySQL",
  "authorized": true,
  "scope": ["target.example.com"],
  "sql": "SELECT 1"
}
```

手工形态**必须**带 `scope`（没有扫描上下文可沿用），否则回 `code: 1007`。
`point.location` / `point.param` 必填。⚠ 手工形态的 `location` 只能是调用方自己确定的一项，
body/cookie/header 点位与编码点位建议走形态 A，否则等于让用户手抄报告里已有的字段。

#### 结果口径

- `sql-shell`：SELECT 类走标量提取。**`ok:true` 必须带回显值**；投递成功但取不到值时回
  `ok:false` + `delivered:true` + 原因（无回显列 / UNION 打不进该上下文 / 被 WAF 半拦），
  不再用 `ok:true, value:null` 这种自相矛盾的形态。
- `file-read` / `file-write`：受目标 `secure_file_priv` 约束；写文件回读校验失败即 `verified:false`。
- `os-shell`：MySQL 需 `sys_eval` UDF；能力不存在时如实失败并给原因（不是假成功）。

#### `POST /exploit/sql`

任意 SQL 执行。入参形态与其它利用端点一致（形态 A：`scanId` + `pointId`；形态 B：手工
`target` + `point` + `dbms`），额外字段 `sql`（上限 200000 字符）。

```json
{ "code": 0, "data": { "ok": true, "value": "8.0.33", "delivered": true }, "message": "ok" }
```

SELECT 类走标量提取：`value` 就是取回的值；语句投递成功但取不到值时回 `ok:false` +
`delivered:true` + 原因（见上节「结果口径」）。

#### `POST /exploit/file-read` / `POST /exploit/file-write` / `POST /exploit/os-shell`

- `file-read`：额外字段 `path`。
- `file-write`：额外字段 `content`、`remotePath`（≤1MB）。
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
