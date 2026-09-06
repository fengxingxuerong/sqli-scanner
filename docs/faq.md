# sqli-scanner 常见问题（FAQ）

> 本文覆盖使用与部署中的高频问题。部署相关问题（Node 版本、生产部署、桌面打包）详见 [deploy.md](./deploy.md)；API 契约详见 [api.md](./api.md)；操作手册详见 [user-guide.md](./user-guide.md)。

---

## 一、错误码速查表

引擎统一返回 `{ code, data, message }`，`code !== 0` 即业务错误（HTTP 状态码恒为 200，鉴权失败例外返回 HTTP 401）。全集如下（与 `server/src/core/errors.js` 保持同步）：

| code | 错误名 | 含义 | 常见处理 |
|------|--------|------|------|
| 0 | OK | 成功 | — |
| 401 | — | 需 API Token（仅当设置了 `SCAN_API_TOKEN` 且请求未携带） | 请求头加 `x-api-token` 或 `Authorization: Bearer <token>` |
| 1001 | INVALID_TARGET | 无效目标（URL 缺失 / 协议非 http/https） | 检查 URL 格式 |
| 1002 | UNSUPPORTED_METHOD | 不支持的请求方法 | 仅支持 GET/POST/PUT/PATCH/DELETE |
| 1003 | INVALID_PARAM | 入参非法（JSON 非法 / 配置越界 / techniques 非法 / sessionFile 路径逃逸等） | 对照 [api.md](./api.md) 的入参契约 |
| 2001 | SCAN_NOT_FOUND | 扫描不存在或已结束 | 扫描有生命周期，完成后会话被回收，重扫即可 |
| 2002 | ENGINE_BUSY | 引擎忙（并发扫描达上限，默认 8） | 稍后重试，或设环境变量 `MAX_SCAN_API_CONCURRENT` 提高 |
| 3001 | HTTP_TIMEOUT | HTTP 请求超时 | 见 [§四](#四目标不可达超时怎么排查) |
| 3002 | HTTP_ERROR | HTTP 请求错误（连接拒绝 / 5xx / SSRF 拦截等） | 见 [§四](#四目标不可达超时怎么排查)、[§五](#五内网回环目标被拒绝ssrf-防护) |
| 4001 | DETECT_FAILED | 检测失败 | 看 `message` 与日志（`server/logs/`）定位具体检测器 |
| 5001 | EXTRACT_FAILED | 数据提取失败 | 多为拖库中途目标报错/被拦，重扫或降低并发 |
| 6001 | OOB_RECEIVER_START_FAILED | OOB 接收端启动失败 | 检查端口占用（默认 HTTP 8899 / DNS 53），见 [§七](#七oob-带外检测怎么配) |
| 6002 | OOB_DISABLED | OOB 未启用 / 接收端未启动 | 需同时满足：`techniques` 含 `oob` 且 `config.oob.enabled=true` |
| 6003 | TAMPER_INVALID_NAME | tamper 插件缺唯一 name | 自定义插件须有唯一 `name` 字段 |
| 6004 | SECOND_ORDER_DISABLED | 二阶注入未开启却调用检测器 | `config.secondOrder.enabled` 置 true |
| 6005 | EXPLOIT_UNAUTHORIZED | 利用操作未声明 `authorized:true` | 前端勾选授权声明，且服务端需 `EXPLOIT_ENABLED=1` |
| 9001 | UNKNOWN | 服务器内部错误 / 未知错误 | 提交 issue 时附上 `server/logs/` 日志 |

---

## 二、sqlmap 模式提示「未找到 sqlmap 脚本」怎么办

后端按以下顺序定位 sqlmap（见 `server/src/engines/sqlmapBridge.js`）：

1. 环境变量 `SQLMAP_PATH`（指向 `sqlmap.py` 的完整路径）；
2. 都没有则回退 `server/tools/sqlmap/sqlmap.py`。

处理方式（二选一）：

```bash
# 方式一：设置环境变量（推荐）
# Windows (Git Bash / PowerShell)
export SQLMAP_PATH=/c/tools/sqlmap/sqlmap.py     # Bash
$env:SQLMAP_PATH="C:\tools\sqlmap\sqlmap.py"     # PowerShell
# Linux / macOS
export SQLMAP_PATH=/opt/sqlmap/sqlmap.py

# 方式二：克隆到约定目录
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git server/tools/sqlmap
```

注意：

- 解释器默认用 `python3`（Windows 上若无此命令，设 `PYTHON_PATH=python` 或 `SQLMAP_PYTHON` 指向可用解释器）。
- 可用 `GET /api/sqlmap/status` 预检可用性（`available/script/python` 字段）。

---

## 三、扫描很慢 / 想更礼貌地扫描

| 手段 | 配置项 | 说明 |
|------|--------|------|
| 请求限速 | `config.ratePerSec`（令牌桶） | 前端默认 5 req/s；调小可显著降载。越低越礼貌、越慢 |
| 请求间抖动 | `config.wafEvasion.jitterMs` | 请求间随机延时（毫秒），0 = 不延时；设置后可打散固定节奏（对 WAF/风控更友好） |
| 降并发 | `config.concurrency`（1-10） | 并发越高对目标压力越大 |
| 降低检测强度 | `config.level`（1-5） | level 越高 payload 越多越慢 |
| 保守风险档 | `config.risk`（1-3） | risk 1 只跑 union/error/boolean，无写请求与长时间等待 |
| 关拖库 | `config.enableExtract=false` | 提取阶段请求数远大于检测阶段 |
| 减少重试 | `config.retry`（0-5） | 目标不稳定时重试会放大请求量 |

> 引擎服务端默认 `ratePerSec=30`（吞吐由网络决定），礼貌扫描请在前端「高级设置 → 请求控制」里显式调低。

---

## 四、目标不可达 / 超时怎么排查

1. **确认目标本身可达**：`curl -I http://target/page` 先手动验证（注意目标是否只允许特定 UA / 是否有认证）。
2. **超时**：`HTTP_TIMEOUT (3001)` 时调大 `config.timeoutMs`（合法范围 1000-60000 ms，默认 10000）。慢目标/高延迟链路建议 20000-30000。
3. **重试**：`config.retry`（0-5）可对瞬时故障重试。
4. **代理**：目标在受限网络时配 `config.proxy`，支持 `http://`、`https://`、`socks5://host:port`。
5. **认证**：目标需要登录态时配 `config.auth`（Basic / Cookie / 自定义 Header），否则拿到的是登录页，所有判定都会失真。
6. **超时上限**：CLI 模式还有整体等待上限 `--timeout`（默认 30000 ms）。
7. **响应体过大**：超过 5MB 会被截断/拒绝（`SSRF_MAX_BODY_MB` 可覆盖）。

---

## 五、内网 / 回环目标被拒绝（SSRF 防护）

引擎对出口请求做了分层 SSRF 防护（见 `server/src/core/httpClient.js`）：

| 层级 | 规则 |
|------|------|
| 基础层（无条件拒绝） | `0.0.0.0/8`、链路本地 `169.254.0.0/16`（含云元数据 169.254.169.254）、组播/保留/文档段 |
| 严格层 | 回环 `127.0.0.0/8`、`::1`、私网 `10/8`、`172.16/12`、`192.168/16`、CGNAT、ULA。当 `SSRF_STRICT=1` 或 `HOST` 被改成非 `127.0.0.1/localhost`（如 Docker 里 `HOST=0.0.0.0`）时自动启用 |
| 显式放行（优先级最高） | `SSRF_ALLOW_PRIVATE=1` 完全放行；`SSRF_ALLOW_CIDRS=192.168.1.0/24,10.0.0.0/8` 逐段放行 |

常见场景：

```bash
# 本地起 mock 目标（127.0.0.1）做测试
SSRF_ALLOW_PRIVATE=1 npm run server

# 授权内网目标网段
SSRF_ALLOW_CIDRS=192.168.10.0/24 npm run server
```

> 重定向同样受控：引擎不自动跟随 302，而是逐跳重新校验目标 IP，防跳转进内网。

---

## 六、误报 / 漏报怎么调

**误报（报了实际不存在）**：

1. **统计判定**：布尔/时间盲注默认走统计判定（`blindRobust`，默认开启），按基线噪声自适应调整门槛，能压住大部分动态内容（广告/时间戳/随机推荐）抖动引起的误报；仍误报时看漏洞详情的时间线（基线采样、真假对、z 值）确认差异是否真实。
2. **锚点判定**：引擎支持真假页锚点 `matchString`（真页面必含文本）/ `notString`（假页面必含文本，对标 sqlmap `--string` / `--not-string`），配置后优先于相似度比对。注意：该字段当前未开放 REST 透传，需在服务端 `server/src/config/defaults.js` 定制后重启引擎生效。
3. **时间盲注抖动**：目标响应本身抖动大时，调大 `timeThresholdMs`（默认 1500 ms）。
4. **降 level**：`level` 调回 1，减少边界探测向量。
5. **人工复核**：报告漏洞详情里的「证据（Evidence）」与「请求报文」可直接复现验证。

**漏报（存在却没测出）**：

1. 升 `level`（1→3+，payload 更全）、升 `risk`（3 含 OR 变体布尔测试，注意破坏性）。
2. 需要 payload 闭合的场景配 `config.prefix` / `config.suffix`（对标 sqlmap `--prefix` / `--suffix`）。
3. 无回显盲注考虑 OOB（见 [§七](#七oob-带外检测怎么配)）。
4. 目标有 WAF 时配 tamper（见 [§八](#八开了-tamper-反而检测不到了怎么排查)）。

---

## 七、OOB 带外检测怎么配

OOB（带外注入）用于**无回显盲注**兜底，默认关闭。启用需同时满足两个条件：

```jsonc
// POST /api/scan/start 的 config 片段（REST 仅透传这 4 个 oob 字段）
{
  "techniques": ["union", "error", "boolean", "time", "oob"],  // ① 勾选 oob
  "oob": {
    "enabled": true,                 // ② 显式开启接收端
    "callbackBase": "1.2.3.4:8899",  // 接收端对目标可达的地址（检测器用它拼回调 URL）
    "httpPort": 8899,
    "timeoutMs": 5000
  }
}
```

接收端是 **HTTP + DNS 双通道**，一次启动同时拉起两个监听：

| 通道 | 默认 | 说明 |
|------|------|------|
| HTTP | 端口 8899 | 检测器自动生成 `http://<callbackBase>/oob/<token>` 回调并等待回连，命中即确认注入 |
| DNS | UDP 53（需 root/管理员） | 任何到达监听的 A/AAAA 查询，其**首个子域标签**会登记为 token，与 HTTP 回连共用同一判定池；启动失败（端口占用/无权限）自动降级为仅 HTTP，不阻断扫描 |

**DNS 外带轮**（对标 sqlmap `--dns-domain`）：`config.oob.dnsOob=true` 且 `dnsDomain` 非空时，检测器在 HTTP 回调轮未命中后，追加一轮 DNS 触发 payload——token 作为子域名标签拼成 `<token>.<dnsDomain>`，目标执行 `LOAD_FILE(UNC)` / `xp_dirtree` / `UTL_INADDR.GET_HOST_ADDRESS` 等原语时发起 DNS 查询被接收端捕获。适用于无 HTTP 出站、仅 DNS 出站的受限目标。支持库：MySQL/MariaDB/TiDB/SQL Server/Oracle/DM8（PG/SQLite/ClickHouse 无纯 DNS 原语不投放）。

DNS 监听的端口/域名可直接走 REST 配置（`config.oob.dnsDomain` / `dnsPort`，优先），或用环境变量兜底：`OOB_DNS_PORT`（默认 53）、`OOB_DNS_DOMAIN`（回调域名，如 `attacker.com`，需把该域名的 NS 指到运行引擎的机器）。DNS 出站几乎不被防火墙拦截，适合仅放行 DNS 的受限出口环境。

其他相关环境变量（接收端加固）：`OOB_LISTEN_HOST`（默认仅绑 127.0.0.1，真实环境需对目标可达）、`OOB_RECEIVED_MAX`（LRU 上限，默认 10000）、`OOB_RATE_PER_MIN`（按来源 IP 限速，默认 60/min）。

报错对照：`6001` 接收端启动失败（多半是 HTTP 端口占用）；`6002` 未启用（上面两个条件缺一，或接收端没起来）。

---

## 八、开了 tamper 反而检测不到了怎么排查

tamper 是链式变换，插件越多、越激进，越可能把 payload 变成目标不认识的语法。推荐排查顺序：

1. **先确认基线**：关掉 tamper，确认目标无 WAF 时可检出（排除 tamper 之外的因素）。
2. **看 WAF 识别推荐**：开启扫描后若识别到 WAF（`waf_detected` 事件 / 报告「检测摘要」标签页），直接用推荐的 tamper 组合，不要自己乱拼。
3. **从轻度预设开始**：轻度（space2comment + randomcase）→ 中度 → 激进，逐档验证。
4. **注意 DBMS 专属插件**：`space2mysqlblank`、`space2mysqldash`、`modsecurityversioned`、`versionedkeywords` 等基于 MySQL 版本注释语法；`space2mssqlblank`、`sp_password` 是 SQL Server 语义。用错库会直接产生非法 SQL。
5. **编码类插件有前提**：`chardoubleencode`（双重 URL 编码）要求目标会解码两次；`appendnullbyte`、`overlongutf8` 等依赖解析器容错。目标不做对应处理时 payload 原样进库，必然检测不到。
6. **大小写类**：`randomcase` 只随机化 SQL 关键字、不动字符串字面量（OOB token、锚点文本不受影响）；但人工复现时要用报告里变换后的 payload 形态，别用原始模板。
7. **二分定位**：插件一个一个加，谁加上后失效就是谁的问题。
8. **只影响注入请求**：tamper 仅变换 payload，不改基线请求，因此不会影响「目标是否可达」的判断；OOB 检测的 payload 例外——引擎对 OOB 注入**不做 tamper**，否则会破坏回调地址导致回连失败。

> tamper 清单可 `GET /api/tampers` 查询（203 个插件，含中文说明）。

---

## 九、Windows 桌面版（Tauri）打包

```bash
# 1. 把引擎打成可部署运行时包（产物在 server/dist-engine/，并暂存到 src-tauri/binaries/sqli-engine-assets/）
npm run build:engine

# 2. 桌面壳开发调试（需 Rust 工具链）
npm run tauri dev

# 3. 正式打包安装包
npm run tauri build
```

`npm run build:engine` 做了什么（见 `scripts/build-engine.mjs`）：

- 用 esbuild 把 `server/index.js` 打成单文件 `server/dist-engine/engine.mjs`（默认压缩，`--no-minify` 关闭）；
- 原样复制 `sql.js` 运行时（wasm 不能内联，否则 `__dirname` 失效导致 wasm 加载失败）；
- 冒烟校验产物可加载、导出完整；
- 复制产物到 `src-tauri/binaries/sqli-engine-assets/`（`--skip-binaries` 跳过）。

常见问题：

| 现象 | 原因 / 处理 |
|------|------|
| `找不到 esbuild` | 根目录安装 `npm install -D esbuild` 后重试 |
| `sql.js 未安装` | 先 `cd server && npm ci` |
| Rust 编译失败 | 确认 Rust 工具链（MSVC 目标）与 WebView2 运行时已安装 |

详细构建路线（含 sidecar 单文件可执行的 pkg/SEA 方案）见 [deploy.md §六](./deploy.md)。

---

## 十、Docker 部署常见问题

```bash
docker compose up -d      # 前端 http://localhost:5173，API http://localhost:4567
```

| 问题 | 处理 |
|------|------|
| 端口被占 | 改 `docker-compose.yml` 的 ports 映射，或裸机部署用 `PORT=4568 npm run server` |
| 前端页面上所有请求 401/跨域失败 | 容器里 `HOST=0.0.0.0`，务必在 `ALLOWED_ORIGINS` 里包含你实际访问的源，需要时设 `SCAN_API_TOKEN` 并在前端同源反代下使用 |
| 扫描内网/回环目标被拒 | 容器内 `HOST` 非 `127.0.0.1` 自动启用 SSRF 严格层，加环境变量 `SSRF_ALLOW_CIDRS=192.168.0.0/16,...` 显式放行授权网段 |
| 健康检查失败 | 容器内置 `curl -f http://127.0.0.1:4567/api/health`；`docker logs` 看启动报错 |
| 会话续跑数据丢失 | 会话落在卷 `sqli-sessions`（挂载 `/app/server/sessions`），`docker compose down` 不删卷，`down -v` 才会 |
| 想开 SQL Shell / 文件读写 | compose 环境变量 `EXPLOIT_ENABLED=1`（破坏性能力，默认关闭，见 [deploy.md 安全基线](./deploy.md)） |

---

## 十一、如何跑测试

```bash
# 前端（vitest）
npm test                    # 单次运行
npm run test:watch          # watch 模式
npm run typecheck           # tsc --noEmit 零错误是合入门槛

# 服务端（node:test，自动加载 server/.env.test：SSRF_ALLOW_PRIVATE=1 + EXPLOIT_ENABLED=1）
cd server && npm test

# 前后端一起
npm run test:all

# WAF / tamper 实验工具
npm run waf-lab             # 本地 WAF 模拟靶场
npm run tamper-matrix        # tamper 绕过矩阵
npm run waf-validate         # HTTP 实测验证 WAF 绕过
```

> 服务端测试大量使用 `127.0.0.1` mock 目标，依赖 `.env.test` 里的 `SSRF_ALLOW_PRIVATE=1` 放行，无需手动设置（`npm test` 已通过 `--env-file=.env.test` 自动注入）。
