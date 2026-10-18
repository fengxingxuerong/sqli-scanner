# sqli-scanner

[![Tests](https://img.shields.io/badge/tests-4202%20passing-brightgreen)](#测试)[![CI](https://github.com/fengxingxuerong/sqli-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/fengxingxuerong/sqli-scanner/actions/workflows/ci.yml)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20known%20vulns-brightgreen)](#环境变量)

> CI 徽章为真实状态（仓库地址已定，run#90 起全绿）。发布判定仍以 `CHANGELOG.md`
> 与本地/远端门禁结果为准。

**简体中文** | [English](README.en.md)

一键式 SQL 注入检测工具 —— Web 面板 / 桌面壳 / CLI 三端，**扫完即出可进 CI 的全套交付件**（SARIF 2.1.0 + CVSS/CWE + 授权声明清单 + 退出码 `0/1/2`）。无需记忆命令行参数，打开浏览器即可使用。

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

常用选项（其余与 `server/bin/cli.js` 完全一致）：

```bash
-F, --formats html,json,markdown,sarif,csv   # 输出格式（默认 html,json,markdown）
-o, --out <dir>                              # 输出目录
    --scope <域名/CIDR,...>                  # 授权范围（缺省按目标同源执行）
    --level 1-5 --risk 1-3 --technique union,error,... --tamper <链>
    --timeout <ms> --quiet --no-ledger
```

退出码可直接用于 CI 门禁：`0` 未发现高危 / `2` 发现 Critical 或 High / `1` 执行失败。完整 CI 接法（官方 composite action `action.yml`、GitHub Actions 示例 + SARIF 上传 + DefectDojo）见 [`docs/CI-集成.md`](docs/CI-集成.md)。

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
| **注入点范围** | 默认 query + body（含 JSON 嵌套）；`--test-headers` / `--test-path` 显式开启后追加请求头与 path 段；`--test-param-names` 追加「参数名本身」注入点（后端把键名当列名/排序名拼 SQL 时，值被参数化 ⇒ 只有改键名能打） |

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
| **凭据风险标注** | `--passwords` 取回的账号哈希按**格式**识别算法（MySQL native / caching_sha2、PostgreSQL md5 / SCRAM-SHA-256、SQL Server 0x0100 / 0x0200、bcrypt / argon2 等）并标注强度与风险，报告新增「凭据风险」一节。判定**完全离线、不做爆破**，且报告**不回显原始哈希** |
| **官方 GitHub Action** | 仓库根 `action.yml`（composite）：一条 `uses:` 跑完扫描 → 产出报告套件 → 上传 code scanning → 按退出码判红。引用方式与所需权限见 [docs/CI-集成.md](docs/CI-集成.md) |
| **9 种检测技术** | union / error / boolean / time / stacked / oob / second_order / inline / nosql |
| **18 种数据库** | MySQL / PostgreSQL / SQL Server / Oracle / SQLite / MariaDB / TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / H2 / Access / HSQLDB / Derby / MonetDB | **6 种真实引擎全链路验证 + 3 种部分通道验证 + 9 种模板适配**（分层见下，口径自洽由 `npm run readme:check` 守护） |

### 数据库支持验证等级（2026-09-10 复核，按证据分层）

> 口径修正：此前 README 写「3 种真实验证，15 种最小适配」——**低估了自身**：仓库中实际存在
> **7 种引擎**的真实验证记录（含 MariaDB 11.4.13、H2、HSQLDB、Derby 真引擎）。现按证据强度重列，
> 等级与 evidence 由 `server/src/engine/dbmsEvidence.js` 统一维护，并**写入每次扫描报告的
> `summary.dbmsEvidence`**（交付时客户可自行判断结论可信度，不必翻 README）。

| 等级 | 方言 | 证据 |
|---|---|---|
| ✅ **真实引擎验证**（检测/绕过主链路跑通） | MySQL、MariaDB、PostgreSQL、SQLite、Oracle（2026-09-15，e2e/oracle-lab）、SQL Server（2026-09-14，e2e/mssql-lab） | 真 MySQL 8.0.x（`e2e/real-mysql-lab` + `e2e/waf-real`）、真 MariaDB 11.4.13（`e2e/multi-engine-lab/mariadb-verify.mjs`；⚠️ 其产物测于 09-09，CRS 执行器 09-19 修准之后**未复跑**，能引什么/不能引什么写在 `results/mariadb-report.md` 顶部）、PGlite 18.3、sql.js WASM、真 PostgreSQL 16.2（`e2e/oob-real-lab` OOB 带外全链路）、**真 SQL Server 2022 Express 16.0.1000.6**（`e2e/mssql-lab`：双上下文三通道 + 拖库 5/5 + os-shell，2026-09-22 补证，见 `e2e/mssql-lab/results/VERIFICATION-2026-09-22.md`）、**真 Oracle AI Database 26ai Free 23.26.3.0.0**（`e2e/oracle-lab`：双上下文三通道 + 拖库 5/5） |
| ⚠️ **部分通道验证** | H2、HSQLDB、Derby | `e2e/multi-engine-lab`（真实 JDBC 内存库）。**三档分开引，别混**：① 无 WAF 档 = 三引擎布尔通道 9/9，回显定库 H2/HSQLDB 成功、**Derby 定不出**；② CRS **PL1（官方默认部署档）** = 布尔 9/9（`results/multi-engine-report.pl1.md`）⇒ "这三库在默认部署的 CRS 下可被检出"成立，但**定库不达**（UNION 哨兵被吃）；③ CRS **PL2/PL3/PL4** = 0/9，PL1→PL2 之间是断崖 ⇒ 不能拿②说"过任何 WAF"，也不能拿③说"过不了 WAF"。旧 P3 报告（09-09）"tamper 打穿 CRS 后 H2/Derby error 通道检出"今已不可复现，见该文件顶部的失效声明 |
| ⛔ **模板适配（未在真实 DBMS 验证）** | TiDB、DM8、ClickHouse、DB2、Sybase、Firebird、Informix、Access、MonetDB | 仅有检测/提取模板；方言语法、列类型、报错文本均可能有偏差 |

**OOB / 强动态页 / 定库加固 / 二阶跨角色的实测记录**（真机靶场，含修复过程与验证数据）已迁至
[docs/检测与定库-实测口径.md](docs/检测与定库-实测口径.md)；下文「诚实边界」仍然有效。

诚实边界：SQL Server xp_dirtree / Oracle UTL_HTTP 等其它库的 OOB 模板未真机验证；真实
ModSecurity/商业云 WAF 环境未实测。
**OOB 通道边界（2026-10-02 修正）**：UNC/SMB 类向量（MySQL/MariaDB/TiDB LOAD_FILE、
SQL Server xp_dirtree）的回调路径已改为裸主机 + share 名（`<host>\oob\<token>`，token 在
share 名里）——Windows UNC 主机位不含 `:port`，旧模板内嵌 `host:port` 在真实目标上永远
解析不了。内置接收端只监听 HTTP+DNS、捕获不到 SMB 握手：收回 UNC 向量的 token 需
自备外部 SMB 监听（Responder/Inveigh）或配置 `oob.dnsOob` 走 DNS 通道；HTTP 类向量
（PG COPY PROGRAM / Oracle UTL_HTTP / MSSQL ping）不受影响。
CRS 保真度口径（门禁现管**两族**：942 的 805 条 + 930 的 38 条
官方回归用例）也只覆盖 **query / 表单 body**：静态普查显示 942 家族装载的 66 条规则里有 54 条声明读 `XML:/*`，而本仓库的执行器不解析 XML ⇒
那 99.6%（942）/ 100.0%（930）的一致率不能外推到 XML 接口（`npm run waf-fidelity` 与
`npm run waf-fidelity:930` 各自会打印这条普查，别只看结论行）。

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

**给客户的话**：上表 ⛔ 等级（TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / Access / MonetDB 共 9 种）仅有模板适配，
请把结论视为**待复核线索**而非可用证据——报告会在 `summary.dbmsEvidence.caveat` 中自动声明这一点。
（SQL Server 与 Oracle 已于 2026-09-14/15 升级 verified，2026-09-22 补齐产物与版本凭证，**不在本段范围**。）
| **1920 条 payload 模板** | 含注释/编码/子句/嵌套闭合变体：主库 1769 + 子句 137 + OOB 14（口径：各库×各技术下的模板条目数，**同一模板跨库/技术重复计入**）+ 686 条声明式注册表（`payloads/registry.json` 681 + `payloads/registry.versioned.json` 5 条版本门条目） |
| **234 个 tamper 插件** | 覆盖 sqlmap 官方 tamper 全集（84/84，分母取自 tag 1.10.10 上游清单；`npm run tamper:parity` 核对名字、`npm run tamper:examples` 用**上游 docstring 里的官方示例**反测语义——同名不等于同行为，当前 100/115 条字面一致（另有 11 条因输出含随机性不适用字面比对、判据逐条点名跳过），其余 15 条**逐条定性**记于 `tamper-upstream-examples-baseline.json` 的 drift 字段——⚠️ 其中 T6 已修 2 条**真缺陷**（versionedkeywords 漏包 `ALL`、morekeywords 族漏包 CONCAT/CHAR/IFNULL/CAST/CURRENT_USER 等函数名，已收敛为单一真源 `versionedKeywords.js`），**另有 3 条形态差异仍未关闭**（本仓 `/*! X */` 含空格 vs 上游 `/*!X*/` 无空格；halfversioned 用版本号 50540 vs 上游 0）——形态取舍须真机 A/B 证据，本地口径不足以判，**不得据此宣称该族与上游等价**；含批次 D13 新增 5 件「上游形态变体」——真机 A/B 用，不动默认链）。⚠️ 绕过率口径见 [docs/waf-绕过能力实测口径.md](docs/waf-绕过能力实测口径.md) |
| **62 WAF 指纹** | 自动识别 WAF 类型并推荐 tamper 组合。[D44] 指纹未命中时的**多向量主动探测**（wafw00f 式）：sqli-union/sqli-quote/xss/lfi 四向量差分 + Server 头漂移 + **连接级阻断识别**（断连型 WAF 此前被吞掉），「unknown 拦截器」也带可复核证据（哪些向量被拦/头怎么漂移）。⚖️ **外部权威对拍**（口径见台账 `waf-fingerprint-coverage`，`docs/_claims-ledger.json`）：wafw00f 18 家 × 36 样本 100%（`wafExternalParity.guard`）+ WhatWaf 27 家 + nuclei(Safe3) 1 家 30 条样本 100%（`wafSecondSourceParity.guard`），16 家无第二源如实登记边界；⚠️ 构造样本口径 ≠ 真机命中，真实流量证据待商业云 WAF 授权样本（见 [docs/WAF-真机样本采集-runbook.md](docs/WAF-真机样本采集-runbook.md)）。入口：`--identify-waf`（只识别不扫描）或 `--active-waf-probe`（扫描期开启，默认关；REST 键 `activeWafProbe` 既有） |
| **可视化报告** | 风险环形图 + 技术分布条形图 + 漏洞列表 + 数据提取树 + 检测摘要 |
| **深度提取** | 分页聚合数据提取，绕过 UNION 限制 |
| **全库拖库** | `--dump-all`：枚举所有库后逐库逐表拖（对标 sqlmap --dump-all） |
| **字典爆破**（information_schema 不可用时的出路） | `--common-tables` / `--common-columns`：WAF 拦 information_schema、账号权限不足、或目标库无该视图时，用内置常见表/列名字典逐个做存在性探针（130+ 表名 / 140+ 列名，含「通道自检 + 不存在对照名」防假阴性）。实测在 WAF 拦 information_schema 的目标上仍能定位表与列 |
| **WAF 识别接口** | `--identify-waf`：仅识别 WAF 厂商并输出推荐 tamper 链，不发起注入检测（对标 sqlmap --identify-waf） |
| **AI 漏洞报告** | 3 角色流水线（分析师→撰写→审阅），支持多 key 容灾，自动生成专业中文安全分析报告 |
| **利用工具** | SQL Shell / 文件读写 / OS 命令执行（需授权）。⚠️ 验证状态见下文「利用能力实测口径」与 [docs/udf-沙箱验证环境与边界.md](docs/udf-沙箱验证环境与边界.md)：**fileRead / fileWrite / UDF-os-shell 均已跑通真实闭环**（后者在隔离沙箱内），仅注册表仍为 mock 单测 |
| **CLI 100+ 参数（原生引擎）** | 对标 sqlmap：--dbs/--tables/--dump/**--dump-all**/**--common-tables**/**--common-columns**/-D/-T/-C/--search/--users/--passwords/--prefix/--suffix/--time-sec/-r/--mobile/--parse-errors/--safe-url/--safe-freq/--delay/--current-user/--current-db/--hostname/--is-dba/**--identify-waf**/--skip-static/--predict-output/--test-headers/--test-path/**--test-param-names**/**--hex**/--where/--param-del/**--advise**（扫描前风险评估）/**--confirm-extreme**（极高危第二道确认）/**-b --banner**/**--statements**/**--procs**/**-U**（用户过滤）/**--exclude**（库排除）等（`node server/bin/cli.js --help` 为准，从仓库根直接跑；`--dbs` 等参数说明在该 help 里） |
| **diff-aware CI 门禁** | `node scripts/one-click-scan.mjs -u <url> --diff-base auto`（[D45] semgrep 语义：**只对新增发现判红**）。与台账中最近一次同目标扫描自动比对（或显式 `--diff-base <scanId>`；diff 计算与 REST `/api/scan/:id/diff` 同一模块）：新增发现 → exit 2；存量仍在 → exit 0（不阻塞无关 PR——安全 CI 被弃用的第一原因就是存量噪声）；本次结论不可信（validity）或无基线可认 → exit 1（不判红也不假绿）。产出 `diff.json`（fixed/new/remaining 明细）+ `manifest.diff`（机器消费）。接法与语义细则见 [docs/CI-集成.md](docs/CI-集成.md) 第五节 |
| **原生 MCP server** | `node server/bin/cli.js mcp`（stdio NDJSON，零依赖，[D43] 对标 dalfox `mcp` / semgrep `mcp` 的「MCP 是 CLI 的一个模式」形态）：AI 代理宿主（Cursor / Claude Code / VS Code 等）直连驱动扫描。9 个工具：`run_scan`（异步返回 scanId）/ `get_scan_status` / `get_findings`（CWE·CVSS·受影响参数·PoC curl）/ `get_report`（json/md/html/csv/sarif/db-json）/ `list_scans` / `stop`·`pause`·`resume_scan` / **`preflight`**（零 payload 侦察：可达性 + 注入点发现）。走与 REST 同一条 sanitizeStart 配置白名单 + SSRF/scope 护栏——MCP 不是旁路；`confirmDestructive` 必须显式传（代理不得代答）。宿主配置：`{"command":"node","args":["<repo>/server/bin/cli.js","mcp"]}` |
| **NoSQL / OOB 通道开关（CLI）** | `--no-sql`（NoSQL / GraphQL / SSTI 补充趟）、`--oob`（带外接收端）与 `--oob-interactsh`（[D87] 外部协作端隧道）。[2026-10-12] 这两个通道**默认关**，引擎与 UI/REST 早可达，**唯独 CLI 没有入口**（连 `--config` 档案都被未知键硬拒）⇒ CLI/脚本用户此前完全开不了：旗标只开总开关，子键走 `--config`（如 `{"oob":{"enabled":true,"callbackBase":"cb.example:8899"}}`，整组带底合并，未写子键回落默认）。⚠️ 与 `--technique` 正交：technique 决定「测不测」，`oob.enabled` 决定「接收端起不起」——只写 `--technique oob` 拿不到回调 | `--oob-interactsh` 解决**回连拓扑**：内置接收端要求「目标能回连扫描器」，目标是云上/NAT 后/跨网段时通常不通 ⇒ 无回显盲注恒判「未检出」（与「这个站没注入」同形的静默假阴性）；该旗标改用 interactsh 协议的外部协作端，**只要求扫描器能出网**（引擎零依赖手写协议：注册/轮询/AES-256-CTR+RSA-OAEP 解密）。默认用公共协作端（`oast.pro` 等，回连记录交给其运营方，**真实项目建议自建**）；⚠️ 公共协作端下 OOB 只回带 token、不回带数据本身；仅在已授权范围内使用 |
| **CLI 报告格式补齐 db-json** | `-f/--format` 现支持 `json|csv|markdown|md|html|sarif|**db-json**`（db-json = 仅拖库数据，扩展名 `db.json`，与 REST `/report/export` 同源；此前 REST/UI 有、CLI 与 MCP 枚举缺）。**未知格式改为拒绝启动**（旧行为静默回退 JSON ⇒「以为导了 db-json 实际是普通 JSON」） |
| **注入点筛选三件套** | `-p/--test-param <p1,p2>`（只测指定参数）/ `--param-exclude <regex>`（正则排除噪声参数）/ `--param-filter <place,...>`（按位置筛选：url/get/query、body/post/form、header、cookie、path；对标 sqlmap 同名三参）。[D41] 复测与 CI 定向回归用：大 body 只测可疑参数不再全量投 payload。**筛光点位即报错退出并列出可用点位**——0 点扫描=「没测」，绝不伪装成「未检出」 |
| **二阶触发整请求** | `--second-req <file>`（对标 sqlmap --second-req）：触发页从 Burp/curl 抓包导入（URL/method/headers/body，与 `-r` 同一解析器）。认证触发页（POST + Cookie/CSRF）用 `--second-order <url>` 表达不了——不带会话必 401、二阶必漏。方法仍过幂等门（productionMode 下非幂等触发读取需 `--allow-second-order-writes`），SSRF/授权范围校验与 `secondUrl` 同级（不过即整体丢弃） |
| **忽略错误码 / 参数随机化** | `--ignore-code <c1,c2>`（对标 sqlmap 同名）：指定状态码不再计入「拦截/会话失效/服务器错误」可信度判定（内容照常比对）——注入点确实坐在 401/500 后面的目标不再被拖成 blocked/session_expired。`--randomize <p1,p2>`（对标 sqlmap 同名）：每条注入请求随机化指定参数值（URL query/Cookie/请求头/表单伴随字段），长枚举防反爆破锁定；注入点自身永不随机化 |
| **拖库独立产物格式** | `--dump-format <csv\|sql\|html\|json>`（对标 sqlmap 同名）：有拖库数据时一键扫描产出 `dump.<ext>`。只影响独立产物，报告内嵌拖库区不变。[D42] 四个格式化函数与 27 条既有单测同源复用 |
| **提取比较算子** | `--fetch-using <gt\|between>`（[D50]，默认 gt=历史行为零回归）：`>`/`<` 被 WAF 过滤而 BETWEEN 仍放行的目标上，between 把长度/字节二分换成 `x BETWEEN lo AND mid` 窄化（cls 字符类探测本就只用 BETWEEN，该通道此前的静默失准正是本开关要堵的洞）。布尔与时间双通道同构；探测次数与 gt 同阶，提取值经等值复验。`in` 不支持（IN 为假时无法定位区间，TODO 留证）；非法值拒绝启动。⚠️ 上游归属更正：原登记为"对标 ghauri --fetch-using"，对 ghauri v1.0.5/dev 整包取证 0 命中——按技术本身价值落地 |
| **响应解密脚本** | `--postprocess <file.js>`（[D52]，与 `--request-script` 对偶）：目标把响应体加密/编码后返回时（AES 信封、自定义 Base64 变体、自研 RPC 序列化），检测层拿到的全是密文 ⇒ 真/假条件的差异被加密抹平 ⇒ 报告写「未检出」——**而那不等于没有洞**。脚本导出 `transform(res)->res`，在 per-scan 客户端视图最内层对每条响应体解密/解码（含保活/CSRF 取页/登录；爬虫请求不经此层），只允许替换 `data`（status/headers 是可信度判账的输入，不可改）。硬约束与 request-script 对偶：脚本须位于 `RESPONSE_SCRIPT_DIR` 白名单目录内；加载失败**扫描不启动**；执行失败时该响应按失败处理（fail-closed，宁漏不误，绝不用密文继续比对） |
| **配置档案** | `--config <file.json>` 预载参数（argv > 档案 > 内置默认；键=长参数名，如 `{"level":5,"tamper":"space2comment"}`；含未知键拒绝启动）+ `--save-config <file.json>` 把本次非默认参数增量落盘复扫（对标 sqlmap -c/--save + ffuf -config）。[D41] 配合上面的筛选三件套可把「复测配方」入库进 CI |
| **sqlmap 桥接参数（非原生）** | `--csrf-url` / `--csrf-token` / `--eval` / `--skip-urlencode` / `--keep-alive` / `--null-connection`：**仅当转交外部 sqlmap 进程（sqlmapBridge）时才会被传递**，本项目自有引擎不消费这些键。请勿把上表与本节混用 |
| **-r 请求文件** | 从 Burp/curl 请求文本导入 URL/method/headers/body |
| **结构化 body 通道（JSON 嵌套 / XML·SOAP）** | 两类现代 API body 都按**叶子路径**发现注入点，而不是把整份 body 当成一个参数：`jsonBody`（对象，如 `user.id` / `tags.0`）与 `xmlBody`（XML 字符串，如 `soap:Envelope.soap:Body.GetUser.id`；对标 ghauri 的 XML·SOAP 支持）。入口：REST `xmlBody` 字段、CLI `--xml-body` / `--xml-body-file`。⚠️ XML 通道只认「元素 + 文本」形态：注释 / CDATA / DOCTYPE / 正文处理指令一律**整体放弃**（宁可不发现，也不发畸形报文） |
| **mTLS 客户端证书** | `clientCert`（PEM 路径，证书+私钥同文件，对标 sqlmap `--cert`）：目标要求 TLS 双向认证时没有证书连第一跳都被拒。与 `insecureTls` 正交（一个管「我信不信目标」，一个管「目标信不信我」） |
| **Bearer/Token 自动续期** | `--refresh-url`（`config.bearerRefresh`，面板「网络与认证」同址）：API 的 access token 通常 15 分钟～1 小时过期，而一次扫描动辄几千条请求几十分钟 —— 后半程全 401 时检测层看到的是"响应没有差异"，报告写「未检出」，**而那半程一个注入都没进业务逻辑**。配上它：请求吃 401/403 ⇒ POST 刷新端点换新令牌 ⇒ 重试原请求一次。四条口径：① 拿到新 token 之前**不动**你从抓包带来的 `Authorization`；② 一次挑战只续一次（不循环打客户认证服务）；③ 并发去重（几十条同时 401 只发一次续期）；④ 续期失败必须显形 —— 结论降级为 **inconclusive**，reason 里给出「尝试 N 次失败 M 次 + 最后一次原因」（取不到 token 时会写明试过哪些字段、响应顶层有哪些键）。同批补了 `session_expired` 的两种此前无人接手的形态：**整轮零业务响应**（从来没进去过）与**进去过之后连续出不去**（中途失效）—— 既有判据要求"基线请求不 401"，而令牌过期时基线同样吃 401，那条判据在这类目标上永不可达。不实现 OAuth2 授权码 / SSO / 验证码。见 [docs/Bearer令牌续期.md](docs/Bearer%E4%BB%A4%E7%89%8C%E7%BB%AD%E6%9C%9F.md) |
| **自定义请求变换（扩展点）** | `--request-script <file.js>`（`config.requestScript`）：目标接口带 `sign=` 签名、整参加密或 timestamp+nonce 防重放时，注入值会破坏签名 ⇒ 目标恒回 400 ⇒ 报告写「未检出」，**而那不等于没有洞**。脚本在**扫描/检测阶段**每条出站请求的最后一环重算签名/重新加密（含保活页、CSRF 取页、登录提交这些非注入请求；⚠️ 注入点发现阶段的爬虫请求不经此层，见文档 §7）。四条硬约束：① 变换在 SSRF/scope 校验之前完成（校验作用于变换后的 URL）；② 脚本失败即**不发**该请求（绝不退化成"发没签名的原始请求"）；③ 只能改 `url/method/headers/data/params`，`signal/scanId/限速` 等引擎控制权不可被脚本摘掉；④ 脚本必须位于环境变量 `REQUEST_SCRIPT_DIR` 内（出口层的代码注入面）。配套判据 `transform_rejected`：连基线请求都被拒 ⇒ 判「脚本配错」并中止；基线正常而注入全被拒 ⇒ 判「签名没覆盖该参数」，两种都强制把结论降级为 **inconclusive**。用法见 [docs/请求变换脚本.md](docs/请求变换脚本.md) |
| **自定义检测条目（扩展点）** | `--payload-file <file.json>`：追加用户自己的 payload 条目（与 `registry.json` 同 schema），**只追加、不允许覆盖内置**，且同样受高危池硬门管辖；不传即与内置基线逐位一致。见 [docs/自定义检测条目.md](docs/自定义检测条目.md) |
| **中英双语** | 全界面 i18n 支持中英切换 |
| **历史记录** | 扫描历史卡片式展示，支持续跑/删除 |
| **真实 DBMS 验证** | **6 种真实引擎全链路验证**（MySQL / MariaDB / PostgreSQL / SQLite / Oracle / SQL Server）+ 3 种部分通道验证 + 9 种模板适配；分层与逐条证据见上文「数据库支持验证等级」表（[2026-10-12 修正] 本行原写「SQLite + PostgreSQL + MySQL 三库」，与「18 种数据库」行自相矛盾且已落后于现状） |

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
npm run waf-real:collect # [P0-1] 商业云 WAF 真机样本采集（仅授权目标；礼仪性 GET / --from-json）
# [P0-2] 第二权威对拍源样本提取（WhatWaf 源码目录 → second-source-samples.json）
node scripts/extract-second-source-samples.mjs --whatwaf <WhatWaf-src> [--out <json>]
npm run acceptance      # 【门禁】全方位验收（21 套件，事实断言模式，可进 CI）
npm run quality:all     # 【门禁】一键全量质量校验（测试/覆盖率/变异/验收/类型/架构/嵌套/引用/文档/版本，等价于 ci:local）
```

## CLI 能力速查（按用途分组）

> 完整口径以 `node server/bin/cli.js --help` 为准（那是**唯一真源**，本节与它由
> `npm run readme:check` 的 ⑯ 判据钉死双向一致：README 少写一个旗标即红）。
> 下表按**用途**归组，不是按 help 的机械顺序；`--authorized` 是所有高危通道的前置。

| 用途 | 旗标 |
|---|---|
| 目标输入 | `--url` `--request-file` `--batch` `--direct` `--headers` `--header` `--log-file` |
| 注入请求构造 | `--method` `--body` `--cookie` `--header` `--session-file` `--known-point` |
| 认证与会话 | `--auth` `--auth-type` `--login-url` `--login-user-field` `--login-pass-field` `--refresh-token` `--refresh-field` `--csrf-method` `--csrf-refresh` |
| 检测控制 | `--test-filter` `--test-skip` `--no-verify` `--use-registry` `--smart` `--time-baseline-every` `--param-mine` `--crawl-browser` `--forms` `--crawl` |
| 并发与调度 | `--concurrency` `--concurrency-det` |
| sqlmap 兼容长名（短名的长形式，脚本可移植用） | `--user` `--db` `--table` `--skip` `--headers` `--concurrency-det` |
| 枚举与拖库 | `--columns` `--columns-list` `--schema` `--privileges` `--roles` `--count` `--exclude-sysdbs` `--no-exclude-sysdbs` `--start` `--stop` `--dbms` `--union-cols` `--union-from` `--no-cast` `--sql-template` |
| 提取与重放 | `--verify` `--flush-session` `--fresh-queries` `--days` |
| 响应匹配（高级检测） | `--string` `--not-string` `--code` `--text-only` `--titles` `--regexp` `--invalid-bignum` `--invalid-logical` `--invalid-string` |
| 利用通道（**需 `--authorized` + `EXPLOIT_ENABLED=1`**） | `--os-cmd` `--os-shell` `--sql-shell` `--udf-hex` `--udf-install` `--file-read` `--file-write` `--file-dest` `--driver` |
| 网络与协议 | `--proxy` `--proxy-bypass-local` `--no-proxy-bypass-local` `--insecure` `--rate` `--threads` `--retries` `--http-timeout` `--delay-sec` `--req-rate` `--max-requests` `--tor` `--check-tor` `--random-agent` `--force-ssl` `--ignore-redirects` `--hpp` |
| 安全护栏与授权 | `--authorized` `--confirm-destructive` `--no-production-mode` `--no-xp-auto-enable` `--no-validation-skip` `--yes` |
| 已移除的占位参数（**收参数但不生效**，仅为兼容旧命令行） | `--no-escape` `--union-char` `--max` `--days` |
> ⚠️ 上表 `--max` / `--days` 指**扫描侧**的占位（收下即丢弃，无效果）。`node server/bin/cli.js ledger prune --max=N` 是 **ledger 子命令自己的参数**，仍然有效，两者同名不同义。

**三处必须知道的口径**（README 别的章节也有展开）：

- **`--authorized` 是红线**：`--os-cmd` / `--sql-shell` / `--file-read` / `--file-write` 四个利用通道**双闸门**——必须显式声明已获授权，且进程环境设 `EXPLOIT_ENABLED=1`；缺一即拒启动。
- **`--risk 3` 默认不放高危 payload**：`--confirm-destructive` 是显式放行口；靶场/自建演练用 `--no-production-mode` 等价声明。
- **`--insecure` 会关闭 TLS 校验**（失去中间人防护），报告与会话会告警。

## 后端 API

下表由 `npm run readme:check` 与代码注册**双向核对**（`server/index.js` 的挂载点 + 各 router 的注册行）：
表里写了不存在的端点会红，代码新增端点而表里漏写也会红。同一批路由双挂载在 `/`（Tauri 版），
下表只列 `/api` 口径（Web 版）。

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查（版本与 package.json 同源，另回显鉴权/利用开关与 Node 版本；含 `egressPolicy`：`{ level, allowCidrs, cloudMetadataBlocked }` 出站策略态） |
| `/api/scans` | GET | 服务端历史清单：台账 + 在途扫描合并（需 token，含目标 URL） |
| `/api/scan/start` | POST | 启动扫描（占一个并发槽；目标先过 SSRF 与 scope 校验；body 可含 `redactPasswords: true` 开启报告凭据脱敏） |
| `/api/scan/:id` | GET | 实时报告快照（含 `status`/`state` 运行态；上下文回收后回退台账并标 `source`） |
| `/api/scan/:id/events` | GET | SSE 进度流（EventSource 无法设自定义头，token 可走 query；按 Last-Event-ID 回放） |
| `/api/scan/:id/stop` | POST | 停止扫描（未知 id → SCAN_NOT_FOUND；已终态不改写状态） |
| `/api/scan/:id/pause` | POST | 暂停扫描（暂停在**请求边界**生效：期间不再向目标发包） |
| `/api/scan/:id/resume` | POST | 恢复扫描 |
| `/api/scan/:id/report` | GET | 获取报告（与导出同源，含可复制的 PoC；内存回收后读台账） |
| `/api/scan/:id/report/export` | GET | 导出报告（json / html / csv / markdown / md / db-json / sarif；无拖库数据的 db-json → 400；`?redactPasswords=1` 运行时覆盖脱敏） |
| `/api/scan/:id/report/ai` | POST | AI 报告生成（数据外发为 opt-in，未设端点即拒绝） |
| `/api/scan/:id/report/ai/configs` | GET | AI 可用配置清单（不回显 Key） |
| `/api/scan/:id/point/:pointId/retest` | POST | 单点复测（交付场景：修完要能证明确实修好了） |
| `/api/scan/:id/diff` | GET | 两次扫描差异对比 |
| `/api/payloads` | GET | payload 模板清单 |
| `/api/tampers` | GET | tamper 插件清单 |
| `/api/exploit/capabilities` | GET | 利用能力清单，**由 Exploiter 的接管能力表推导**（附 `matrix`：各能力的 risk / requiredPriv） |
| `/api/exploit/sql` | POST | SQL 执行（需 `EXPLOIT_ENABLED=1` + 显式 authorized）。两种入参：手工 `target+point+dbms`，或 `scanId`+`pointId` 直接沿用扫描点位、定库结果与会话。严格模式下需 `authDeclaration`（operator/scope/timestamp/validWindowMs） |
| `/api/exploit/file-read` | POST | 目标文件读取（同上） |
| `/api/exploit/file-write` | POST | 目标文件写入（同上） |
| `/api/exploit/os-shell` | POST | OS 命令执行（同上；MySQL 需 sys_eval UDF，缺失时如实返回失败原因） |
| `/api/exploit/side-effects` | GET | [D90] 查看某次扫描的**写副作用登记**与清理计划（`?scanId=`）。**只读、不需 EXPLOIT 门** —— 关掉利用能力后仍能查残留，否则运维看不见痕迹反而更危险 |
| `/api/exploit/side-effects/cleanup` | POST | [D90] 执行写副作用清理（P2-5：把人工条款 R5/R6 变成代码能力）。**与写类端点同门控**（`EXPLOIT_ENABLED=1` + 授权声明 + scope 声明）——清理会对目标再发一次命令/写请求，绝不绕过门控；默认不自动执行（扫描器自作主张再动目标比不清理更危险） |

> **授权声明**（`authDeclaration`）：利用操作在 `AUTH_DECLARATION_STRICT=strict`（默认）下需结构化授权声明 `{ operator, scope, timestamp, validWindowMs }`——`scope` 覆盖目标、`timestamp` 在有效窗内。`lenient` 模式兼容旧 `authorized: true` 布尔自证。配额超限返回 `QUOTA_TARGET_EXCEEDED` / `QUOTA_FANOUT_EXCEEDED`；声明问题返回 `AUTH_DECLARATION_MISSING` / `AUTH_DECLARATION_INVALID` / `AUTH_SCOPE_MISMATCH` / `AUTH_DECLARATION_EXPIRED`。审计落盘 `ledger/auth.jsonl`。
| `/api/sqlmap/status` | GET | sqlmap 是否可用（不返回脚本路径） |
| `/api/sqlmap/start` | POST | 启动一次 sqlmap 桥接扫描 |
| `/api/sqlmap/:id/events` | GET | sqlmap 扫描 SSE 事件流 |
| `/api/sqlmap/:id/report` | GET | 取 sqlmap 扫描报告 |
| `/api/sqlmap/:id/report/export` | GET | 导出 sqlmap 报告（`?format=json\|markdown\|md`；html/csv/sarif 属内置引擎渲染器，桥侧显式 400 而非静默降级） |
| `/api/sqlmap/:id/diff` | GET | 与基线扫描比差异（`?base=<scanId>` → `added`/`removed`/`unchanged`；缺 base 或任一侧不存在 ⇒ 显式错误码，不返回空 diff） |
| `/api/sqlmap/:id/stop` | POST | 停止 sqlmap 扫描 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `4567` | 监听端口 |
| `SCAN_API_TOKEN` | 无 | API 认证 Token（**非回环监听时必填**，见下） |
| `SCAN_API_TOKEN_FILE` | 无 | 从文件读取 Token（Docker/K8s secret 挂载优先于此项） |
| `SCAN_API_ALLOW_NO_TOKEN` | `0` | 置 `1` 显式接受无鉴权（仅隔离网络；非回环时会打显著告警） |
| `SSRF_ALLOW_PRIVATE` | `0` | 置 `1` 豁免严格层（回环/私网），不豁免基础层（云元数据仍拒） |
| `SSRF_ALLOW_CIDRS` | 无 | 逐段放行 CIDR（逗号分隔，支持 IPv4 与 IPv6，如 `10.0.0.0/8,2001:db8::/32`）；非法项忽略并告警 |
| `EXPLOIT_ENABLED` | `0` | 开启利用能力（=1 启用）；开启后仍需结构化授权声明（`authDeclaration`）或 `AUTH_DECLARATION_STRICT=lenient` 兼容旧布尔 `authorized:true` |
| `AUTH_DECLARATION_STRICT` | `strict` | 授权声明严格模式：`strict` 要求结构化 `authDeclaration`（operator/scope/timestamp）；`lenient` 兼容旧 `authorized:true` 布尔自证 |
| `QUOTA_TARGET_MAX` | `20` | 单凭据时间窗内最多不同目标数（超限 → `QUOTA_TARGET_EXCEEDED`） |
| `QUOTA_FANOUT_MAX` | `5` | 单凭据同时最多活跃扫描数（超限 → `QUOTA_FANOUT_EXCEEDED`） |
| `QUOTA_WINDOW_MS` | `3600000` | 配额时间窗（毫秒，下限 60000） |
| `AUDIT_SINK_FAIL_MODE` | `strict` | 审计 sink 不可写时：`strict` 拒绝执行（不静默放行）；`lenient` 告警但放行（仅本地开发） |
| `TIMING_BASELINE_MIN_SAMPLES` | `5` | 目标级时间基线返回所需最少样本数（不足时降级为扫描内基线） |
| `TIMING_BASELINE_MAX_HOSTS` | `1000` | 目标级时间基线 LRU 上限（超限淘汰最旧 host） |
| `TIMING_BASELINE_EWMA_ALPHA` | `0.3` | 时间基线 EWMA 平滑因子（0-1，越大越偏向新样本） |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | 跨域白名单 |
| `SCAN_LEDGER_MAX` | 无 | 台账条目上限：保留最近 N 条，更老的连目录一起删除。**未设 = 不淘汰**（默认不清任何历史） |
| `SCAN_LEDGER_MAX_DAYS` | 无 | 台账保留天数：按 `finishedAt` 淘汰过期条目。**未设 = 不淘汰** |
| `REQUEST_SCRIPT_DIR` | 无 | 自定义请求变换脚本（`--request-script` / `config.requestScript`）的**白名单根目录**。未设时一律拒绝加载任何脚本 —— 脚本会改写 URL 与报文、且运行在持有客户凭据与出口策略的那一层，属代码注入面，故不给自由路径 |

> 台账保留策略默认关闭 —— 扫描产物是有损删除，不能因为升级静默清掉历史。
> 需要时才配置上面两项（或手动 `node server/bin/cli.js ledger prune --max=50`）。
> 淘汰是「目录 + 索引」成对移除：被淘汰的 `scanId` 不会再出现在 `GET /api/scans` 里，
> `GET /scan/:id/report` 也如实返回 404，而不是留半份数据。

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

**目标认证能力实测口径（2026-09-14 起）**：Basic / Digest / NTLM 均已实现并接线 ——
NTLMv1 三步握手 + 自实现 DES（`core/desEcb.js`，不需要 `--openssl-legacy-provider`）；
逐项状态与验证命令见 [docs/检测与定库-实测口径.md](docs/检测与定库-实测口径.md)。

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
# 前端测试（574 个用例）
npm test

# 服务端测试（3634 个用例）
cd server && npm test

# 全部测试
npm run test:all
```

> 下方「项目状态」里的测试数与覆盖率**不是手写的**，唯一来源是 `docs/_facts.json`
> （由 `npm run facts:refresh` 实跑采集）。`npm run facts:check` 会校验二者是否一致，
> 已接入 `check:all` 与 CI —— 数字对不上就红，避免文档口径静默漂移。
> 补测后若数字变化，跑 `npm run facts:fix` 一键回写 README。

```bash
npm run artifact:drift   # 入库的 e2e 基线产物必须等于当前代码跑出来的那份（只忽略时间戳）
```

> 与上面那条不同源的另一半：`facts` 管"README 抄的数字新不新"，`artifact:drift` 管
> "**入库的 e2e 报告本身**还是不是当前代码生成的"。仓库里躺过一份连印五天
> 「tamper 后检出」而两列实测全为 `-` 的基线（09-20 生成、09-25 才发现），
> 当时**没有任何门禁会因它变红**。现在 CI 的 `e2e-self-contained` job 在 run-all 之后跑这道，
> 三处接线（package.json / ci.yml / ci-local）由 `server/tests/artifactDrift.wiring.test.js` 钉住。

## 项目状态

- TypeScript: 零错误
- 前端测试: 574/574 通过（覆盖率门禁 stmts 93.03 / branch 84.88 / func 81.90，阈值 88/77/67）
- 服务端测试: 3634 用例（3628 pass / 0 fail / 6 skip，并发口径 2026-10-18 复测；6 skip 为环境依赖显式跳过。覆盖率 lines 91.13 / branch 80.54 / func 84.28，阈值 85/74/77）
- 一键扫描: `npm run scan -- -u <url>`（CLI 一条命令产出 HTML/JSON/Markdown 全套报告 + manifest，退出码可直接进 CI 门禁）
- Tamper 插件: 234 个（含批次 D3 新增 scalarselectinline；含 v24 增量 20 个，对齐 sqlmap 官方 tamper 全集，含官方 CRS/libinjection 实测组合 uniontable+odbcbrace；含批次 D13 新增 5 件上游形态变体 *nospace/*open/*block，真机 A/B 判决前不进默认链）
- WAF 绕过能力: 200+ 插件链式组合，覆盖 62 个 WAF 厂商指纹识别 + 推荐

## 性能

**手法**：请求数不是估的 —— 用记录型 stub 顶替 `core/httpClient.js` 逐条记账，
因此**不需要网络、不需要靶场、不需要数据库**也能精确计数（`e2e/perf/request-budget.probe.mjs`）。
这突破了「性能结论必须上靶场」的死结，也让性能成为可回归的量。

```bash
npm run perf:budget    # 打印分检测器明细 + 跨检测器重复请求 + 未采样通道清单
```

> ⚠️ 本节**刻意不写死数字**：探针结果随 `level/risk/technique` 与目标响应形态变化，
> 写进文档就会漂移（本仓已多次踩「文档现状段过期」）。要数字就跑上面那条命令。
> 参考量级：2026-10-03 最小配置 + 安全点实测约 **96 请求**，
> 其中「跨检测器字节级完全相同」的重复请求仅 1 种 × 5 份（约 5%，且是**上界** ——
> 能否复用要先证各检测器要的 baseline 语义等价）。

**未采样通道（别当成「无浪费」）**：`time` / `stacked` / `oob`（会真 sleep 或需真靶场）、
提取阶段（需真实 DB 回显）、WAF 自适应重跑路径（需真被拦截，实测 +40~60 请求/点）。

**优化纪律**：`compactErrorTemplates`（按机制族裁剪报错模板）默认**关闭** ——
干净场景零损失，但 CRS PL1 技术位会掉 2 个。本仓口径是**不用检出能力换请求数**，
任何性能优化的验收都必须包含 WAF 场景。

**速度对照（sqli-labs 复刻靶场 23 关，产物 2026-10-13，双方各 3 轮 · 检出多数决 · 耗时取中位）**：
本工具平均 **101ms/关**，sqlmap 1.10.7（`--level=1 --risk=1 --technique=BEUSQ`）平均 **2.2s/关**
—— 约 **22× 快**，检出 **23/23 vs 14/23**（仅我方命中 9、仅 sqlmap 命中 0、双方均未检出 0）。
⚠️ 与 2026-10-03 那份同口径产物**逐位复现**（同为 23/23 vs 14/23，我方 116ms→101ms）⇒ 这条数字可复跑、不是一次性快照。
⚠️ 此前本行写的是「产物 2026-09-16：335ms/关、23/23 vs 15/23」——那是两轮口径的旧产物，
仓库里更新的 10-03 定版已是一致地 **14/23**；旧行把「sqlmap 少一轮测量」写成了「sqlmap 多检出一关」。
⚠️ 靶站是 `e2e/sqli-labs/sqli-labs.py`（本项目自写的 Python 复刻，非上游 PHP 仓库），
双方同靶站同条件 ⇒ 这是**同题对照**而不是外部真值；复跑：`node e2e/sqlmap-benchmark/run.mjs --runs=3`。

### ⚠️ 已知问题与修复记录（黑盒评测）

独立第三方评测靶场 `e2e/blackbox-lab/`（刻意不复用项目自带靶场，避免作者自证）：真 MySQL 8.0.28，
22 靶点 = 15 漏洞点（真值 15/15 成立）+ 7 安全对照（真值 7/7 防护确认）。当期结论：
**扫描覆盖 22/22；默认档 r1 检出 10/13、实战档 r2 检出 13/13、安全点误报 0/7**；
同题对照 sqlmap（level 1）：检出 7/13、误报 0/7。

历次缺陷（P0 / P1-A..G）的根因、修法、修复验证，以及「修复同时推翻一组此前对外数据」的
完整记录见 [docs/blackbox-lab-已知问题与修复记录.md](docs/blackbox-lab-已知问题与修复记录.md)。

### WAF 绕过能力实测口径（2026-09-19 重写：旧数字已作废）

> ⚠️ 本节曾于 2026-09-19 被整体推翻过一次：旧数字出自保真度只有 60.7% 的自实现 SecRule 执行器，
> 用 CRS 官方回归集修准后（99.3%）同一批探针的结论完全变了。完整历史见
> [docs/waf-绕过能力实测口径.md](docs/waf-绕过能力实测口径.md)。

| 档位 | tamper off | tamper on | 自动选链 | 结论 |
|---|---|---|---|---|
| **PL1（CRS 默认部署档 —— 客户线上真正面对的）** | 8 | 8 | 8 | 现有探针本就能通过默认部署的 CRS，**挂链无可证增益** |
| **PL2** | 0 | **1** | 0 | **全仓目前唯一观测到「挂链有净收益」的档**：off 0 → on 1（orderby 的 error 通道） |
| **PL3（全规则最严档）** | 0 | 0 | 0 | 现有 tamper 链对 942 家族**无可证绕过** |
| **PL4** | 0 | 0 | 0 | 与 PL3 同形 —— **断崖在 PL1→PL2，之后是平的** |

- 上表是「技术位合计」，**不是绕过率** —— 不要写成 `N/M` 分数或百分比对外引用；PL2 那格是
  1 个技术位且出自自实现执行器口径。安全对照：四档均零误拦。复现：`npm run acceptance`
  （`waf-real` / `waf-auto` 两套件，事实数字进报告）。
- 执行器保真度门禁（`crs-fidelity`，CRS 官方回归集钉执行器自身）：**族 942 99.6% / 族 930 100.0%，
  两族各 0 未点名分歧 → PASS**。修复过程与缺陷注入复验见迁移文档。
- ⚠️ **2026-09-27**：真实 ModSecurity 引擎已首次实测（真 `owasp/modsecurity-crs:nginx` 容器）——
  当时记录为真机判「有绕过效果」的插件 PL1 74 / PL3 72。**⚠️ 这两个数字现已禁止引用**：
  09-28 复查时它的 CI 报告产物已不在（只保留了后两轮），而三轮之间样本集、镜像 digest、
  PARANOIA/阈值、放行判据全部一致 ⇒ 无法复现、也无法解释它与后一轮的差 9 倍。此处保留仅作
  过程留痕。**仍禁止对外声明真实 WAF 下的绕过率**，逐条数字与三条理由见
  [docs/archive/WAF-真机对拍-2026-09-27.md](docs/archive/WAF-真机对拍-2026-09-27.md) 与
  [2026-09-28 第七节](docs/WAF-真机对拍-2026-09-28.md) 的 7.3。
- ✅ **2026-09-28**：靶站换真 MySQL，口径从「放行」升级为**「打穿」**——同一条样本要同时满足
  过了 WAF **且** SQL 真的执行并吐出证据。PL1/PL3 真机**打穿**插件各 **1** 个（`unionvaluesrow`），
  而同口径下**放行**的是 **8** 个：**「放行 ≠ 打穿」由此第一次被量化（差 8 倍）**；安全对照 0 误拦。
  ⚠️ 本批样本的直连打穿上界只有 **1/8** ⇒ **仍禁止对外声明真实 WAF 下的绕过率**（分母是 1，
  不具统计意义）；且 CI 里设 `MODSEC_REQUIRE_DB=1`，真库不在位时对拍直接失败、不降级出数。
  数字、边界与一处待查差异见 [docs/WAF-真机对拍-2026-09-28.md](docs/WAF-真机对拍-2026-09-28.md)。
  （上两条为**旧样本集**（8 条、单注入点）下的数字，与下一条不可横向比。）
- ✅ **2026-09-28（第三轮）**：样本集扩到 **15 条并自带上下文**，靶站注入点从 1 种扩到 3 种
  （`WHERE id = ${raw}` / `WHERE name = '${raw}'` / `WHERE id IN (${raw})`，对应真实业务里
  最常见的三种裸拼写法）。起因是上一轮直连上界只有 1/8 —— 根因不是 WAF 强，而是
  **样本与靶站形态不匹配**（字符串上下文的样本拼进数值注入点 = 语法错误）。同批把打穿判据
  收紧为「报错里也必须出现注入标记」。
  **CI `modsec-live` 已出数**（镜像 digest 与 CRS 4.29.0 随报告固化）：**直连打穿上界 7/15**
  （闸门 `MODSEC_MIN_UPPER=4`，不够就红、不静默出数），真机**打穿**插件 **1** 个
  （`unionvaluesrow`，2/15；它自己的直连上界同为 7/15，故按可打穿样本计 2/7），
  同口径**放行** PL1 **24** / PL3 **23** 个 ⇒ **「放行 ≠ 打穿」差一个数量级**；安全对照 0 误拦。
  ⚠️ 分母仍只有 7、打穿插件只有 1 个 ⇒ **依然禁止对外声明真实 WAF 下的绕过率**。
  逐样本判定、逐链矩阵与三条口径见
  [docs/WAF-真机对拍-2026-09-28.md](docs/WAF-真机对拍-2026-09-28.md) 第六、七节。
- ✅ **2026-09-29（第四轮）**：注入点形态从 3 种扩到 **5 种** —— 补上真实业务里同样高频、
  但**逃逸前提完全不同**的两处：搜索页 `LIKE '%q%'`（要先闭合 `%'`）与列表页排序
  `ORDER BY ${sort}`（不在 WHERE 里，等值/union 那套前提整个不成立）。PHP 与 Python 的差别
  只在字符串怎么拼，落到 SQL 是同一句 ⇒ 形态按 **SQL 拼接位置**划分。样本 15 → 19 条。
  **CI 实测：直连上界 7/15 → 10/19**；新形态 4 条里 3 条打穿（like 的两条 + `ORDER BY` 的
  报错取数 —— **排序位置不是安全位置**）；真机**打穿**插件**仍只有 1 个** `unionvaluesrow`
  （2/19，其直连上界 10/19 ⇒ 2/10），**放行** PL1/PL3 各 **25** 个；0 误拦。
  ⚠️ **形态变多 ≠ 绕过链变多**：本轮改善的是「尺子」（分母 7→10、靶点 3→5 类），
  **没有发现任何新的打穿链**；分母仍只有 10 ⇒ **依旧禁止对外声明绕过率**。
  详见 [docs/WAF-真机对拍-2026-09-28.md](docs/WAF-真机对拍-2026-09-28.md) 第八节。
- ✅ **2026-10-04（第五轮）**：上界 10/19 固化；新增语义保持型变换 `scalarselectinline`
  （FROM-less 标量子查询内联，真 MySQL 实证报错逐字节一致）——真机 19 条全拦：
  **错误注入形态的指纹不止 SELECT**，单变换路线性价比证伪并留证。
- ✅ **2026-10-05（链对拍首发）**：modsec-live 从「单插件」升级为**「链」**对拍——引擎实际
  部署的是链，联合指纹效应首次被真机检验。7 条链的结果：**旧首选链
  `dash2hash×hexliterals` 真机 0 打穿 0 放行**（本地口径 tamper on 5/5 与真机天花板首次
  实测背离）；**`unionvaluesrow+dash2hash` 2/19 打穿**，是唯一真机有效的形态 ⇒ 推荐表
  已按真机证据重排（真机打穿链提为第一顺位）。定版表：
  [docs/WAF-真机链对拍-2026-10-05.md](docs/WAF-真机链对拍-2026-10-05.md)。
  ⚠️ 分母仍只有 10 ⇒ **维持禁止对外声明绕过率**；但「推荐链按真机证据排序、而非按本地
  自实现口径排序」自本轮起成立。
- `npm run waf-validate`（e2e/waf-lab，自写正则模拟器）的数字仅作插件自检，**禁止对外**。

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

> ⚠️ **口径沿革（2026-10-17 D91 推翻记录）**：上表 19/19 的原始证据为 2026-10-05 三轮复测
> （axios 1.18.1）。2026-10-17 全量 acceptance 实测 **18/19** —— D11-cookie 因 axios 1.20.0
> 同名大小写头合并行为变化出现**静默假阴性**（`--header "cookie:"` 双处存储被夹击，服务端
> 永远收到原值）。D91 已修复并复跑恢复 19/19；**现行结论以修复后复跑为准**
> （`e2e/redteam-lab/results-r2.json`，台账 `detect-benchmark-redteam-26-d91`），
> 旧三轮证据已按 §3.5 标 refuted。复跑命令：`node e2e/redteam-lab/run-scan.mjs r2`。

> docs/ 下文档的分组导航见 [docs/INDEX.md](docs/INDEX.md)（`npm run docs:index` 重新生成）。
> **2026-10-13 起分两层**：`docs/` 根只放**现行**文档（42 篇：设计/PRD/实测口径/手册/门禁纪律），
> 「某一天的评估、审计、批次战报」一律进 [docs/archive/](docs/archive/INDEX.md)（40 篇，含同系列
> 更晚一份的取代指向）。归档规则与"为什么不删"见该索引页首——归档 ≠ 删除，被证伪的旧结论原样留着。

### sqlmap 同题对照（定版：26 靶点 × 3 轮，2026-10-04）

```bash
# 先起靶场环境（常驻），再跑两侧多轮对照
node e2e/redteam-lab/env.mjs &
node e2e/redteam-lab/sqlmap-bench.mjs --runs=3      # sqlmap 侧
node e2e/redteam-lab/run-scan.mjs m1                 # 引擎侧默认档 × 3 轮（m2/m3 同）
node e2e/redteam-lab/strict-compare.mjs --runs=3     # 合并出定版表
```

| 指标（同分母：19 漏洞点 + 7 安全点） | sqli-scanner（默认档） | sqlmap 1.10.7（--level 1 --risk 1） |
|---|---|---|
| 漏洞检出 | **19/19** | 16/19 |
| 安全点误报 | **0/7** | **6/7**（F18-F22、F24 全部 3/3 轮稳定误报） |
| 命中场景中位耗时 | **0.7s** | 21.7s |

- 双方各跑 3 轮，检出取多数决、耗时取中位；**两侧结果全部逐轮稳定（零抖动）**。
- 引擎 19/19 为 2026-10-05 修复 cookie 点位生成门（testHeaders 显式开启时任档位生效）
  后的三轮复测；修复前 18/19（D11-cookie 与 sqlmap 同漏，见 CHANGELOG 批次 D6）。
- **该表数字已于 2026-10-17 经 D91 推翻重做**：10-17 acceptance 实测 18/19（axios 1.20.0
  同名大小写头合并致 D11-cookie 静默假阴性），D91 修复后复跑恢复 19/19。
  **引用本表时以 D91 修复后复跑（`results-r2.json`）为准**；10-05 三轮证据台账标 refuted。
  耗时中位 747ms/0.7s 未随 D91 重测，**不再对外引用**。
- 引擎的差异化能力点：`E15-second-order`（二阶跨角色）引擎 3/3 检出、sqlmap 0/3。
- 引擎的差异化能力点：`E15-second-order`（二阶跨角色）引擎 3/3 检出、sqlmap 0/3。
- 完整逐靶点表与轮次明细：`docs/sqlmap-benchmark/redteam-strict-runs3.md`（由
  `strict-compare.mjs` 从双侧多轮原始结果合成，可复现）。

口径边界：SQLite 靶场 + 浅档对照（引擎侧刻意不用 R2 高档结果参与对比，档位须与
sqlmap --level 1 对等）。已作为 `redteam` 套件纳入 `npm run acceptance`（需先起靶场；
CI 里起不来则按 SKIP 处理，不假绿）。

### 接口靶场（`npm run e2e:api-range`）

其余 e2e 大多 `import ScanManager` 直接驱动引擎 —— 那验证的是**引擎**；这一套只走 HTTP，
逐条核「接口有没有把能力交付到用户手上」。它自带一套真实靶场：
真 MySQL 8.0.28（隔离沙箱）+ mysql2 直连靶站（url/body/cookie/header 四类注入位 + 会话依赖端点 +
可"打补丁"开关）+ 本地 OpenAI 兼容假端点（AI 报告那条外发链路）。

44 条用例覆盖 26 个端点：扫描生命周期（含 SSE 断线重连回放、暂停/续跑、停止三态、单点复测、
diff、7 种导出格式）、三条入参路径、枚举/拖库、直连模式、四条利用动作（真库回显 / 真文件读写 /
OS 能力缺失时如实失败）、sqlmap 入口、AI 三角色流水线与降级、鉴权与 CSRF/415/413 闸门、
以及台账历史（`GET /api/scans`、上下文回收后回读）。

判据纪律与验收门禁一致：**接口自报的布尔值不算证据**。暂停是否生效看靶站侧请求计数是否冻住、
重测是否只打一个点看靶站收到的参数、凭据是否继承看受保护端点的 `authOk/authDenied` 计数、
导出是否成产物看 Content-Disposition 与正文字节。台账写到 `logs/api-range-ledger/`（不污染仓库台账）。

```bash
npm run e2e:api-range                       # 全套（需要隔离 MySQL 沙箱，见 e2e/udf-lab/.mysql-sandbox）
node e2e/api-range-lab/run.mjs --groups=meta,gates   # 只要无库依赖的两组（秒级）
node e2e/api-range-lab/run.mjs --list        # 列出全部用例
```

最近一次真机结果（2026-09-28，本机沙箱 MySQL 8.0.28）：**44/44 PASS，21.6s**，退出码 0。
它同时是 `npm run e2e:run-all` 里的 `api-range-lab` 一项（依赖 `sandbox`，缺沙箱则如实 SKIP）。

### 验收门禁（`npm run acceptance`）

21 套件一次跑完（顺序即 `e2e/acceptance.mjs` 里 SUITES 的登记顺序）：服务端单测 → 独立刁钻靶场 →
检测回归 → 真 MySQL → 参数名注入真靶场（键名拼 SQL：检出 + 白名单对照 + 开关语义）→
参数挖掘真靶场（隐藏参数只能字典挖掘：开挖掘 3/3 检出 + 关 0 + 安全点 0）→ 真 PG（含二阶）→ **批量编排故障隔离（`-m`，真 SQLite 靶站 + 死目标）** → OOB 带外通道真机 →
OOB 外部隧道真机（interactsh 协作端，需出网，离线 SKIP） →
**第三方真框架外部裁判（Juice Shop：真漏洞须检出 + 安全端点零误报，未就绪 SKIP）** →
**登录编排自动重登（真表单登录 + 会话反复过期，含对照组）** → 报告契约 → CRS 人工挂链 A/B →
CRS 自动选链绕过 → CRS 执行器保真度（官方回归集）→ WAF 定向变异搜索（A2）端到端 →
WAF 通道降级编排（A3）端到端 → 红队实战（真值对照 + sqlmap 同题）→ fileRead 真闭环 → fileWrite 真闭环。

**判定纪律（关键）**：门禁**不采信任何套件自报的 PASS 字样**，只解析可独立核对的事实数字
（漏洞场景数 / 安全误报数 / 技术位 / 文件是否真的存在），据此断言并决定退出码。

制定这条纪律的原因：项目曾出现五类缺陷，全部位于**组件接缝**处，共同病征是
「中间层自报成功、无人校验外部事实」——`wrote:true` 但文件不存在、探针发出但无闭合、
靶场存在却因硬编码端口跑不起来。**覆盖率不等于有效性**。

```bash
npm run acceptance                  # 全量（约 8 分钟）
npm run acceptance -- --skip-heavy  # 跳过最慢的 CRS 组
npm run acceptance -- --only=waf-auto,waf-real   # 改完某模块做定向门禁
npm run acceptance:sandbox          # 同全量，但套隔离 MySQL 沙箱（3308）——宿主无 3306 MySQL 时的推荐跑法
```

- 依赖缺失时输出 **SKIP + 原因**（不静默跳过、不假装通过）；任一必需套件失败 → 非零退出码。
- 报告落盘 `e2e/results/acceptance-report.md`。
- [2026-10-02 实测] `acceptance.mjs` 本就读 `MYSQL_HOST/PORT/USER/PASSWORD` 环境变量，
  经 `run-with-sandbox.py` 注入沙箱连接信息后 16/16 全绿（含 fileRead/fileWrite 真闭环，
  secure_file_priv 由沙箱放行）；直连宿主的旧口径在 3306 无 MySQL 时会把 6 个套件 BLOCKED。

**最近一次全量结果（2026-09-20 01:00，本机：MySQL 8.0.28 @3306 + 红队靶场 @8231 均在线）**：
**12 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP**（12 套件全绿；改到盲注提取链路后复跑仍全绿）

| 套件 | 事实 |
|---|---|
| 服务端单测 | 1896 tests / 1895 pass / 0 fail / 1 skip（skip 为环境依赖显式跳过） |
| 独立刁钻靶场 | 10/10 检出，安全误报 0 |
| 检测回归 | 19 PASS / 0 FAIL |
| 真 MySQL / 真 PG（含二阶） | 10 PASS / 全部通过（PGlite） |
| 报告契约 | 8 项一致 / 0 不一致 |
| CRS 人工挂链 A/B（PL1） | off 8 / on 8，安全对照零误拦 |
| CRS 自动选链（PL1） | 技术位 8，安全误报 0 |
| CRS 执行器保真度（官方回归集｜族 942） | 保真度 **99.6%**，未点名分歧 **0**，已消失 0，误触 2 |
| 红队实战评测（真值对照） | 19/19（100%），安全点 7，误报 0（D91 修复后 10-17 复跑；期间曾因 axios 1.20 回归至 18/19，见 CHANGELOG D91） |
| fileRead / fileWrite 真闭环 | PASS（文件落盘=true，隔离沙箱重试） |

> ⚠️ **误报率的证据边界（2026-10-09 补，2026-10-13 更正）**：上表的「误报 0 / 19/19」全部产自**自建靶场**
> （`e2e/` 下 37 个靶场）。**第三方卷子 = 0**：本节此前写「唯一第三方卷子是 `sqli-labs`」，
> 那次核对错了对象 —— `e2e/sqli-labs/` 里躺着的是本项目自己写的 223 行 Python 复刻
> （`sqli-labs.py`，http.server + SQLite，runner 直接 spawn 它），不是上游那个 PHP+MySQL 仓库；
> 同目录的 sqlmap 对照（`e2e/sqlmap-benchmark/run.mjs`）双方跑的就是这个复刻靶站，所以它是
> **「同一自建靶场上的双方同题对照」，不是外部真值**。⇒ 该数字**不可外推为通用误报率**。
> **未在任何第三方复杂应用上验证**（DVWA / Juice Shop / OWASP Benchmark 一类「真框架 +
> 真 ORM + 复杂拼接」）。WAF 侧同理：只验了 ModSecurity+CRS 一家。

**本轮 0 FAIL。** 此前两轮 FAIL 的定位与修复（CRS 执行器 `(?i:…)` 兼容性、`engine.e2e` 环境耦合假红）、
「11 PASS / 0 SKIP 假绿」事故、门禁自身的两处缺陷修复与缺陷注入验证记录，已迁至
[docs/验收门禁-判定纪律与事故记录.md](docs/验收门禁-判定纪律与事故记录.md)。

### 利用能力实测口径（2026-09-10 起）

| 能力 | 状态 | 依据 |
|---|---|---|
| **fileRead（MySQL）** | ✅ **已跑通真实闭环** | HTTP 注入点 → UNION 注入 → `LOAD_FILE` → 内容回传，与自备标记文件**逐字节一致**。复现：`npm run e2e:file-read` |
| **fileWrite（MySQL）** | ✅ **已跑通真实闭环** | HTTP 注入点 → `INTO OUTFILE` → **文件系统侧确认落盘**（含注入标记）。复现：`npm run e2e:file-write` |
| **UDF / os-shell** | ✅ **已跑通真实闭环**（隔离沙箱内） | HTTP 注入点 → `CREATE FUNCTION ... SONAME` 注册 → `sys_eval` 执行命令 → 输出回传，与标记**逐字符一致**；`mysql.func` 表独立复核。复现：`python e2e/udf-lab/sandbox.py --script udf-takeover.e2e.mjs --allow-command-exec` |
| 注册表 | ⚠️ 实验特性，未真实验证 | 仍只有 mock 单测 |

**UDF 接管：验证环境与边界（2026-09-18 起，如实说明，勿夸大）**：验证在 `e2e/udf-lab/` 内的
隔离 MySQL 实例（独立 datadir + 端口 3308 + secure_file_priv/plugin_dir 双锁，用完即毁）中运行，
沙箱隔离边界 5/5、负向拦截 7/7、直连基线 6/6、经注入通道注册与 `sys_eval` 执行命令均 PASS；
沙箱能力边界与「仍未复现：经 SQL 通道投递 DLL 本体」的说明见
[docs/udf-沙箱验证环境与边界.md](docs/udf-沙箱验证环境与边界.md)。

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

**真实 ModSecurity 已实测**：CI `modsec-live` job 每轮 dispatch 起官方 `owasp/modsecurity-crs:nginx`
镜像（真 ModSecurity + libinjection）跑 PL1/PL3 双档，真机报告见
[docs/WAF-真机对拍-2026-09-28.md](docs/WAF-真机对拍-2026-09-28.md)（最新一轮：19 样本、直连上界
10/19、真机打穿链 **1 个**）。镜像 tag **未钉死 ⇒ CRS 版本逐轮记录在报告里**（09-28 起 4.29.0，
D14 轮起 4.30.0）；跨轮数字比较前先确认同镜像 digest。**未实测的是 Coraza 与商业云 WAF** ——
本节自实现执行器口径的数字不能外推到它们。
复现：`MYSQL_PORT=3306 node e2e/waf-real/waf-verify.mjs`（人工挂链 A/B）与
`node e2e/waf-real/waf-auto-check.mjs`（自动路径验收）。
- 直连模式（对标 sqlmap -d）：支持 SQLite 直连（sql.js）+ 真实驱动注册接口（mysql2/pg/mssql/oracle 等需用户自备）

## 贡献

详见 [CONTRIBUTING.md](CONTRIBUTING.md) — 包含项目结构、开发环境、代码规范、引擎架构要点和提交规范。