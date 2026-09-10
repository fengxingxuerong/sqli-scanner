# sqli-scanner

[![CI](https://img.shields.io/github/actions/workflow/status/OWNER/REPO/ci.yml?branch=main&label=CI)](https://github.com/OWNER/REPO/actions)
[![ Tests](https://img.shields.io/badge/tests-1440%20passing-brightgreen)](#测试)

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

## 功能

| 功能 | 说明 |
|------|------|
| **一键扫描** | 输入 URL → 点击开始 → 查看报告 |
| **9 种检测技术** | union / error / boolean / time / stacked / oob / second_order / inline / nosql |
| **18 种数据库** | MySQL / PostgreSQL / SQL Server / Oracle / SQLite / MariaDB / TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / H2 / Access / HSQLDB / Derby / MonetDB | **4 种真实引擎全链路验证 + 3 种部分通道验证 + 11 种模板适配**（分层见下） |

### 数据库支持验证等级（2026-09-10 复核，按证据分层）

> 口径修正：此前 README 写「3 种真实验证，15 种最小适配」——**低估了自身**：仓库中实际存在
> **7 种引擎**的真实验证记录（含 MariaDB 11.4.13、H2、HSQLDB、Derby 真引擎）。现按证据强度重列，
> 等级与 evidence 由 `server/src/engine/dbmsEvidence.js` 统一维护，并**写入每次扫描报告的
> `summary.dbmsEvidence`**（交付时客户可自行判断结论可信度，不必翻 README）。

| 等级 | 方言 | 证据 |
|---|---|---|
| ✅ **真实引擎验证**（检测/绕过主链路跑通） | MySQL、MariaDB、PostgreSQL、SQLite | 真 MySQL 8.0.x（`e2e/real-mysql-lab` + `e2e/waf-real`）、真 MariaDB 11.4.13（`e2e/multi-engine-lab/mariadb-verify.mjs`）、PGlite 18.3、sql.js WASM |
| ⚠️ **部分通道验证** | H2、HSQLDB、Derby | `e2e/multi-engine-lab`（真实 JDBC 内存库，仅布尔通道 × CRS） |
| ⛔ **模板适配（未在真实 DBMS 验证）** | SQL Server、Oracle、TiDB、DM8、ClickHouse、DB2、Sybase、Firebird、Informix、Access、MonetDB | 仅有检测/提取模板；方言语法、列类型、报错文本均可能有偏差 |

**给客户的话**：若目标是 ⛔ 等级中的数据库（尤其 SQL Server / Oracle 这类主流库），
请把结论视为**待复核线索**而非可用证据——报告会在 `summary.dbmsEvidence.caveat` 中自动声明这一点。
| **1870+ 条 payload 模板** | 含注释/编码/子句/嵌套闭合变体（1779 主库 + 82 子句 + 14 OOB）+ 672 条声明式注册表 |
| **225 个 tamper 插件** | 覆盖 sqlmap 官方 tamper 全集（84/84）。⚠️ 绕过率口径见下文「WAF 绕过能力实测口径」 |
| **62 WAF 指纹** | 自动识别 WAF 类型并推荐 tamper 组合 |
| **可视化报告** | 风险环形图 + 技术分布条形图 + 漏洞列表 + 数据提取树 + 检测摘要 |
| **深度提取** | 分页聚合数据提取，绕过 UNION 限制 |
| **AI 漏洞报告** | 3 角色流水线（分析师→撰写→审阅），支持多 key 容灾，自动生成专业中文安全分析报告 |
| **利用工具** | SQL Shell / 文件读写 / OS 命令执行（需授权）。⚠️ 验证状态见下文「利用能力实测口径」：**fileRead 已跑通真实闭环**，其余仍为 mock 单测 |
| **CLI 55+ 参数** | 对标 sqlmap：--dbs/--tables/--dump/-D/-T/-C/--search/--users/--passwords/--prefix/--suffix/--time-sec/-r/--mobile/--parse-errors/--safe-url/--safe-freq/--csrf-url/--csrf-token/--delay/--eval/--current-user/--current-db/--hostname/--is-dba/--identify-waf/--skip-urlencode/--skip-static/--keep-alive/--null-connection/--predict-output 等 |
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
| `SCAN_API_TOKEN` | 无 | API 认证 Token |
| `EXPLOIT_ENABLED` | `0` | 开启利用能力（=1 启用） |
| `ALLOWED_ORIGINS` | `http://localhost:5173` | 跨域白名单 |

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
# 前端测试（191 个用例）
npm test

# 服务端测试（1249 个用例）
cd server && npm test

# 全部测试
npm run test:all
```

## 项目状态

- TypeScript: 零错误
- 前端测试: 191/191 通过
- 服务端测试: 1249/1249 通过
- Tamper 插件: 225 个（含 v24 增量 20 个，对齐 sqlmap 官方 tamper 全集，含官方 CRS/libinjection 实测组合 uniontable+odbcbrace）
- WAF 绕过能力: 200+ 插件链式组合，覆盖 62 个 WAF 厂商指纹识别 + 推荐

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

### 利用能力实测口径（2026-09-10 起）

| 能力 | 状态 | 依据 |
|---|---|---|
| **fileRead（MySQL）** | ✅ **已跑通真实闭环** | HTTP 注入点 → UNION 注入 → `LOAD_FILE` → 内容回传，与自备标记文件**逐字节一致**。复现：`npm run e2e:file-read` |
| fileWrite / UDF / os-shell / 注册表 | ⚠️ **实验特性，未真实验证** | 仍只有 mock 单测；能力矩阵按 DBMS 文档声明，未在任何真实库跑通 |

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