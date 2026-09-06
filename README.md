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
| **18 种数据库** | MySQL / PostgreSQL / SQL Server / Oracle / SQLite / MariaDB / TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / H2 / Access / HSQLDB / Derby / MonetDB | 3 种真实验证，15 种最小适配 |

> 数据库支持说明：**MySQL / PostgreSQL / SQLite 经 recall-lab 18 场景真实引擎验证**（SQLite WASM、PGlite、MariaDB 便携）。其余 15 种有检测/提取模板但未经真实 DBMS 验证，方言可能有偏差。|
| **1870+ 条 payload 模板** | 含注释/编码/子句/嵌套闭合变体（1779 主库 + 82 子句 + 14 OOB）+ 672 条声明式注册表 |
| **225 个 tamper 插件** | WAF 绕过，覆盖 sqlmap 官方 tamper 全集（84/84） |
| **62 WAF 指纹** | 自动识别 WAF 类型并推荐 tamper 组合 |
| **可视化报告** | 风险环形图 + 技术分布条形图 + 漏洞列表 + 数据提取树 + 检测摘要 |
| **深度提取** | 分页聚合数据提取，绕过 UNION 限制 |
| **AI 漏洞报告** | 3 角色流水线（分析师→撰写→审阅），支持多 key 容灾，自动生成专业中文安全分析报告 |
| **利用工具** | SQL Shell / 文件读写 / OS 命令执行（需授权） |
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
- 直连模式（对标 sqlmap -d）：支持 SQLite 直连（sql.js）+ 真实驱动注册接口（mysql2/pg/mssql/oracle 等需用户自备）

## 贡献

详见 [CONTRIBUTING.md](CONTRIBUTING.md) — 包含项目结构、开发环境、代码规范、引擎架构要点和提交规范。