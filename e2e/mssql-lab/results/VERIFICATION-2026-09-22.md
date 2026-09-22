# SQL Server / Oracle 真机验证报告（2026-09-22 补证）

> 背景：README 自 2026-09-14/15 起把 SQL Server 与 Oracle 列入「✅ 真实引擎验证」，
> 但仓库中**从未留下可复现的产物**（无 `results/`、无版本凭证），而 CI 上这两个靶场
> 因依赖本机安装的实例而**永久跳过**（`e2e-self-contained` 实测：未跑 16/24）。
> 本报告补上这批证据：**真机执行 + 版本凭证 + 产物留痕**。

## 环境凭证（外部事实，非自报）

| 项 | 实测值 | 取证方式 |
|---|---|---|
| SQL Server | `Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)` | `SELECT @@VERSION` |
| — Edition | `Express Edition (64-bit)`，实例名 `SQLI` | `SERVERPROPERTY('Edition'/'ProductVersion'/'InstanceName')` |
| — 端口 | `127.0.0.1:65039` | 靶场连接配置 |
| — 服务 | `MSSQL$SQLI` = Running | `Win32_Service.ProcessId` 对应 `sqlservr` |
| Oracle | `Oracle AI Database 26ai Free Release 23.26.3.0.0` | `SELECT banner_full FROM v$version` |
| — 服务 | `OracleOraDB23Home1TNSListener` = Running | 同上（`OraDB23` 是内核版本号，非产品名） |
| — 连接 | `127.0.0.1:1521/FREEPDB1`，`SYS` SYSDBA（thin 模式，无 Instant Client） | 靶场连接配置 |

> ⚠️ 口径说明：Oracle 服务名含 `OraDB23`，易被误读为「23c」；实际产品名是 **26ai**
> （`v$version` 的 banner 明确写 `Oracle AI Database 26ai Free`）。以 banner 为准。

## 执行结果（4/4 PASS）

| 靶场 | 结果 | 关键断言 |
|---|---|---|
| `e2e/mssql-lab/e2e.mjs` | ✅ PASS | `/num` 与 `/str` 双上下文均检出 `union/error/boolean`，定库 `SQL Server` |
| `e2e/mssql-lab/dump.e2e.mjs` | ✅ PASS | 枚举 `master,tempdb,model,msdb,sqli_lab_mssql`；拖 5/5 行，中文/单引号/跳号全对 |
| `e2e/mssql-lab/osshell.e2e.mjs` | ✅ PASS | `xp_cmdshell` 初始 0 → **auto-enable 真实覆盖** → 回显 `msshell_95203` 命中 → 收尾复原为 0 |
| `e2e/oracle-lab/e2e.mjs` | ✅ PASS | `/num`、`/str` 检出 `union/error/boolean`，定库 `Oracle`；拖库 5/5 行全对 |

产物：`e2e/mssql-lab/results/last-run{,-dump,-osshell}.md`、`e2e/oracle-lab/results/last-run.md`

> 注：产物用 `.md` 而非 `.log` —— 本仓 `.gitignore:10` 有全局 `*.log` 规则，
> `.log` 格式的证据**不会入库**（沿用既有靶场用 `.md`/`.json` 存证据的惯例）。

## 结论与边界

**可以确认**：SQL Server 与 Oracle 的**检测主链路 + 拖库正确性 + MSSQL os-shell** 已在真机跑通，
结论有版本凭证与产物支撑，不再属于「仅有模板适配」。

**仍不能声称**（诚实边界，勿夸大）：
- **OOB 带外**：SQL Server `xp_dirtree`、Oracle `UTL_HTTP` 模板**仍未真机验证**（本次未覆盖）。
- **等级库**：TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / Access / MonetDB
  仍为模板适配，未在真机验证。
- **CI 覆盖**：这两个靶场依赖本机安装的实例，**CI 上仍会 SKIP**（已在靶场加显式 SKIP 出口，
  不再误报为 FAIL）。要让它们进 CI，需要先做容器化改造（凭证/端口/连接方式参数化）。
