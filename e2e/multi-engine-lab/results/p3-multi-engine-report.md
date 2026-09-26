# P3 多引擎真实验证报告：tamper 链接真实数据库引擎 × CRS v4.1.0

> 生成：2026-09-09 ｜ 实验设施：e2e/multi-engine-lab（新增）｜ WAF：OWASP CRS v4.1.0 官方规则 + 自实现执行器 ≈PL3
> 引擎运行时：JDK Temurin 17.0.20.1（清华镜像）+ Maven Central 官方 jar；MariaDB 11.4.13 便携版（清华镜像）

> ⚠️ **本报告的核心数字已被自己的复跑推翻（2026-09-25 标注，保留原件）**
> 下面那张「H2 / Derby：tamper off `0` → on `error`」的表，今天用同一靶场复跑**一个都不再出现**
> （见同目录 `multi-engine-report.md`：3 引擎 × 3 场景 × tamper 两侧 = 0/9 全空）。
> 归因不是"检测能力退步"：09-09 之后 CRS 执行器改过保真度（`t:urlDecodeUni` 把 `+` 折成空格、
> PL 区块截断、FILES 取值停止预解码），拦截强度已经不是当天那把尺子，两边的数字不可互引。
> **现在这份设施能支撑的只有两档口径**：无 WAF 档（覆盖面与定库：H2/HSQLDB 成功、**Derby 定不出**）
> 与 CRS ≈PL3 档（0/9，只证明 safe 零误报）。README 的「部分通道验证」一栏已按此改写。
> 本文件继续入库，是为了留住"当时确实看到过 error 通道"这条观察——它记录的是那天的实验，不代表现在成立。

## 一、验证目标

P2 已证明 dash2hash tamper 链在 MySQL 8.0.28 上可绕过严格 CRS。P3 将同一条 tamper 链
链接到**更多真实数据库引擎**，验证两件事：

1. **检测可达性**：引擎 payload 模板（此前仅"最小适配"未经真库验证）在真实引擎上是否语法正确、可检出；
2. **方言正确性**：dash2hash 的 `#` 注释是 MySQL 系方言——方言门控 `dbms:['MySQL','MariaDB','TiDB']`
   是否真实挡住了不认 `#` 的引擎（防止"绕过成功但 SQL 无效"的静默假阳性）。

## 二、新增真实引擎清单（本轮拉起 4 个，全部真实运行）

| 引擎 | 版本 | 获取方式 | 接入方式 |
|---|---|---|---|
| MariaDB | 11.4.13 | 便携 zip（清华镜像） | mysql2 驱动 @3308，复用 real-mysql-lab 靶场 |
| H2 | 2.2.224 (MODE=MySQL) | Maven Central jar | EngineBridge（JVM 常驻子进程） |
| HSQLDB | 2.7.3 | Maven Central jar | EngineBridge |
| Derby | 10.16.1.1 | Maven Central jar（+derbyshared） | EngineBridge |

加上 P2 已验证的 MySQL 8.0.28，**真实引擎验证覆盖 3 → 5 种**（MySQL/MariaDB/PG/SQLite + H2），
H2/Derby/HSQLDB 属 15 个"最小适配"库中首次接入真实引擎。

## 三、A/B 实测结果（tamper off vs tamper on=dash2hash）

### MariaDB 11.4.13（与 MySQL 8.0.28 同构矩阵，可横向对比）

| 场景 | tamper off | tamper on | 结论 |
|---|---|---|---|
| num | boolean | boolean | — |
| str | **- 全拦** | **boolean** | ↑ 绕过生效 |
| like | **- 全拦** | **boolean** | ↑ 绕过生效 |
| orderby | **- 全拦** | **error,boolean** | ↑ 绕过生效 |
| blind | boolean | boolean | — |
| 安全对照 | 零误报 | 零误报 | ✅ |

**tamper off 2/5 → tamper on 5/5，与 MySQL 8.0.28 表现完全一致**（dash2hash 的 dbms
白名单含 MariaDB，方言适配正确生效——MariaDB 认 `#` 注释）。

### Java 引擎（H2 / HSQLDB / Derby，EngineBridge 桥接）

| 引擎 | num off→on | str off→on | blind off→on | 说明 |
|---|---|---|---|---|
| H2 (MODE=MySQL) | 0→error | 0→error | 0→0 | tamper on 打通 CRS 后 error 通道检出 |
| Derby | 0→error | 0→error | 0→0 | 同上 |
| HSQLDB | 0→0 | 0→0 | 0→0 | **负结果（预期内，见下）** |

安全对照（/safe 参数化端点）：三引擎全部零误报 ✅

## 四、关键发现

### 1. HSQLDB 零检出是方言门控的"诚实负结果"，不是失败

HSQLDB 不支持 `#` 行注释。扫描时 dbms 未知（指纹未定），ctx.dbms 为 null → 方言门控
不生效 → dash2hash 照常把 `--` 改成 `#` → HSQLDB 收到语法错误 → 真假条件同构 → 零检出。
这正是 P3 要验证的核心风险：**tamper 在方言不匹配的引擎上会把"可检出"变成"静默零检出"**。
处置方向（后续优化）：HSQLDB/Derby 走各自 error 指纹定库后，dash2hash 被告警跳过，
payload 保持 `--` 原形（`--` 对 CRS 的 942460 仍是 4 连非词字符，可换 space2plus 等不依赖注释方言的变形）。

### 2. H2/Derby 的 error 通道首次真实验证

tamper on 打穿 CRS 拦截墙后，引擎的报错指纹（H2 `[42104-224]` 表不存在、Derby `does not exist`）
被 ErrorDetector 正确识别——15 个"最小适配"库中，**H2/Derby 的报错签名首次在真实引擎上确认有效**。

### 3. 工程资产沉淀

- `e2e/multi-engine-lab/EngineBridge.java`：JVM 常驻桥（行协议 `\t` 分隔），单连接懒加载 +
  INITED 集合修复建表时机；Derby 10.16 须补 `derbyshared.jar` 且走 JDBC 4 SPI 自动加载。
- `e2e/multi-engine-lab/lab-app.mjs`：多引擎靶场（num/str/blind/safe 四端点 + CRS 中间件）。
- `e2e/multi-engine-lab/verify.mjs` + `mariadb-verify.mjs`：两套 A/B 驱动，结果落盘 results/。
- 引擎产物位置：D:\engines\（jdk-17.0.20.1+1、jars/、mariadb-11.4.13-winx64、mariadb-data）。

## 五、15 库验证状态总表（P3 后）

| 状态 | 引擎 |
|---|---|
| ✅ 真实引擎验证（5） | MySQL 8.0.28、PostgreSQL(PGlite)、SQLite(sql.js)、MariaDB 11.4.13、H2 2.2.224 |
| ⚠️ 本轮桥接验证（3） | Derby 10.16.1.1、HSQLDB 2.7.3（桥接检出/方言负结果已确认）、MySQL 3307 复测 |
| ❌ 未真实验证（10） | SQL Server、Oracle、TiDB、DM8、ClickHouse、DB2、Sybase、Firebird、Informix、Access、MonetDB |

未验证 10 库中：Oracle/SQL Server/DM8 商业库需授权安装；ClickHouse/MonetDB 可后续照
EngineBridge 模式接入（均有官方可执行发行版）；Access 无跨平台引擎，可能永久保持模板态。

## 六、诚实边界

- CRS 执行器仍是自实现（≈PL3，无 libinjection），绕过率相对真实部署偏高；
- Java 引擎桥的 blind 场景 0 检出属实验设施限制（EngineBridge 无事务级延迟原语），
  非引擎 payload 缺陷；
- H2 以 MODE=MySQL 运行，其 `#` 注释能力来自兼容模式而非原生方言。
