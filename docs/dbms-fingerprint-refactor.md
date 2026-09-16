# 定库通道重构方案（DBMS Fingerprint Refactor）

> 状态：**设计稿，未实施**　编写：2026-09-16　依据：`e2e/blackbox-lab` 独立黑盒评测
>
> 本文档只出设计，不动代码。实施前请先读完「影响面」与「风险」两节。

---

## 1. 背景：问题不是"某个 sig 写错了"

`e2e/blackbox-lab/check-dbms-sig.mjs` 首跑结果（判据：**某库的典型返回值只能命中它自己的 sig**）：

```
sig 冲突（同一返回值命中多个库）: 20 处
sig 漏检（自己的值都命不中）:    2 处
```

| 返回值（库） | 命中 sig 数 | 被误判为 |
|---|---|---|
| `8.0.28`（MySQL） | **6** | SQLite, ClickHouse, Firebird, H2, MonetDB |
| `3.45.1`（SQLite） | **6** | MySQL, ClickHouse, Firebird, H2, MonetDB |
| `23.8.1.1`（ClickHouse） | 5 | MySQL, Firebird, H2, MonetDB |
| `Oracle Database 19c …Release 19.0.0.0.0` | 2 | Sybase（`/ASE/i` 命中 "Rel**ease**"） |

**两个根因簇**：

1. **纯版本号不可区分** —— 各库版本号格式天生雷同（`X.Y.Z`），
   用 `/^\d+\.\d+\.\d+/` 做签名在原理上就不成立。
2. **裸短签名到处命中** —— `/ASE/i` 会命中 "Release"、`/H2/i` 会命中任意含 "h2" 的串。
   这与项目早先踩过的「Sybase `/ASE/i` 误命中 `BaseHTTP` **是同一个坑**」。

**实测后果**：真 MySQL 8.0.28 被判为 DB2（`e2e/blackbox-lab` 靶场），
进而 payload 族错配 —— **定库错了，后面全错**。

---

## 2. 设计判据

> **判别必须基于「引擎行为是否存在」，而不是「返回文本长什么样」。**

理由：函数**能否执行**是布尔量，没有"格式雷同"的问题；
而文本匹配永远面临"不同库返回相似文本"与"短签名误伤"两个无法根治的坑。

---

## 3. 目标架构：三层，逐层降级

| 层 | 手段 | 性质 | 处理 |
|---|---|---|---|
| **L1** | 响应头特征（`FINGERPRINT`，17 条） | 强判别 | **保持不变**，命中即定库 |
| **L2** | **特有函数可执行性** | 强判别（新增） | 本方案核心 |
| **L3** | 文本 sig（收紧后） | 弱判别（兜底） | 只保留含**唯一产品词**的条目 |

### L2 机制

```sql
-- 探针：把「该库特有的函数/伪列」放进回显列，用标记包裹
<orig><boundary> UNION SELECT CONCAT('__S__', <expr>, '__E__'), NULL, …-- -
```

- **能取到 `__S__…__E__` 标记** → `expr` 在该引擎上可执行 → 命中该库
- **函数不存在** → SQL 报错 → 无标记 → 不命中（**天然互斥**）

> 关键约束：**`expr` 必须是该库（族）特有的**。
> 通用函数（`version()`、`@@version`）**不得进 L2** —— 多库都能执行，
> 放进来只会制造新的"多命中"。

### L2 探测表（草案，可信度如实标注）

| 库 | L2 特有 expr | 可信度 | 备注 |
|---|---|---|---|
| SQLite | `sqlite_version()` | 高 | SQLite 专有 |
| MySQL | `@@version_comment` | 高 | 返回含 "MySQL Community Server" |
| MariaDB | `@@version_comment` | 高 | 与 MySQL 同函数，**族内靠 L3 文本**区分 |
| TiDB | `@@version_comment` | 中 | 返回含 "TiDB"；待真机确认 |
| PostgreSQL | `version()` | 高 | 返回以 "PostgreSQL " 开头，**唯一前缀** |
| SQL Server | `@@version` | 高 | 含 "Microsoft SQL Server" |
| Sybase | `@@version` | 高 | 含 "Adaptive Server" |
| Oracle | `(SELECT banner FROM v$version WHERE rownum=1)` | 高 | v$version 为 Oracle 专有视图 |
| DM8 | 同 Oracle 路径 | 中 | banner 含 "DM Database"；与 Oracle **族内靠 L3 区分** |
| H2 | `H2VERSION()` | 高 | H2 专有函数 |
| HSQLDB | `DATABASE()` | 中 | 待真机确认 |
| Derby | `SYSCS_UTIL.SYSCS_GET_DATABASE_VERSION()` | 高 | Derby 专有系统函数 |
| Firebird | `rdb$get_context('SYSTEM','ENGINE_VERSION')` | 高 | Firebird 专有上下文 |
| Informix | `DBINFO('version','full')` | 中 | 待真机确认 |
| MonetDB | `(SELECT sys_version FROM sys.version)` | 高 | MonetDB 专有系统视图 |
| DB2 | `CURRENT SERVER` | 高 | DB2 专有伪列 |
| ClickHouse | `currentDatabase()` | **待研究** | CH 有 `currentDatabase()`；需确认回显限制 |
| Access | **待研究** | **未知** | Access 无标准系统函数表，可能只能留在 L3 |

### L3 收紧规则

保留条件（**全部满足**才留在文本通道）：

1. sig 必须含**产品名或产品专有词**（如 `PostgreSQL`、`Adaptive Server`、`DM Database`）；
2. **禁止**纯版本号模式（`/^\d+\.\d+/`、`/^\d+\.\d+\.\d+$/`）—— 这类一律迁往 L2；
3. **禁止**长度 ≤3 的裸短签名（`ASE`、`H2`）—— 必须带词边界或上下文（`\bASE\b` 仍不够，
  需 `Adaptive Server` 这类完整词）；若无法满足，迁往 L2 或删除。

---

## 4. 影响面

**引用 `DB_VERSION` 的位置（实测，共 8 处）**：

| 文件 | 影响 |
|---|---|
| `server/src/engine/payloads/index.js` | 定义处 —— 表结构改造 |
| `server/src/engine/DBFingerprinter.js` | 通道 4 判定逻辑 —— 主改点 |
| `server/src/engine/dbmsVersion.js` | 版本解析 —— 需兼容新返回形态 |
| `server/src/engine/extractionMaps.js` | 读取方言映射 —— 预期零改动（只读 key） |
| `tests/dbmsExtend.test.js` / `dbmsExtend6.test.js` | 需同步改断言 |
| `tests/fingerprint.mariadb.test.js` | **必须零回归**（MariaDB 是真机验证过的） |
| `tests/payloads.test.js` | 表结构断言需同步 |

**能力影响**：
- **7 个真机验证库**（MySQL / MariaDB / PostgreSQL / SQLite / Oracle / SQL Server + WAF 场景）
  → **必须零回归**，实施后逐个跑真靶场。
- **11 个未验证库** → L2 的 expr 基于文档推断，**标注"待真机确认"**；
  若写错只导致"该库定不回来"（**漏检**），不会误判 —— 比现状（必然误判 DB2）好。

---

## 5. 分阶段实施（每阶段独立可回退）

### 阶段 1 —— 只增不改（并行通道）

- 新增 `DB_PROBE` 表 + L2 通道，**插在现有通道 4 之前**；现有 L3 逻辑**原样保留**。
- 验证：真机 7 库靶场零回归；黑盒靶场应判 MySQL。
- 回退：删新增通道即可。

### 阶段 2 —— L3 收紧

- 移除纯版本号与裸短签名条目（依赖阶段 1 已能覆盖）。
- 验证：`check-dbms-sig.mjs` 冲突数 → 0；真机 7 库再跑一遍。
- 回退：`git revert` 该提交。

### 阶段 3 —— 挂 CI 门禁

- `check-dbms-sig.mjs` 纳入 CI（当前**非绿，故尚未纳入**）。
- 建议同时把「每库典型返回值只命中自己」作为**新库准入条件**写进 CONTRIBUTING。

---

## 6. 验证计划

| 层次 | 手段 | 通过标准 |
|---|---|---|
| 静态 | `check-dbms-sig.mjs` | 冲突 0、漏检 0 |
| 单测 | `server/tests`（含 4 个 DB_VERSION 相关） | 全绿 |
| 真机 | `e2e/real-mysql-lab`、`multi-engine-lab`（H2/HSQLDB/Derby）、`oracle-lab`、`mssql-lab` | 7 库判定与实施前一致 |
| 黑盒 | `e2e/blackbox-lab/run-scan.mjs` | MySQL 判 MySQL（现状为 DB2） |
| 回归 | 同点连跑 5 次 | 无偶发变化 |

---

## 7. 风险与诚实边界

| 风险 | 应对 |
|---|---|
| 特有函数名写错 → 该库漏检 | 保守可接受（现状是误判）；保留 L3 兜底；标"待真机确认" |
| 未验证库无法真机验证 | 只用**官方文档明确的系统函数**；把握不足的（ClickHouse/Access）**宁可留在 L3** |
| 请求数增加 | 每点最多 +N 个探针（N=库数），与现有遍历同量级；可用「L1 命中即停」压缩 |
| 破坏已验证库 | 阶段 1「只增不改」+ 真机零回归作为硬门 |

**不在本方案范围内**（需另立项）：
- 响应头通道（L1）的 17 条签名同样存在裸短签名风险 —— 已修复过一轮（加 `\b`），
  但**未做区分度自检**，建议后续用同样的方法审一遍。
- 提取链完整性验证（`--dbs/--tables/--dump` 逐字比对）—— 独立的评测项。

---

## 8. 附：一句话总结

**别再问"这个库返回什么文本"，去问"这个库有没有这个函数"。**
前者是猜谜，后者是事实。
