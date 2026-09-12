# e2e 靶场索引

> 一条命令看清全部：`node e2e/run-all.mjs --list`（含**依赖探测**：当前环境满足哪些、缺哪些）

## 统一入口

```bash
node e2e/run-all.mjs                          # 只跑「当前环境依赖满足」的靶场（推荐日常回归）
node e2e/run-all.mjs --list                   # 列出全部靶场 + 依赖状态，不执行
node e2e/run-all.mjs --only redteam-lab,retest-lab   # 指定靶场
node e2e/run-all.mjs --all                    # 强制全跑（缺依赖的会失败，但如实汇总）
```

设计取舍：默认**跳过缺依赖的靶场**，避免"跑一半全挂在环境缺失上"的噪音——
这也是本目录此前最大的使用痛点（15+ 个靶场各有入口/端口/依赖，逐个数容易漏、容易误判"全红"）。

## 环境准备

| 依赖 | 怎么起 | 说明 |
|---|---|---|
| **MySQL 8 + PostgreSQL 16.2 + 红队靶场** | `node e2e/redteam-lab/env.mjs` | 常驻脚本（单进程拉起三者，进程活着服务就活着）。⚠️ 跨会话后进程会被回收，需重跑 |
| **Java + 引擎 jar** | 本机 Temurin 21 + `D:\engines\jars\` | 多引擎靶场（H2/HSQLDB/Derby）用，无外部 DB 服务 |
| **MariaDB** | 需自备并监听 `3308` | `mariadb-verify.mjs` 用；**当前环境未装**，该项无法复现（见 `docs/dbms-验证复核-2026-09-12.md`） |

## 靶场清单

| 靶场 | 用途 | 入口 | 依赖 |
|---|---|---|---|
| `redteam-lab` | 红队评测：24 靶点（17 注入 + 7 安全对照）+ 真值自检 | `run-scan.mjs r2` / `selftest.mjs` | MySQL |
| `retest-lab` | 单点重测接口端到端（自起靶场，断言请求量收敛） | `verify.mjs` | 无 |
| `multi-engine-lab` | 多引擎 tamper A/B（真 JDBC：H2/HSQLDB/Derby） | `verify.mjs` | Java + jar |
| `mariadb-verify` | MariaDB 11.4 真实引擎 tamper A/B | `mariadb-verify.mjs` | MariaDB:3308 |
| `oob-real-lab` | OOB 带外全链路（PG `COPY TO PROGRAM` / MySQL UNC DNS） | `verify.mjs` | PG + MySQL |
| `real-mysql-lab` | 真实 MySQL 驱动靶场验证 | `verify.mjs` | MySQL |
| `waf-real` | 真实 CRS v4.1.0 规则绕过验证 | `selftest.mjs` | MySQL |
| `real-world-lab` | 拟真靶场（登录/搜索/上传等业务面） | `verify.mjs` | PGlite（内置） |
| `pentest-lab` | 渗透视角「刁钻场景」实测 | `verify.mjs` | MySQL |
| `recall-lab` | 假阳性验证（安全靶场零误报） | `false-positive.e2e.js` | PGlite |
| `tamper-matrix` | tamper × WAF 规则绕过矩阵 | `tamper-test.mjs` | 无 |
| `detection-runner` | 数据驱动检测测试 | `run.js` | 无 |
| `udf-lab` | UDF 接管真实验证（真 DLL） | `udf-takeover.e2e.mjs` | MySQL |
| `waf-lab` | WAF 规则对比实验 | `compare.e2e.js` | 无 |
| `sqli-labs` | sqli-labs 靶场适配与诊断脚本 | 各 `diag*.mjs` | 需 sqli-labs 环境 |

## 常用工具

| 工具 | 用途 |
|---|---|
| `redteam-lab/diff-reports.mjs <beforeDir> <afterDir> <ids>` | **行为等价性对比**：归一化时间戳/随机 id/请求数后比对两次扫描报告的结论字段。重构后证明"行为没变"用它，退出码可作 CI 门禁 |
| `redteam-lab/env.mjs` | 一键拉起 MySQL + PG + 靶场并常驻 |
| `redteam-lab/results/`、各靶场 `results/` | 报告落盘位置 |

## 约定

- **报告落 `results/`**，可被 git 跟踪（作为证据留存）。
- 涉及外部 DB 的靶场，凭据优先走**环境变量**（如 `LAB_DB_PASSWORD`、`MARIADB_PORT`），
  不要在脚本里硬编码——硬编码口令会让靶场换机器就莫名连不上（已踩过）。
- 新增靶场时，把条目加进 `run-all.mjs` 的 `LABS` 并声明 `deps`，否则统一入口看不到它。
