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
| `multi-engine-lab` | 多引擎 tamper A/B（真 JDBC：H2/HSQLDB/Derby），**挂 CRS 的默认档 ≈PL3** | `verify.mjs`（≈PL3 实测 0/9 ⇒ 本档只验 safe 零误报，判定行会自己标"空转"） | Java + jar |
| `multi-engine-lab-crs-pl1` | 同一设施的 **CRS PL1 档 = 官方默认部署档**：三引擎布尔通道 9/9 ⇒ README 里"默认 CRS 下可被检出"那句的来源 | `CRS_PL=1 verify.mjs`（产物 `.pl1.md`） | Java + jar |
| `multi-engine-lab-no-waf` | 同一个 `verify.mjs` 的**无 WAF 档**：覆盖面/定库类断言只挂这档（三引擎布尔 9/9，H2/HSQLDB 定库成功、Derby 定不出） | `NO_WAF=1 verify.mjs`（产物另名 `.no-waf.md`，不覆盖 CRS 档） | Java + jar |
| `dialect-templates` | 方言模板在真引擎上的**可执行性 + 反证**（H2/HSQLDB/Derby/MonetDB，16 条）。09-22 写完只被手动跑过一次，2026-09-25 才注册进 run-all | `verify-dialect-templates.mjs`（缺 `ENGINE_JARS` 时 `[SKIP]` 退 0，不再退 2） | Java + jar |
| `mariadb-verify` | MariaDB 11.4 真实引擎 tamper A/B | `multi-engine-lab/mariadb-verify.mjs`（在本仓它**不是独立靶场目录**，挂在 multi-engine-lab 下） | MariaDB:3308 |
| `oob-real-lab` | OOB 带外全链路（PG `COPY TO PROGRAM` / MySQL UNC DNS） | `verify.mjs` | PG + MySQL |
| `real-mysql-lab` | 真实 MySQL 驱动靶场验证 | `verify.mjs` | MySQL |
| `waf-real` | 真实 CRS v4.1.0 规则绕过验证 | `selftest.mjs` | MySQL |
| `real-world-lab` | 拟真靶场（登录/搜索/上传等业务面） | `verify.mjs` | PGlite（内置） |
| `pentest-lab` | 渗透视角「刁钻场景」实测 | `verify.mjs` | MySQL |
| `signed-api-lab` | **签名/加密参数接口**的请求变换闭环（`--request-script`）：真 md5 验签中间件 + 四形态（正确签名 / 只覆盖抓包副本的字段 / 密钥错 / 关键字过滤），裁判是靶站计数的 `reachedPayload`（改了取值的请求是否抵达 SQL）。D 对照组钉住"不做扩展点时的静默假阴性"，E 钉住"不误报" | `run.mjs`（五场景连跑三轮逐字一致；摘掉变换接线 ⇒ 6 条红） | 无（真 SQLite + 真 CLI 进程） |
| `recall-lab` | **两个入口，别混**：`false-positive.e2e.js` = 安全靶场零误报（run-all 里那个叫 "recall-lab" 的条目指它）；`recall.e2e.js` = 18 条召回基线（含 2 条真实 MySQL，CI 在 acceptance job 里带 `RECALL_REQUIRE_MYSQL=1` 每次 push 跑满 18） | 见左列 | PGlite + 真 MySQL |
| `tamper-matrix` | tamper × WAF 规则绕过矩阵 | `tamper-test.mjs` | 无 |
| `detection-runner` | 数据驱动检测测试 | `run.js` | 无 |
| `udf-lab` | UDF 接管真实验证（真 DLL） | `udf-takeover.e2e.mjs` | MySQL |
| `waf-lab` | WAF 规则对比实验 | **门禁看 `compare-real.e2e.mjs`**（真 MySQL；本机经 `compare-real.run.py` 沙箱，CI 每次 push 直连 mysqld 跑）。⚠️ `compare.e2e.js` 是 2026-09-18 已废弃的空壳夹具（其 `/vuln` 端点不执行 SQL ⇒ 判据恒为 NO），只作历史保留、不作入口 | 无 |
| `sqli-labs` | sqli-labs 靶场适配 | `sqli-labs-runner.mjs`（75 关黄金标准 runner，靶场由 `sqli-labs.py` 起） | 需 sqli-labs 环境 |

## 常用工具

| 工具 | 用途 |
|---|---|
| `redteam-lab/diff-reports.mjs <beforeDir> <afterDir> <ids>` | **行为等价性对比**：归一化时间戳/随机 id/请求数后比对两次扫描报告的结论字段。重构后证明"行为没变"用它，退出码可作 CI 门禁 |
| `redteam-lab/env.mjs` | 一键拉起 MySQL + PG + 靶场并常驻 |
| `redteam-lab/results/`、各靶场 `results/` | 报告落盘位置 |

### 本地手动探针（**不进 CI**，改动相关链路时自行复跑）

这批脚本没有退出码门禁、也不在 `run-all.mjs` 里，靠下面这张表被找到；
`server/tests/orphanScripts.guard.test.js` 会钉住"新增脚本必须在这里或某个执行入口登记过"。

| 工具 | 用途 | 依赖 |
|---|---|---|
| `python e2e/run-with-sandbox.py e2e/pentest-lab/probe-limit-expr.mjs` | LIMIT 裸数字位的可注入性：逐条验证 `CASE WHEN`/`PROCEDURE ANALYSE` 等"无引号变体"在真 MySQL 上全部语法错 ⇒ 该位不可达是 SQL 语法的**客观边界**，不是引擎缺陷 | 真 MySQL（沙箱） |
| `node e2e/waf-real/inject-check.mjs` | 真机对拍链路的**缺陷注入复验**：把判据改坏看是否红，跑完自动还原源文件 | 真 MySQL（沙箱） |
| `node e2e/waf-real/tamper-live.mjs` | tamper 链在真 MySQL + CRS v4.1.0 下的**动态** A/B（与静态 `tamper-sweep.mjs` 互补：静态只看 CRS 拦不拦，这条看语义是否还破得了） | 真 MySQL（沙箱） |
| `node e2e/waf-real/dialect-audit.mjs` | 方言浪费审计：目标是 MySQL 却投放 MSSQL/Oracle payload 的请求逐条计数 | 真 MySQL（沙箱） |
| `node e2e/waf-real/header-channel.mjs` | 请求头注入通道端到端验证（CRS 942 系多数规则只覆盖 ARGS/ARGS_NAMES/COOKIES/XML，头通道是否真被放过） | 真 MySQL（沙箱） |
| `node e2e/waf-real/probe-hex.mjs` | hexliterals 专项：插件 doctest + 真 MySQL 语义等价 + CRS 静态绕过 + 与 `quote2hex` 的安全性对比 | 真 MySQL（沙箱） |
| `python e2e/udf-lab/sandbox.py --script _sandbox_adversarial_probe.mjs --probe` | 沙箱对抗性压测：量出沙箱"实际拦住了什么"而非声称什么都拦得住，结果原样输出由上层判 | MySQL 沙箱 |
| `python e2e/udf-lab/verify-all.py` | UDF 验证的**一键回归**（隔离边界 / 负向拦截 / 直连基线 / 注入通道注册 4 步）；第 5 步 `sys_eval` 真执行系统命令，**只在显式加 `--with-command-exec` 时跑** | MySQL 沙箱 |

## 约定

- **报告落 `results/`**，可被 git 跟踪（作为证据留存）。
- 涉及外部 DB 的靶场，凭据优先走**环境变量**（如 `LAB_DB_PASSWORD`、`MARIADB_PORT`），
  不要在脚本里硬编码——硬编码口令会让靶场换机器就莫名连不上（已踩过）。
- 新增靶场时，把条目加进 `run-all.mjs` 的 `LABS` 并声明 `deps`，否则统一入口看不到它。
