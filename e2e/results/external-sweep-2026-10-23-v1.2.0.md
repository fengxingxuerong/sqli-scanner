# 外部裁判复跑 · 2026-10-23（v1.2.0）＋发布阻断项复验

> 目的：2026-10-22 的 187/187 外部结果产自 D121–D124 工作树（后提交为 `6e9cc40`），
> 而当前 HEAD 已到 `e06f7f7` / tag `v1.2.0`（含 D125–D132）。本文件补上 **v1.2.0 上的外部
> 实跑**，并把 `docs/release-readiness-2026-10-23.md` 里 4 项「未决」在真 MySQL 上复跑销账。
>
> 代码状态：`HEAD=e06f7f7`、tag `v1.2.0`、工作树仅被本轮验收生成的 e2e 产物弄脏
> （`e2e/results/acceptance-report.md`、`e2e/detection-runner/results/detection-report.md`、
> `e2e/waf-real/results/waf-real-report.md`），**引擎源码未改动**。

## 一、环境

五个靶场复用 2026-10-21 构建产物，本轮重启服务（未重新下载/构建）：

| 靶场 | 版本/栈 | 地址 |
|---|---|---|
| Juice Shop | v20.3.0，Node + Sequelize + SQLite | `http://127.0.0.1:3199` |
| VAmPI 漏洞/对照 | master，Flask + SQLAlchemy + SQLite | `http://127.0.0.1:5000` / `:5001`（`vulnerable=0`） |
| DVGA | 2.2.0，Flask + Graphene + SQLite | `http://127.0.0.1:5013` |
| DVWA | master，PHP 8.3 + MariaDB 10.11.19 | `http://127.0.0.1:8099` |
| OWASP Benchmark | 1.2，JDK17 + Tomcat(cargo) + HSQLDB 2.7.4 | `https://127.0.0.1:8443/benchmark` |

日志（本地留档，`*.log` 按仓库约定不入库）：
`.box-agent-scratch/run-2026-10-23-v120/{run-juice,run-vampi,run-dvga,run-dvwa,run-bench-baseline,run-bench-query,run-bench-header}.log`。

## 二、外部裁判结果（v1.2.0 本轮实测）

| 裁判 | 真值 | 安全端点误报 | 备注 |
|---|---|---|---|
| Juice Shop | 2/2 | 0/4 | 同源复检 1/1（banana，98 请求） |
| VAmPI | 2/2（同一注入点匿名 + Bearer） | 0/5 | 同源复检 2/2；Bearer 端点 5 个、未测 0；证据不足 0 |
| DVGA | 1/1（`body·query.filter`） | 0 | 结构对照 0 点/0 请求；`search(keyword)` 0 误报（124 请求） |
| DVWA | 5/5 | 0/2 | low GET / low blind / high cookie / medium POST / medium blind POST；同源复检 1/1 |
| OWASP Benchmark | **178/178** | **0/149** | 基线 43/43 + 0/24；query 111/111 + 0/99；header 33/33 + 0/34 |

合计：**187/187 个外部真值端点全部可打穿、安全端点误报 0、证据不足 0**。
`{call <过程名>}` 真值仍 0/4（已知能力边界，单列不计入 178；3 条安全用例 0 误报）。

复跑命令：

```bash
JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs
node e2e/vampi-lab/run.mjs
DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs
DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs
node e2e/benchmark-lab/run.mjs
BENCHMARK_CASES=e2e/benchmark-lab/cases-query.json node e2e/benchmark-lab/run.mjs
BENCHMARK_CASES=e2e/benchmark-lab/cases-header.json node e2e/benchmark-lab/run.mjs
```

与 2026-10-22 的 187/187 逐项一致；本轮把「外部证据停留在 1.1.x/D121–D124」的版本缺口补齐。
五个裁判的**外部真值仍来自第三方源码**，不是本仓断言。

## 三、发布阻断项复验（4 项旧「未决」）

`docs/release-readiness-2026-10-23.md` §3 P0-5 / §10 记录的四项，本轮在本机真 MySQL 上复跑：

| 旧条目 | 本轮命令 | 结果 |
|---|---|---|
| 报告契约：显式 UNION 点只出 `error` | `python e2e/run-with-sandbox.py e2e/contract/report-contract.e2e.mjs --drop-dir` | **8/8 通过**；`union 技术应被检出` 断言通过 |
| CRS 人工挂链 PL1（旧记 4/8） | `MYSQL_* node e2e/acceptance.mjs --only=waf-real,waf-auto` | **PASS**：off=8 / on=8；基线 off≥8/on≥8；安全误拦=false |
| CRS 自动选链 PL1（旧记 4<8） | 同上 | **PASS**：技术位=8；基线≥8；安全误报=0 |
| fileWrite 真闭环 | `MYSQL_*（MySQL 8.0.28 沙箱 3308）node e2e/fileops/exploit-file-write.e2e.mjs` | **PASS**：`{ok:true,wrote:true,verified:true,via:"union"}`；文件系统侧存在且含 `PWNED_marker_2026=xyz789` |
| fileRead 真闭环（同类环境项） | 同上，`exploit-file-read.e2e.mjs` | **PASS**：LOAD_FILE 返回 `FILEREAD_OK_marker_2026=abc123` |

关键环境事实：报告契约/CRS/fileops 的旧红里有**测试库 schema 缺失**与
`secure_file_priv` 配置差异；本轮用 `e2e/lib/sqliSchema.mjs` 初始化 `users/products` +
MySQL 8.0.28 沙箱（`secure_file_priv` 指向隔离目录）后，四项均转绿。旧结论按 §3.5 作废：
不再引用「显式 UNION 漏报」「CRS PL1 4/8」「fileWrite 自报成功」作为当前能力结论；
旧数字保留在 README 历史表/CHANGELOG 中并标注被本轮复跑取代。

## 四、全量 acceptance（25 套）

```
MYSQL_HOST=127.0.0.1 MYSQL_PORT=3306 MYSQL_USER=root MYSQL_PASSWORD=root \
MYSQL_DATABASE=sqli_lab WAF_GATE_PL=1 node e2e/acceptance.mjs
→ 17 PASS / 0 BLOCKED / 0 FAIL / 8 SKIP（17/25 跑出断言，exit 0）
```

17 PASS 包括：服务端单测（3744 用例 3738 pass / 0 fail / 6 skip）、独立刁钻靶场 11/11、
检测回归 19/19、真 MySQL 11/11、参数名/参数挖掘、真 PG（PGlite）、批量编排、登录编排、
OOB 外部隧道、报告契约 8/8、CRS 手工/自动/保真度/变异/降级、红队 19/19。

8 SKIP 及处置：

| SKIP | 原因 | 处置 |
|---|---|---|
| Juice / VAmPI / DVWA / Benchmark 四个外部裁判 | 验收时靶场未启动 | **本文件第二节已单独复跑：187/187、0 误报** |
| fileRead / fileWrite | 宿主 MariaDB `secure_file_priv=NULL` | **本文件第三节已用 MySQL 8 沙箱复跑：PASS** |
| OOB 带外真机（PG COPY TO PROGRAM） | 5432 未监听 | 环境缺失，未验证；不计通过 |
| 数据泄露实证 | 环境不满足 | 环境缺失，未验证；不计通过 |

验收产物：`e2e/results/acceptance-report.md`（本轮生成；工作区在跑批时含上述 e2e 产物改动）。

## 五、仍然存在的边界（不得越界引用）

- Benchmark 占 178/187，外部样本严重不均衡，**不能外推「通用外部检出率」**。
- GraphQL 面仍只有 DVGA `pastes(filter)` 一个真值端点；`{call <过程名>}` 4 条真值未检出。
- **没有真实云 WAF 样本**；CRS PL1 的 8/8 是自实现 CRS 执行器 + 真 MySQL 靶站，不是商业云 WAF。
- 外部裁判为**手动起靶场**；未接入 acceptance/CI（验收本轮四个外部套件 SKIP，已单独补跑）。
- 本轮未重复 2026-10-22 的 D123/D124 字段探针；该证据仍见
  `e2e/results/external-sweep-2026-10-22-post-d124.md`。
- Docker 镜像未构建/冒烟（本机无 Docker）；桌面打包未在本轮验证。
- 远端尚未推送；`v1.2.0` tag 目前只在本机。
