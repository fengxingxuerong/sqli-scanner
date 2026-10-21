# 外部裁判回归复跑 · 2026-10-22（D121–D124 工作树）

> 目的：D121（GraphQL 内联值位）、D122（口径修正）、D123（未验证注入面）、D124（未覆盖面 +
> 浏览器降级留痕）之后的**外部回归**。与 D122 的「5 裁判从零重搭」不同，本轮复用
> 2026-10-21 已构建的源码/venv/war/数据库，只重启服务；判据与清单不变。
>
> 代码状态：`HEAD 1f3d628`（D120），工作树包含 D121–D124 未提交改动（32 个变更/新增条目）。
> 因此本文件的数字对应**未提交代码**，提交后应保持同一内容再引用。

## 一、环境（复用 2026-10-21 构建产物）

| 靶场 | 版本/栈 | 地址 | 本轮状态 |
|---|---|---|---|
| OWASP Juice Shop | v20.3.0，Node + Sequelize + SQLite | `http://127.0.0.1:3199` | 重启，就绪 |
| VAmPI（漏洞实例） | master，Flask + SQLAlchemy + SQLite | `http://127.0.0.1:5000` | 重启 + `/createdb`，`tokentimetolive=7200` |
| VAmPI（对照实例） | 同上，`vulnerable=0` | `http://127.0.0.1:5001` | 重启（`PYTHONPATH` 指向源码目录） |
| DVGA | 2.2.0，Flask + Graphene + SQLite | `http://127.0.0.1:5013` | 重启，DB 已存在 |
| DVWA | master，PHP 8.3 + MariaDB 10.11.19 | `http://127.0.0.1:8099` | MariaDB + PHP 重启，`disable_authentication=true` |
| OWASP Benchmark | 1.2，JDK 17 + Tomcat(cargo) + HSQLDB 2.7.4 | `https://127.0.0.1:8443/benchmark` | HSQLDB（9001，恢复 2026-10-21 数据）+ Tomcat 重启 |

日志（本地留档，`*.log` 按仓库约定不入库）：
`.box-agent-scratch/run-2026-10-22/{run-juice,run-vampi,run-dvga,run-dvwa,run-bench-baseline,run-bench-query,run-bench-header,probe-summary,probe-summary2,probe-bench-header,run-acceptance}.log`。

（`probe-summary.log` 是探针初版，含第三节记录的两处探针配置错；`probe-summary2.log` 为修正后结果。）

## 二、逐裁判结果（本轮实测）

### 1 号 · Juice Shop

| 端点 | 类型 | 结果 |
|---|---|---|
| `GET /rest/products/search?q=apple` | 真值（`routes/search.ts` LIKE 拼接） | 通过：vulns=1，98 请求，boolean |
| `POST /rest/user/login` | 真值（`routes/login.ts` 直拼） | 通过：vulns=2，111 请求，error+boolean |
| `GET /rest/products/search?q=banana` | 同源复检 | 通过：vulns=1，98 请求 |
| `/api/Feedbacks/?limit=2`、`/api/Challenges/?name=`、`/rest/user/security-question?email=`、`/api/Products/?name=` | 安全 ×4 | 通过：0 误报（124/174/124/124 请求） |

结论：真值 2/2、同源复检 1/1、安全 0/4 误报。

### 2 号 · VAmPI

| 端点 | 类型 | 结果 |
|---|---|---|
| `GET /users/v1/zzz` | 真值（`models/user_model.py:72` f-string） | 通过：vulns=3，95 请求，union+error+boolean，dbms=SQLite |
| 同端点 + Bearer | 真值（认证夹击回归面） | 通过：vulns=3，95 请求 |
| `GET /users/v1/name1` | 同源复检 | 通过：vulns=3，75 请求 |
| 同端点 + Bearer | 同源复检 | 通过：vulns=3，69 请求 |
| `/users/v1/zzz`、`/users/v1/name1` @5001 | 安全（`vulnerable=0` 同路径 A/B） | 通过：0 误报（123/144 请求） |
| `/books/v1/{title}` @5000/5001 + Bearer | 安全（`filter_by` 参数化 + token 门禁） | 通过：0/3 误报（123/122/144 请求） |

结论：真值 2/2（同一注入点匿名 + Bearer）、同源复检 2/2、安全 0/5、Bearer 端点 5 个未测 0、证据不足 0。

### GraphQL 面 · DVGA

| 端点 | 类型 | 结果 |
|---|---|---|
| `POST /graphql` `{ pastes(public:true, filter:"x"){…} }` | 真值（`core/views.py:320` 拼接） | 通过：vulns=3，98 请求，union+error+boolean |
| `POST /graphql` `{ pastes(public:true){…} }` | 结构对照（无字面量） | 通过：0 点 / 0 请求（按设计） |
| `POST /graphql` `{ search(keyword:"x"){…} }` | 安全（ORM `like` 参数化） | 通过：0 误报，124 请求 |

命中明细 `body·query.filter·dbms=SQLite`，D121 的内联值位通道仍生效。

### 3 号 · DVWA

| 端点（官方难度档） | 类型 | 结果 |
|---|---|---|
| `GET /vulnerabilities/sqli/?id=1&Submit=Submit`（low） | 真值 | 通过：vulns=3，57 请求，union+error+boolean，dbms=MariaDB |
| 同点换 `id=2` | 同源复检 | 通过：vulns=3，57 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1`（low） | 真值 | 通过：vulns=1，67 请求，boolean |
| `GET` + `Cookie id=1` @`sqli_blind`（high） | 真值 | 通过：vulns=1，70 请求，boolean |
| `POST /vulnerabilities/sqli/`（medium） | 真值 | 通过：vulns=3，89 请求，union+error+boolean |
| `POST /vulnerabilities/sqli_blind/`（medium） | 真值 | 通过：vulns=1，148 请求，boolean |
| `GET /vulnerabilities/sqli/?id=1`（impossible） | 安全 | 通过：0 误报，150 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1`（impossible） | 安全 | 通过：0 误报，150 请求 |

结论：真值 5/5、同源复检 1/1、安全 0/2、证据不足 0。

### 4 号 · OWASP Benchmark（三份清单）

| 清单 | 条数 | 真值 | 安全 | 本轮结果 |
|---|---|---|---|---|
| `cases.json`（门禁基线） | 74 | 43 | 24 | 43/43 检出、0/24 误报、证据不足 0；`{call}` 真值 0/4 单列（已知边界）、安全 0/3 |
| `cases-query.json`（query 全量） | 210 | 111 | 99 | 111/111 检出、0/99 误报、证据不足 0 |
| `cases-header.json`（header 全量） | 67 | 33 | 34 | 33/33 检出、0/34 误报、证据不足 0 |

三份清单有效真值 111 + 33 + 34 = **178/178**、安全 99 + 34 + 16 = **0/149**，与 D117/D122 口径逐条吻合。
`{call <过程名>}` 4 条真值仍未检出（已知能力边界，不计入 178；3 条安全用例 0 误报）。

### 合计

快裁判真值 2（Juice）+ 1（VAmPI 唯一端点）+ 5（DVWA）+ 1（DVGA）+ Benchmark 178 = **187 个外部真值端点全部可打穿**；
安全端点误报 0（分母 4 + 5 + 2 + 1 + 149）。与 D122 的 187/187 一致。

### 门禁侧

```
node e2e/acceptance.mjs --only=juice-shop,vampi,dvwa,benchmark
→ 4 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP（套件范围 4/25，非全量报告）
```

四套件均以「事实断言」模式判 PASS（不采信套件自报）。前置提示 MySQL 连接失败
（`ER_BAD_DB_ERROR`）与本次外部裁判无关——DVWA 使用独立 MariaDB 账号 `dvwa/p@ssw0rd`。

## 三、D123/D124 新报告字段的外部核验

D123 新增 `summary.unverifiedSurfaces` / `summary.unverifiedSentence`（并拼进 `verdictNote`），
D124 新增 `summary.uncoveredSurfaces` / `summary.uncoveredSurfacesHint` 与
`summary.crawlBrowserFallback` / `summary.crawlBrowserHint`。本轮在真实外部目标上用独立探针
（`.box-agent-scratch/run-2026-10-22/probe-summary-fields.mjs`）逐项核对：

| 场景 | 配置 | 结果 | 未覆盖清单 | 未验证面 | 降级字段 |
|---|---|---|---|---|---|
| Juice 真值 | level=2 | vulns=1 / 98 请求 | header, path, forms | 无 | 无 |
| Juice 安全 | level=2 | vulns=0 / 124 请求 | header, path, forms | 无 | 无 |
| Juice 真值 | level=2 + `testHeaders` | vulns=1 / 92 请求 | path, forms | 无 | 无 |
| VAmPI 安全 | level=2 + `testPath` | vulns=0 / 123 请求 | header, forms | 无 | 无 |
| DVWA impossible | level=2 + `security=impossible` | vulns=0 / 445 请求 | header, path, forms | 无 | 无 |
| DVGA 安全 | level=2 | vulns=0 / 124 请求 | header, path, forms | 无 | 无 |

另在 Benchmark 的 **HTTP header 注入面**（Java/HSQLDB，真实 header 点）用 `testHeaders: true`
核验两条官方用例：

| 用例 | 官方真值 | 结果 | 未覆盖清单 | 未验证面 | 降级字段 |
|---|---|---|---|---|---|
| `BenchmarkTest00194` | true | vulns=1 / 95 请求 | path, forms | 无 | 无 |
| `BenchmarkTest00197` | false | vulns=0 / 124 请求 | path, forms | 无 | 无 |

合计 **8/8 通过**，判据：真值/安全的检出数与套件一致；健康目标上**不得**出现
`unverifiedSurfaces` / `unverifiedSentence` / `crawlBrowserFallback`；`verdictNote` 不得含
「未验证」「降级」；`uncoveredSurfaces` 必须随 `testHeaders` / `testPath` 正确收缩。

过程注记（如实留痕）：探针初版两处配置错导致假红——VAmPI 未开 `testPath`（路径段注入点未生成，
0 请求、verdict=inconclusive）、DVWA 未带 `security=impossible`（实际打在默认 low 档，检出 3 条）。
修正后全部通过；这是探针配置错，不是引擎回归。
DVWA impossible 的探针未限制 `testParameter`，请求数 445；套件判据（限制 `id`）为 150 请求，两者均 0 误报。

## 四、与 D122 的差异

| 项 | D122（2026-10-21） | 本轮（2026-10-22） |
|---|---|---|
| 代码状态 | D121 之后 | D121–D124 工作树（未提交） |
| 靶场搭建 | 5 个全部从零重搭 | 复用 10-21 构建产物，仅重启服务 |
| 快裁判 | Juice 2/2+0/4、VAmPI 2/2+0/5、DVGA 1/1+0、DVWA 5/5+0/2 | 完全一致 |
| Benchmark | 基线 43/43+0/24；query 111/111+0/99；header 33/33+0/34 | 完全一致 |
| 新报告字段 | 未核验（D123/D124 尚未落地） | 8/8 通过（见第三节） |

本轮未发现引擎回归或新字段误报。

## 五、边界（不得越界引用）

- 187 个真值点仍严重不均衡：Benchmark 占 178/187；不能外推「通用外部检出率」。
- Benchmark header 形态依赖 `testHeaders`、参数名形态依赖 `testParamNames`、DVWA cookie 形态
  依赖 level>=2、VAmPI 路径段依赖 `--test-path` ⇒ 套件显式开启的档位不代表默认配置覆盖率。
- `{call <过程名>}` 4 条真值仍未检出，是已知能力边界，单列不计入 178。
- 本轮靶场为**重启既有构建**，未像 D122 一样从零重搭；构建产物与 10-21 相同。
- D123 的**阳性路径**（注入面被 WAF 拦截 ⇒ 报未验证面）本轮没有外部 WAF 流量，仍只有
  `unverifiedSurfaces.scan.test.js` 的本地端到端证据（cookie 面被拦 36 次）；本轮验证的是
  **健康目标上零假阳性**这一半。真实云 WAF 样本仍是缺口。
- `e2e/run-all.mjs` 全量套件本轮未跑；DVGA 仍不接 acceptance。
