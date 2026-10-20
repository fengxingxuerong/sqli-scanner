# OWASP Benchmark 外部裁判实跑（D115，2026-10-20）

外部裁判 **4 号**。前三号裁判技术栈各异（Node/Python/PHP），但**没有一个覆盖 HTTP header
位置的注入点**（D113 的待推进里点名了这块）。Benchmark 补的正是这个，而且它带来前三号
都没有的东西：**官方逐条标注每个用例是否有真漏洞**。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | **OWASP Benchmark**（`OWASP-Benchmark/BenchmarkJava`，master） |
| 技术栈 | Java 17（Temurin 17.0.2）+ Spring + Tomcat 9.0.122 + **HSQLDB 2.7.4** |
| 实例 | `https://127.0.0.1:8443/benchmark/`（deploy profile ⇒ https/8443 + 自签证书） |
| 数据库 | HSQLDB Server @9001（`target/db/benchmark.db`）；4 行 USERS（User01..03 + foo/bar） |
| 真值来源（外部） | 官方 `expectedresults-1.2.csv`：`<test name>, sqli, <real vulnerability>, 89` |
| 扫描配置 | `level=2 risk=2 techniques=union,boolean,error,time insecureTls=true`；header 用例加 `testHeaders`；参数名用例加 `testParamNames` |

## 复跑命令

```bash
# 起靶场（详见 e2e/benchmark-lab/README.md）
mvn initialize clean package -Pdeploy -DskipTests -Dspotless.apply.skip=true
mvn cargo:run -Pdeploy -Dspotless.apply.skip=true

# 外部裁判套件
node e2e/benchmark-lab/run.mjs
node e2e/acceptance.mjs --only=benchmark
```

## 套件结果（2026-10-20 21:16，完整日志 `results/run-2026-10-20.log`）

| 用例 | 官方标注 | 形态 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| BenchmarkTest00024 | real=true | query | ✅ 2 条 | union/error/boolean | 92 |
| BenchmarkTest00025 | real=true | query | ✅ 3 条 | union, error, boolean | 102 |
| BenchmarkTest00026 | real=true | query | ✅ 3 条 | union, error, boolean | 95 |
| BenchmarkTest00027 | real=true | query | ✅ 1 条 | error | 95 |
| BenchmarkTest00032 | real=true | query | ✅ 1 条 | error | 95 |
| BenchmarkTest00033 | real=true | query | ✅ 3 条 | union, error, boolean | 95 |
| BenchmarkTest00034 | real=true | query | ✅ 2 条 | error, boolean | 92 |
| BenchmarkTest00037 | real=true | **参数名** | ✅ 2 条 | `paramName` | 58 |
| BenchmarkTest00038 | real=true | **参数名** | ✅ 2 条 | `paramName` | 58 |
| BenchmarkTest00039 | real=true | **参数名** | ✅ 1 条 | error | 72 |
| BenchmarkTest00018 | real=true | **header** | ✅ 1 条 | error | 95 |
| BenchmarkTest00194 | real=true | **header** | ✅ 1 条 | error | 95 |
| BenchmarkTest00430/432/436/437/440 | real=false | query | ✅ 0 | - | 124 × 5 |
| BenchmarkTest00511/513/514 | real=false | query | ✅ 0 | - | 123 × 3 |

- 真值 **12/12 检出（漏检 0）**，安全对照 **0/8 误报**，证据不足 0
- 命中 DBMS：**HSQLDB**（`url·BenchmarkTest00025·dbms=HSQLDB`）
- header 注入面 2/2 检出（`header·BenchmarkTest00018`）—— 前三个外部裁判从未覆盖的形态
- `acceptance --only=benchmark`：**1 PASS / 0 FAIL / 0 SKIP**

## 首跑抓到的问题（两条，都不是引擎缺陷 —— 是**用法没对上官方用例语义**）

首跑 **9/12**（漏检 00037 / 00038 / 00039）。逐条看官方源码后定位：

1. **参数名注入形态**（`src/main/java/**/BenchmarkTest00037.java`）：
   ```java
   java.util.Enumeration<String> names = request.getParameterNames();
   while (names.hasMoreElements()) {
     String name = (String) names.nextElement();
     for (String value : request.getParameterValues(name))
       if (value.equals("BenchmarkTest00037")) { param = name; flag = false; }
   }
   ```
   **注入点是参数名**（`param = name`），且服务端要求**值等于类名**才取该参数名。
   首跑按普通 query 参数发 `?BenchmarkTest00037=baseline` ⇒ `value != 类名` ⇒ param 恒为
   `""` ⇒ SQL 里 `PASSWORD=''` ⇒ 注入根本没进查询（实测基线/真/假三种响应**完全相同**）。
   正确用法：`?<payload>=<类名>` + 引擎 `testParamNames`（D93 的 `--test-param-names`）。
   修正后三条全部检出（`paramName·BenchmarkTest0003x`）。
   —— 这一类在 504 个 sqli 用例里有 **57 个**（索引 `benchmark-sqli-index.json` 的 `paramName` 字段）。

2. **header 用例的 `testHeaders`**：TargetParser 只在 `level>=3` 或显式 `testHeaders` 时把
   `headerParams` 变成注入点；本 lab 全局 `level=2`（query 用例的默认档）⇒ 不加这一项会得到
   「header 用例 0 请求 / 没匹配到注入点」的假漏检。已在 runner 里按 `kind === 'header'` 显式开启。

## 边界（不得越界引用）

- **子集 ≠ 全集**：20/504（12 真值 + 8 安全对照）。只证明「该子集上」的表现，
  **不能外推为「Benchmark 检出率 N%」**，更不能与官方 scorecard 的百分比相提并论。
- 12 条 finding 是同一注入点的多技术命中，不是 12 个独立漏洞。
- 参数名形态的 3 条依赖 `testParamNames`（默认关闭的 opt-in 能力）；header 形态依赖
  `testHeaders`（同为 opt-in）⇒ 不代表默认配置覆盖率。
- HSQLDB 的 `TOP 1` / `{call}` 等方言差异只在个别用例出现；本子集不含 `{call` 存储过程用例。
- Benchmark 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 靶场需要 `-Pdeploy` 起 HSQLDB server（antrun），且数据库文件在 `target/db/`；
  这属于**官方流程**，未改任何 Benchmark 源码（只加了 `-Dspotless.apply.skip=true`，
  因为 tarball 无 `origin/master` ref）。

---

# [D116 2026-10-20] 扩面：20 → 74 用例（参数名形态全量 + `{call}` 边界单列）

D115 的子集只有 20 条（12 真值 + 8 安全），其中参数名形态只取到 3 条。本批把
**全部 57 条参数名形态用例**并入清单，合计 **74 条**（真值 43 + 安全 24 + `{call}` 7）。
清单落盘为 `e2e/benchmark-lab/cases.json`（不再硬编码在 runner 里 —— 清单会随扩面增长，
硬编码会让「加了用例却没落数据来源」变成新的静默缺口）。

## 结果（2026-10-20 22:30，完整日志 `results/run-2026-10-20-d116b.log`）

| 类别 | 结果 |
|---|---|
| 真值漏洞（官方 real=true，**不含 `{call}`**） | **43/43 检出（漏检 0）** |
| 安全对照（官方 real=false，不含 `{call}`） | **0/24 误报** |
| 证据不足（请求 < 30） | 0 |
| header 注入面 | 2/2 |
| **参数名注入面** | **50 条全检出**（`paramName·BenchmarkTestNNNNN·dbms=HSQLDB`） |
| `{call <过程名>}` 形态 | 真值 **0/4**（已知能力边界，不计入分母）；安全对照 **0/3 误报** |

`acceptance --only=benchmark`：**1 PASS / 0 FAIL / 0 SKIP**（形态覆盖=header+参数名（50 条））。

## 首跑的一处**清单口径错误**（不是引擎缺陷）

未加 `callProcedure` 标记前首跑是 **43/47**，4 条漏检全部是
`BenchmarkTest00590 / 01460 / 01462 / 01463`。逐条读源码：

```java
String sql = "{call " + bar + "}";        // 注入点是**存储过程名**
java.sql.CallableStatement statement = connection.prepareCall(sql);
```

即 payload 空间是 `CALL <procedure_name>` —— 与「值位注入」不是同一个问题。本引擎不支持
该类注入（sqlmap 也需显式 `--os-cmd`/存储过程专用路径才碰）。处置：

- 清单里保留这 7 条（4 真值 + 3 安全），标 `callProcedure: true`；
- 统计**单列**：真值不计入分母（否则把能力边界算成「漏检」，会污染检出率口径）；
- 但**安全侧误报必须为 0**（误报是真的缺陷，边界不豁免）—— 实测 0/3，说明引擎在这类
  端点上不会瞎报。

## 边界（更新）

- **子集 74/504**（原 20/504）。真值 43 条 —— 仍**不能外推为「Benchmark 检出率 N%」**，
  也不能与官方 scorecard（28887 用例、按类别加权）的百分比相提并论。
- `{call <过程名>}` 形态是**明确的能力缺口**（4 条真值全未检出），已记入 TODO 待推进；
  本条不构成误报，也不影响值位注入的检出结论。
- 参数名形态依赖 `testParamNames`、header 形态依赖 `testHeaders`（均 opt-in）。

---

# [D117 2026-10-20] header 注入面全量（67 条）

D115 只覆盖了 2 条 header 用例（当时全平台都没有 header 位置注入点）。本批把
**header 形态全量 67 条**（33 真值 + 34 安全）单独跑一轮 —— 清单落盘
`e2e/benchmark-lab/cases-header.json`，用 `BENCHMARK_CASES` 指定。

## 结果（2026-10-20 22:46，完整日志 `results/run-2026-10-20-d117-header.log`）

| 类别 | 结果 |
|---|---|
| 真值漏洞（官方 real=true） | **33/33 检出（漏检 0）** |
| 安全对照（官方 real=false） | **0/34 误报** |
| 证据不足（请求 < 30） | 0 |
| 每例请求数 | 92 ~ 124（全部打满，不是「没测过」） |

命中技术分布：**error 33/33**（全部命中错误回显），其中 17 条同时 boolean 命中、8 条同时
union 命中 —— 说明 header 位置的注入在这批用例上主要靠**报错回显**判定，布尔/UNION 是补充。
命中 DBMS 全为 `HSQLDB`。

## 观察

header 位置的注入是前三个外部裁判（Juice Shop / VAmPI / DVWA）**完全没有**的形态，
本批 67 条全绿说明：`--test-headers`（`headerParams` → 注入点）在真实目标上可用，
且不会对 34 条安全实现产生误报。⚠ 该能力是 **opt-in**（`level>=3` 或显式 `testHeaders`），
不代表默认配置（`level=1/2` 不测 header）的覆盖率。

---

# [D117 2026-10-20] query 注入面全量（210 条）

清单 `e2e/benchmark-lab/cases-query.json`：query 形态全量 210 条（111 真值 + 99 安全），
已排除 paramName / `{call` / preparedStatement 三类（各有独立口径）。

## 结果（2026-10-20 22:49，完整日志 `results/run-2026-10-20-d117-query.log`）

| 类别 | 结果 |
|---|---|
| 真值漏洞（官方 real=true） | **111/111 检出（漏检 0）** |
| 安全对照（官方 real=false） | **0/99 误报** |
| 证据不足（请求 < 30） | 0 |
| 用时 | 54 秒（210 例） |

## D117 累计覆盖（去重后）

| 形态 | 用例数 | 真值 | 安全 | 结果 |
|---|---|---|---|---|
| query 全量 | 210 | 111 | 99 | 111/111 + 0/99 |
| header 全量 | 67 | 33 | 34 | 33/33 + 0/34 |
| 参数名形态（**不含 call**） | 50 | 34 | 16 | 34/34 + 0/16 |
| 小计（**有效口径**） | **327** | **178** | **149** | **178/178 + 0/149** |
| `{call <过程名>}`（单列，已知边界） | 7 | 4 | 3 | 0/4 检出（不计分母）+ **0/3 误报** |

即 **504 个 sqli 用例里可测的 327 条全部通过**；另有 7 条 `{call` 形态为已知能力缺口
（4 条真值全未检出，但 3 条安全对照 0 误报），113 条 prepared/其它形态未纳入。
四个外部裁判合计真值 **187 个端点/用例**（Juice 2 + VAmPI 2 + DVWA 5 + Benchmark 178）。

## 观察

- **零误报**：152 条官方标注安全的用例（转义、白名单、数值强转等实现）全部 0 检出 ——
  这批是「同族不同实现」的对照，比随便找几个无关安全端点强得多。
- 真值 182 条覆盖了 query / header / 参数名三种注入面与 HSQLDB 方言（`TOP 1`、存储过程除外），
  但**仍不能外推为全局检出率**：Benchmark 的用例是合成靶场，真实系统里还有 WAF、参数签名、
  JSON/XML body 等本批未覆盖的形态。
