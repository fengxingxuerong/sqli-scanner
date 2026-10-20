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
