# OWASP Benchmark 外部裁判靶场（外部裁判 4 号）

第三方行业基准：**OWASP Benchmark**（`OWASP-Benchmark/BenchmarkJava`）。与前三号裁判
（Juice Shop / VAmPI / DVWA）最大的区别：**官方逐条标注每个用例是否真有漏洞**
（`expectedresults-1.2.csv`），因此可以做「同族 A/B」——同一种写法、同一个注入面，
官方说可注入的必须检出，官方说安全的必须零误报。

## ⚠️ 当前状态：已知漏检缺口（参考靶场，不接门禁）

2026-10-20 实跑本机 20/504 子集：**真值 4/12（query 3/10、header 1/2）、安全对照 0/8、
证据不足 0**。header 首跑曾因 lab 全局 `level=2` 且未开 `testHeaders`，`headerParams`
没有生成注入点（0 请求，报「没有匹配到任何注入点」）——已在 `run.mjs` 显式补
`testHeaders: true`，重跑 header 1/2。query 仍有 7 例真值漏检，待逐例归因。

按 DVGA 同口径登记为 `e2e/reference-labs.json` 的参考/缺口靶场，**不接
acceptance/run-all**；缺口修复后再转门禁。证据见 `results/benchmark-2026-10-20.md`。

## 为什么需要第四号

| 裁判 | 栈 | 注入面 | 规模 |
|---|---|---|---|
| Juice Shop（1 号） | Node + SQLite | query / JSON body | 2 真值 |
| VAmPI（2 号） | Python + SQLite | URL 路径段 / Bearer | 2 真值 |
| DVWA（3 号） | PHP + MySQL | query / POST / cookie | 5 真值 |
| **Benchmark（4 号，本靶场）** | **Java + Spring + HSQLDB** | **query / HTTP header** | **504 sqli 用例（子集 20）** |

前三号没有一个覆盖 **HTTP header 位置的注入点**（3 号待推进里点名「VAmPI 头注入形态
未覆盖」——Authorization 不能当注入点，打了 token 会坏，那是另一回事）。Benchmark 的
`request.getHeader(类名)` 用例正好补这块。

## 环境准备（本机实测配方）

前置：**JDK 17**（本机原先只有 TRAE 内置 JRE，无 javac）+ Maven 3.9。

```bash
# 1. JDK 17（华为云镜像可用；tuna 的 Adoptium 路径 404）
Invoke-WebRequest https://mirrors.huaweicloud.com/openjdk/17.0.2/openjdk-17.0.2_windows-x64_bin.zip -OutFile D:\tools\jdk\jdk.zip
#    解压 → D:\tools\jdk\jdk-17.0.2（含 javac）

# 2. Maven（archive.apache.org 可用；dlcdn / tuna / aliyun 的 maven 路径均 404）
#    D:\tools\maven\apache-maven-3.9.11；~/.m2/settings.xml 配 aliyun 镜像加速依赖

# 3. 源码
Invoke-WebRequest https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/tar.gz/refs/heads/master -OutFile benchmark.tar.gz
tar xzf benchmark.tar.gz    # → BenchmarkJava-master/

# 4. 分三步起（本机实测配方；官方 runBenchmark.sh 是单条命令，但见下面第 3 条坑）
cd BenchmarkJava-master
export JAVA_HOME='D:/tools/jdk/jdk-17.0.2'

# 4a. 打包（-Pdeploy 才会跑 antrun 的 database-server / database-init）
mvn initialize clean package -Pdeploy -DskipTests \
    -Dspotless.check.skip=true -Dspotless.apply.skip=true

# 4b. 手动起 HSQLDB Server（端口 9001，库名 benchmarkDataBase）
#     ⚠ 官方 antrun 用 <daemons> fork 起它，但 mvn 一退出子进程就被回收 ⇒ 本机必须手动起。
mkdir -p target/db
"$JAVA_HOME/bin/java" -cp ~/.m2/repository/org/hsqldb/hsqldb/2.7.4/hsqldb-2.7.4.jar \
  org.hsqldb.Server --database.0 file:target/db/benchmark.db --dbname.0 benchmarkDataBase --port 9001 &

# 4c. 起 tomcat（deploy profile ⇒ https/8443 + 自签证书）
mvn cargo:run -Pdeploy -Dspotless.apply.skip=true
#    就绪后：https://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00025?BenchmarkTest00025=foo
```

⚠ 坑（按踩到的顺序，全部本机实测）：
- **javac 必须来自真 JDK**：只有 JRE 时 maven-compiler-plugin 报
  `Could not retrieve version from javac`（报错中文乱码，容易看错方向）。
- **`-Dspotless.apply.skip=true` 必须有**：spotless 配了 `ratchetFrom origin/master`，
  tarball 没有 git ref ⇒ `No such reference 'origin/master'` 直接 fail。
- **必须带 `-Pdeploy` 打包**：`database-server` / `database-init` 是 deploy profile 里
  antrun 的两个 execution。不带 ⇒ HSQLDB 没起（`Connection refused`）或表不存在
  （`SQLSyntaxErrorException: user lacks privilege or object not found: USERS`）。
- **HSQLDB Server 要手动起**：ant 的 `<java fork="true">` 在 `mvn` 退出后进程被回收，
  实测 9001 立刻消失 ⇒ 用上面 4b 的 java 命令常驻。
- **`cargo:run` 别跟 `clean` 连跑**：库文件锁（`benchmark.db.lck` / `cargo.log`）会让
  `clean` 失败。改代码后要先停 java 进程再 clean。
- **端口是 8443 https（自签）不是 8080**：deploy profile 里 `cargo.servlet.port=8443` +
  `cargo.protocol=https`；引擎侧要 `insecureTls: true`。
- war 的 finalName 是 `benchmark` ⇒ URL 前缀 `/benchmark/`；参数名 = 用例类名（官方约定）。

## 注入面三种形态（runner 必须区别对待）

| 形态 | 判定（读官方源码） | runner 配置 |
|---|---|---|
| 普通 query | `request.getParameter(类名)` | `testParameter: [类名]`，URL `?类名=baseline` |
| **参数名** | `param = name` 且要求 `value.equals(类名)` | `testParamNames: true`，URL `?<payload>=类名` |
| **header** | `request.getHeader(类名)` | `headerParams: {类名: baseline}` + `testHeaders: true` |

⚠ 第二种最容易踩：按普通 query 参数发时服务端 `param` 恒为空串（`PASSWORD=''`），
注入根本没进查询，三种响应的**字节完全相同** ⇒ 会被误判成「引擎漏检」。
504 个 sqli 用例里这类有 **57 个**（索引 `benchmark-sqli-index.json` 的 `paramName` 字段）。

## 真值来源（外部，非本仓编写）

`expectedresults-1.2.csv`：`<test name>, sqli, <real vulnerability true|false>, 89`。
URL 从各用例源码 `@WebServlet(value = "/sqli-XX/BenchmarkTestNNNNN")` 提取；
参数名 = 用例类名（官方约定，query 参数与 header 同名）。

子集选择口径（索引脚本见 `results/` 与 README 末）：
- 504 个 sqli 用例中，筛 `request.getParameter` 取值、字符串拼接 SQL、非 `{call`、
  非 `prepareStatement` ⇒ query 真值 137 / query 安全 113；
- 另取 `request.getHeader` 取值的真值 33 个中的前 2 个 ⇒ header 新注入面；
- 本轮实跑 **20 个**（query 真值 10 + query 安全 8 + header 真值 2；结果见上方「当前状态」）。
全集 504 个留待后续批次（每端点 60~150 请求，全跑一遍约需数小时）。

## 三套用例清单（按跑批时长分开）

| 清单 | 条数 | 内容 | 用时 | 用途 |
|---|---|---|---|---|
| `cases.json` | 74 | 20 条回归基线 ∪ 全部 57 条参数名形态 | ~25 min | **门禁基线**（`acceptance --only=benchmark`） |
| `cases-query.json` | 210 | query 形态全量（111 真值 + 99 安全） | ~1 min | 深度验证（最常见注入面） |
| `cases-header.json` | 67 | header 形态全量（33 + 34） | ~20 s | 深度验证（头位置注入） |

```bash
# 门禁基线（已接 acceptance 第 24 套件，D115 起；不再是「参考靶场」）
node e2e/benchmark-lab/run.mjs
node e2e/acceptance.mjs --only=benchmark          # 未就绪 SKIP

# 深度验证（指定清单）
BENCHMARK_CASES=e2e/benchmark-lab/cases-query.json node e2e/benchmark-lab/run.mjs
BENCHMARK_CASES=e2e/benchmark-lab/cases-header.json node e2e/benchmark-lab/run.mjs
```

当前累计（D117）：**有效 327 条 —— 真值 178/178 检出、安全 0/149 误报**；
`{call <过程名>}` 7 条单列（4 真值未检出 = 已知边界，3 安全 0 误报）。


## 边界（不得越界引用）

- **子集 ≠ 全集**：20/504，只证明「该子集上」的表现，不外推为「Benchmark 检出率 N%」。
- 官方标注 `real=false` 的用例仍可能因**别的缺陷**（如报错回显差异）产生误报 ——
  那恰恰是本裁判要抓的东西；但单例子集不足以量化。
- Benchmark 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 本套件只读（GET/POST 官方用例端点），不写业务数据。
