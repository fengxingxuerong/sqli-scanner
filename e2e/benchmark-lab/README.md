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

# 4. 编译 + 部署（cargo 起 tomcat + 自动下 tomcat；HSQLDB 文件库自动建）
cd BenchmarkJava-master
JAVA_HOME='D:\tools\jdk\jdk-17.0.2' \
  mvn initialize clean package cargo:run -Pdeploy \
    -Dspotless.check.skip=true -Dspotless.apply.skip=true
#    就绪后：https://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00025（自签证书）
#    ⚠ tarball 没有 origin/master，Spotless 的 apply 会直接失败；必须跳过（本机实测）。
```

⚠ 坑：
- `java.target=8` 但 **javac 必须来自真 JDK**；只有 JRE 时 maven-compiler-plugin 报
  `Could not retrieve version from javac`（报错信息是中文乱码，容易看错方向）。
- cargo 会自己下载 tomcat（走 maven 中央/aliyun 镜像），首次几分钟。
- war 的 finalName 是 `benchmark` ⇒ URL 前缀 `/benchmark/`；端口 cargo 默认 8080。

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

## 复跑

```bash
BENCHMARK_BASE=https://127.0.0.1:8443/benchmark node e2e/benchmark-lab/run.mjs
# 当前是参考/缺口靶场，不接 acceptance；实跑证据在 results/benchmark-2026-10-20.md。
```

## 边界（不得越界引用）

- **子集 ≠ 全集**：20/504，只证明「该子集上」的表现，不外推为「Benchmark 检出率 N%」。
- 官方标注 `real=false` 的用例仍可能因**别的缺陷**（如报错回显差异）产生误报 ——
  那恰恰是本裁判要抓的东西；但单例子集不足以量化。
- Benchmark 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 本套件只读（GET/POST 官方用例端点），不写业务数据。
