# 架构对标：sqli-scanner vs GitHub SQLi 类开源项目（2026-11-06）

> 本文只做**架构**对比，不重复 `docs/竞品对标分析-2026-10-03.md` 的能力清单 / star 数 / 检出率对标，
> 也不涉及 LLM 报告链路。口径延续 AGENTS.md §3.5：区分「实拉一手事实」与「二手叙述」。

## 0. 证据等级（先说清哪些能信）

| 等级 | 内容 | 来源 |
|---|---|---|
| A 一手实拉 | 各仓库**顶层与核心子目录树**、语言、star、pushed_at | `api.github.com/repos/{o}/{r}/contents/{path}`，2026-11-06 本机实拉 |
| A 一手实拉 | 本项目 `server/src` 分层文件数 / 行数 | 本机 `node` 遍历统计，命令见 §7 |
| B 二手叙述 | sqlmap / ghauri / jSQL 的内部状态、执行流、设计模式 | DeepWiki 索引页、`codex-infinity.com` 的 sqlmap 贡献者架构图、jSQL Architecture 页 |
| B 一手文档 | nuclei 的 Executer / Operators / RunEnumeration 设计 | 仓库内 `DESIGN.md`（WebFetch 直取原文） |
| C 未验证 | 各项目性能 / 检出率 / 误报率 | **本文一律不比**，公开评测口径互不相同 |

⚠️ B 级是别人对代码的描述，不等于我读过它们源码。凡引用 B 级结论处均标注，
落到具体改造建议前须回读对应仓库源码。**本文没有跑任何竞品的基准测试。**

---

## 1. 结论先行

1. **架构范式上，本项目站在「深度引擎」阵营，但工程分层更像平台型产品。**
   sqlmap / ghauri 是「探测引擎」，nuclei / ZAP 是「规则平台」，jSQL 是「带 GUI 的分层引擎」；
   本项目是**唯一**把深度引擎 + 三端入口 + 交付件 + 可机读结论台账揉进一个仓的形态。
2. **最值得抄的不是判定算法，是「规则数据外置」与「执行器/算子解耦」。**
   sqlmap 的 `data/xml/`、nuclei 的 YAML 模板 + `Executer` 接口、jSQL 的 `VendorYaml`
   三家不约而同把「载荷/方言/匹配规则」从引擎代码里剥出去；本项目 payload 与 tamper
   虽有 registry 与 234 个插件，但**仍是 JS 模块**，加一种方言要改代码。
3. **质量基建是全场独一份，也是唯一的架构级负债。**
   51 项门禁 + 每道 selftest + facts 指纹 + 结论台账推翻链，竞品没有第二家；
   代价是 483 个 server 源文件、7 个文件贴着 1200 行上限、e2e 目录臃肿。

---

## 2. 本项目架构基线（本机实测，2026-11-06）

`server/src` 六层，共 **483 文件 / 61,103 行**：

| 层 | 文件 | 行数 | 职责 |
|---|---:|---:|---|
| `core/` | 327 | 23,455 | HTTP 出口 / SSRF / 会话 / tamper 插件（234 个）/ payload registry |
| `engine/` | 109 | 26,242 | 检测编排与判定 |
| `services/` | 21 | 6,100 | 扫描管理、报告、导出、AI 等横切服务 |
| `api/` | 20 | 3,966 | REST 端点 |
| `config/` | 3 | 700 | 配置 |
| `mcp/` | 3 | 640 | MCP stdio 工具 |

`engine/` 内八个子域：`detectors/`(10) · `detectorSupport/`(9) · `discovery/`(3) ·
`exploit/`(8) · `extraction/`(7) · `payloads/`(9) · `scan/`(18) · `logs/`。

前端 `src/`：`components/`(68) · `hooks/` · `pages/` · `shared/` · `store/` · `tests/`(71)。

**编排链**：`ScanManager → scanRunner → scan/* 阶段模块`；CLI / REST / MCP 三入口复用
同一 ScanManager 与同一判据（arch-guard 实跑 1,034 文件 0 环，跨树 import 仅 1 处刻意对拍）。
引擎零运行时 npm 依赖（~470 文件里仅 `nanoid`）。

---

## 3. 竞品架构骨架（按范式分三类）

### 3.1 深度探测引擎：sqlmap / ghauri

**sqlmap**（Python，38,865 star，2026-11-04 push）——「全局单例 + 微内核 + 数据驱动」：

```
sqlmap.py / sqlmapapi.py        # CLI 与 REST 两个入口
lib/core/        conf、kb 两个 AttribDict 全局单例、settings、BigArray、HashDB
lib/controller/  controller.py / checks.py / action.py / handler.py   ← 编排仅 4 文件
lib/request/     connect.py(唯一出口) / comparison.py(真假 oracle) / inject.py + 22 个协议 handler
lib/techniques/  blind / dns / error / union + 11 个非 SQL 通道目录（graphql/hql/ldap/nosql/…）
lib/parse/       CLI、请求文件、HTML、sitemap、XML 载荷加载
lib/takeover/    OS 接管
plugins/generic/ 抽象基类
plugins/dbms/    30+ 个 DBMS 子目录，每库 connector/enumeration/filesystem/...
tamper/          每文件一个 tamper() 的变形管道
data/xml/        boundaries.xml / errors.xml / queries.xml / payloads/   ← 规则彻底外置
```

B 级要点：`conf`（用户配置）与 `kb`（运行期知识库）是进程全局单例，子系统直接读写；
线程 + thread-local，默认上限 10；`BigArray` 磁盘后备防拖库 OOM，`HashDB`(SQLite) 做会话续跑。
**架构含义**：加一种库/技术常只需加 XML + plugin 目录，不必动引擎；但共享可变状态使
它不适合当库嵌进多线程服务。

**ghauri**（Python，4,086 star，2025-10-04 停更）——同构但更薄：

```
ghauri/ghauri.py              # 单入口
ghauri/core/    extract.py inject.py request.py tests.py update.py   ← 核心只有 5 文件
ghauri/dbms/    fingerprint.py                                      ← 只有 1 文件
ghauri/common/ extractor/ logger/ scripts/
```

B 级要点：载荷与提取策略**内嵌代码**，无 XML 层，dbms 层退化成一个指纹文件；
不支持 UNION、无文件/OS 接管。**= 去掉编排层与数据层、把性能路径写死的 sqlmap 精简版**：
扩展弱，但每步开销小。

### 3.2 广度规则平台：nuclei / ZAP / Wapiti / pocsuite3

**nuclei**（Go，32,606 star，2026-11-05 push）——「引擎极薄、规则极厚」：

`pkg/` 23 个子包；`pkg/protocols/` 21 个（http/dns/network/headless/websocket/code/ssl/whois…）。
`DESIGN.md` 原文可核的几个接口（A 级，直取仓库文档）：

```go
type Executer interface {
    Compile() error
    Requests() int
    Execute(input string) (bool, error)
    ExecuteWithResults(input string, callback OutputEventCallback) error
}
```

- `pkg/templates` + `pkg/catalog/loader`：YAML → 编译成可运行 Template/Workflow
- `pkg/operators`：`Matchers` / `Extractors` 与协议解耦，协议只需嵌入 `operators.Operators`
- `pkg/core.ExecuteWithOpts`：引擎调度 + 请求聚类（相同 GET 合并）
- `pkg/output` 的 `Writer` 接口 + `pkg/reporting` 的 `Exporter`/`Tracker` 接口（含 SARIF）
- `pkg/protocols/common/interactsh`：OOB 关联用两个 LRU 缓存

**架构含义**：新增检测能力的成本从「写代码」降到「写 YAML」；代价是不做 payload 自适应、
不做 DBMS 指纹、不验证可利用性。SQLi 只是模板库里的一类初筛。

**pocsuite3**（Python，3,878 star，2025-02-28 停更）不是注入引擎，是 **PoC 框架**：
`pocsuite3/{api,cli,data,lib,modules,plugins,pocs,shellcodes}`；`modules/` 里是
`censys/ fofa/ shodan/ zoomeye/ hunter/ quake/ seebug/ ceye/ interactsh/ listener/ spider/`
—— **资产测绘与带外服务被做成可插拔模块**，具体漏洞逻辑在 `pocs/` 的 Python 脚本。

**ZAP**（Java，16,110 star）：Gradle 多模块，MITM 代理中枢 + `AbstractActiveScanRule`
模板方法 + `PluginFactory` 按 `ascanrules.yaml` 工厂加载 + `Alert.Builder` DTO。
SQLi 只是 50+ 条主动规则里的一条，只报「疑似」不做提取验证。

**Wapiti**（B 级）：爬虫 + 模块化 fuzz，`sql` / `blindsql` 两个独立模块按需 `-m` 加载，
SQLite 持久化会话可续跑，`wapiti_swagger` 单独解析 OpenAPI 生成请求体。

### 3.3 分层最规范：jSQL Injection

（Java，1,790 star，Maven 多模块 `model/` + `view/` + `web/`）

- `InjectionModel` 兼 MVC 被观察模型与总协调者；`MediatorVendor` 管 DBMS 识别，
  `MediatorStrategy` 管策略注册与择优
- 策略目录实拉 12 项：`StrategyUnion / Stack / Error / Multibit / BlindBit / BlindBin /
  Time / Dns` + `AbstractStrategy` + `MediatorStrategy`，按效率显式排序、失败自动降级
- `VendorYaml` 把 30+ 数据库方言外置成 YAML；`ConnectionUtil` 集中认证/CSRF/代理
- `suspendable/` 可挂起任务让长提取不冻结 GUI；`ResourceAccess` 统一后渗透入口

**架构含义**：可读性、可测试性（JUnit + Docker 化集成测试）是同类最好，
策略优先级 + vendor 配置是「自研引擎最值得参考的范本」；代价是 JVM 重、单人维护风险。

### 3.4 极简与旁路

| 项目 | 实拉结构 | 架构一句话 |
|---|---|---|
| bbqsql（834 star，2019 停更） | `bbqsql/{lib,menu,settings,utilities}` | 菜单驱动 + 盲注专用，交互式配置优先 |
| DSSS（882 star） | `dsss.py` 单文件 + `tests/` | 零架构，一个脚本打完 |
| SQLiDetector（B 级） | 单脚本 + 2 个文本清单 | 载荷表 × 签名表 × 线程池 |
| Sqlvet（B 级，Go） | AST linter | 解析 Go 源码 SQL 调用，**不发请求**，属 SAST 另一条赛道 |

---

## 4. 架构维度总表

| 维度 | sqli-scanner（本仓实测） | sqlmap | ghauri | jSQL | nuclei | ZAP |
|---|---|---|---|---|---|---|
| 状态管理 | 按扫描实例 `ScanManager`（多扫并发 + SSE） | 进程全局 `conf`/`kb` 单例 | 单链过程式 | MVC Model + 中介者 | 无状态任务队列 | 代理会话 + 规则上下文 |
| 编排层 | 三层：Manager→Runner→scan/* | `lib/controller` 4 文件 | `core/` 5 文件 | `InjectionModel` + 2 Mediator | `pkg/core.ExecuteWithOpts` | `ActiveScanner` + 线程池 |
| 规则/载荷承载 | **JS 模块 + JSON registry + 234 tamper 插件** | `data/xml` 外置 + tamper 脚本 | 代码内嵌 | YAML vendor + 策略类 | YAML 模板库（外置） | 规则类 + `ascanrules.yaml` |
| 方言扩展点 | `core/tamper/plugins` 平铺 | `plugins/dbms/<dbms>/` 子类 | 改 `fingerprint.py` | 加 `VendorYaml` | 无关 | 无关 |
| 判定与请求解耦 | `detectors/` + `detectorSupport/`，假阳性门控 | `request/comparison.py` 独立 oracle | `core/inject.py` | `ConnectionUtil` | `Executer` + `Operators` 接口 | `HttpSender` + `checkVulnerability` |
| 并发 | Node 异步 + 实例隔离 | 线程 + thread-local，≤10 | 多线程 | 可挂起任务 + 线程 | Go 高并发 + 请求聚类 | 扫描线程池 |
| 会话续跑 | 扫描实例 + 报告落盘（本仓口径） | `HashDB`(SQLite) + `BigArray` | 内建 session | GUI 可挂起 | 无状态 | 代理会话 |
| 入口形态 | **CLI / REST / MCP / Web / Tauri 同源** | CLI + `sqlmapapi.py` | CLI | Swing GUI + headless | CLI | 代理 + GUI + Automation |
| 质量基建 | **51 项门禁 + 各自证 + facts 指纹 + 推翻链** | `tests/` unittest | 无 | JUnit + Docker 集成 | fuzz + 单测 | Gradle CI |
| 运行时依赖 | 引擎零 npm 依赖 | 零第三方 Python 包 | requests 等 | Spring/Hibernate 重 | Go 模块 | JVM 插件生态 |

---

## 5. 本项目独有价值（架构层，非能力层）

1. **三入口同源被机器判据钉住**：arch-guard 0 环、跨树 import 仅 1 处刻意对拍；
   sqlmap 的 CLI 与 `sqlmapapi.py` 是两套包装，ZAP / nuclei 没有「同一 ScanManager」概念。
2. **门禁体系自身被门禁看守**：9 道 guard 每道 `--selftest`、51 项 `gate:close`、
   greenguard 防恒绿、facts 指纹防采集源漂移、结论台账保留 7 条推翻链 —— 全场唯一。
3. **交付件是一等公民**：SARIF / manifest / 退出码 0-1-2 / `dbmsEvidence` 证据等级
   写进架构契约，而非扫描完再补一个导出脚本。
4. **引擎零运行时依赖**：与 sqlmap「零第三方包」同一哲学，但落在 Node 内置能力上。

---

## 6. 可借鉴 / 现存差距（只列架构层，不动 LLM）

| 方向 | 参考谁 | 本项目现状 | 代价评估 |
|---|---|---|---|
| 规则数据彻底外置（`boundaries`/`payloads`/`errors`/`queries`） | sqlmap `data/xml/` | payload 在 JS/JSON，加方言要改代码 | 迁移 234 tamper + registry，成本高；**先做「新方言可声明化」增量即可** |
| 执行器 / 匹配算子接口化 | nuclei `Executer` + `Operators` | detector 已分层，但无统一算子接口 | 中等；可先抽 `Detector` 的 match/extract 契约 |
| 策略显式优先级 + 厂商中介者 | jSQL `MediatorStrategy` / `MediatorVendor` | 已有策略模式，DBMS 抽象平铺在 `core/` | 中等；能缓解 core 23k 行膨胀 |
| 外部资产 / OOB 服务做成可插拔模块 | pocsuite3 `modules/` | OOB 接收端内置 | 低；但会引入运行时依赖，与「零依赖」哲学冲突 |
| 插件市场 / 规则动态启停 | ZAP Add-on、nuclei 模板库 | 无外部插件生态 | 高；属产品形态决策，不只是代码改动 |
| 会话续跑与防 OOM | sqlmap `HashDB` + `BigArray` | 报告落盘；大 dump 边界未见同类机制 | 需先实测确认是否已有等价能力，**别照抄** |

**现存架构负债**（一手实测，见 `工程架构质量评估-2026-11-01.md`）：
7 个文件贴 1200 行上限（余量 25~29 行）；`core/tamper/plugins` 234 个插件平铺；
前后端 `parseRequestFile` 双实现 + `types.ts` 手工镜像后端类型；命名风格 PascalCase / camelCase 混杂。

---

## 7. 复现命令

```bash
# 本项目分层规模（本机）
node -e '/* 遍历 server/src、src 统计 .js/.ts/.tsx 文件数与行数，见本文 §2 */'

# 竞品目录树与元数据（2026-11-06 实拉，A 级）
for r in sqlmapproject/sqlmap r0oth3x49/ghauri knownsec/pocsuite3 \
         projectdiscovery/nuclei ron190/jsql-injection Neohapsis/bbqsql \
         stamparm/DSSS zaproxy/zaproxy; do
  curl -s -H 'User-Agent: sqli-scanner-arch-survey' "https://api.github.com/repos/$r/contents/"
done

# nuclei 架构原文
# https://raw.githubusercontent.com/projectdiscovery/nuclei/main/DESIGN.md
```

## 8. 口径更正（2026-11-06，D256 落码时实测发现）

**⚠️ 作废**：§1 结论 2 与 §6 表格里「本项目 payload 与 tamper 仍是 JS 模块，加一种方言
要改代码」这句**只对了一半**，按推翻协议保留原文并在此标注作废（不删历史）。

**事实（读码核实）**：

- `server/src/engine/payloadRegistry.js` 头注释明确写着「声明式 Payload 注册表
  （对标 sqlmap XML `<test>` 元素）」；**E5-2（2026-09-23）已把 681 条 payload 外置到
  `payloads/registry.json`**，另有 `registry.versioned.json`（版本特定语法族）与
  `customPayloads.js`（用户自定义条目合并）。**加一条 payload 不需要改代码**，
  且 `payloadRegistry.fingerprint.test.js` 用内容指纹钉住数据。
- 真正仍硬编码在 JS 里的是**方言知识**：`DialectSqlBuilder.js` 431 行的
  `resolveDbms` 正则链、`DIALECT_TO_DBMS` 对象、`fromDummy` / `escCols` / `nnExpr` /
  `tableRef` / `quoteCol` / `nullSafeQuoteCol` 的 switch，以及 `WRAP` / `WRAP_NOCAST` /
  `INLINE_CONCAT` / `HIGH_FREQ_DBMS` 字典 —— **加一种 DBMS 方言才要改代码**。
- 234 个 tamper 是**变形插件**（每文件一个 `tamper()` 函数），与「规则数据外置」不是
  同一层概念；把它们全量迁成数据既无收益也会破坏既有插件契约，故不迁。

⇒ 因此 §6 第一条「先做新方言可声明化增量」的方向成立，但**落点应精确为
「方言声明化」**，不是「payload 声明化」。D256 已按此实现：新建
`server/src/engine/payloads/dialects.json` 作为 18 种方言的真源，
`DialectSqlBuilder.js` 退化为纯解释器，详见 `docs/方言声明化-D256.md`。

## 9. 诚实边界

- 目录树 / star / pushed_at 是 **2026-11-06 api.github.com 实拉**，会随时间变。
- sqlmap / ghauri / jSQL / ZAP / Wapiti 的内部状态与执行流描述来自 **DeepWiki、贡献者架构图、
  公开技术文章（B 级）**，本文未逐个 clone 源码核对；要落地改造前必须回读源码。
- 本文**未**对任何竞品做性能、检出率、误报率实测，也不复述本仓 README 的门面数字。
- 与 `docs/竞品对标分析-2026-10-03.md` 的旧结论若有冲突，以**当日实拉**为准；
  旧文档里的 star / push 日期是 2026-10-03 口径，已过期，不要混用。

---

## 10. 补：几轮真靶场实测后的架构复核（2026-11-06 晚，增量）

> 只补两件事：① §3 没覆盖的一家同类项目（commix）；② 把当日几轮实测暴露的**工程模式**回映射到架构层。
> **§1~§9 结论一律不变**。若将来出现反证，按 `AGENTS.md` §3.5 走推翻流程，不在本节打补丁。
> 编号说明：本节原写 §9，与并发批次插入的新 §8/§9 撞号，顺延为 §10（两边都不动对方正文）。

### 10.1 commix（新增；Python，5,897 star，2026-11-05 push — A 级实拉）

目录骨架（`api.github.com/repos/commixproject/commix/contents/...`，2026-11-06 本机实拉）：

```
commix.py / commixapi.py      # CLI 与 REST 双入口（与 sqlmap 同构）
src/core/main.py              # 总装配
src/core/controller/          # 编排
src/core/techniques/          # results_based / boolean_based / time_based /
                              # file_based / tempfile_based / oob（6 目录）
src/core/modules/             # modules_handler.py + shellshock（注册式模块）
src/core/requests/            # 15 个切片：anticsrf / authentication / cookies /
                              # keepalive / parameters / proxy / reproduce / tor / ...
src/core/oob/ · shells/ · eval/ · parse/ · options.py
src/tamper/ · src/utils/settings.py
```

B 级（GitHub wiki「Module development」+ DeepWiki Architecture，**未 clone 源码核对**）：

- 每个 technique 目录是 `handler + injector + payloads` 三件套，`select_injector` /
  `select_payloads_module` 统一调度；
- **最轻的扩展点**：`src/utils/settings.py` 的 `MODULES` 字典（名字 → import path + handler 名），
  `load_modules()` 遍历注册表，新增模块不用改 `cmdline.py`、不用改 loader；
- `commixapi.py` + `commixapi.yaml` 提供 REST 驱动，session / JSON / CSV / HAR 输出可续跑。

**对本项目的含义**：§6 第一条「新方言可声明化」**已由 D256 方言声明化批次落地**
（见 `docs/方言声明化-D256.md` 与 §8 口径更正）。commix 的 `MODULES` 注册表在这里只是
**下一段路**的参考：不必先把载荷彻底数据化，也能拿到「加能力不改引擎」的收益 ——
先把 detector / technique 的注册从分支收敛成一张表 + 固定 handler 契约即可。
落地前须回读 `src/core/modules/modules_handler.py` 与 `settings.py`。

### 10.2 当日实测反推出的架构模式（不是新对标数据）

D252~D255（真靶场 MCP/CLI e2e、双网关 LLM 报告、429 口径修正）里反复出现的不是算法缺陷，
而是**测量配置与目标场景不一致**：单网关同 key 的 429 被外推成「双网关 429 连环」；
改完代码没用「与质疑场景相同的配置」重跑；短重试挂在 writer/reviewer，断点却在 analyst。

⇒ 架构层读法：§5 说的「质量基建 + 结论台账 + 推翻链」确实是同类独一份，
这几轮实测恰好**验证了它的价值**（错结论能被抓出来并留下推翻链）；
但也暴露仍缺一环：**「复现配置」本身没有被指纹化**。同一台机器上另一仓同日的评测
踩的是同构的坑（单席评委绝对分不可复现、CRLF 语料造成假缺陷）。
建议（架构级，未实现）：给 facts 指纹补一列 **实验配置 config digest**
（输入语料字节 + 网关/端点 + 参数快照 + 时间戳），与采集源指纹并列；
`refute_cmd` 复跑时先比配置指纹再比结果，否则「复跑」可能根本不是同一个实验。

### 10.3 优先级重排：把 §6 与 `03-architecture.md` 串起来

- §6 的「规则数据外置 + 执行器/算子接口化」是**长期架构方向**；方言层已由 D256 完成声明化，
  剩下的是执行器/算子接口化（另一会话已把它列为后续 D257）；
- `docs/vs-sqlmap-analysis/03-architecture.md` 的 P0 清单（扫描上下文/SSE 不回收、
  `sessionFile` 任意读写、`ratePerSec` 静默失效、并发无上限、配置白名单缺口）
  与当日实测暴露的是**同一类问题：契约与生命周期**；
- ⇒ 顺序应是 **先补契约/生命周期护栏，再继续扩大声明化范围**。配置面越铺越大，
  在白名单与生命周期没收敛前先扩，等于把不确定性搬进更大的配置空间。

### 10.4 边界

- commix 的目录 / star / pushed_at 为 2026-11-06 `api.github.com` 实拉（A 级），会随时间变；
  内部执行流与注册机制为 B 级二手叙述，未读源码。
- §10.2 / §10.3 是**架构建议，未实现、未跑验证**，不写进任何能力声明或对外台账。
- 本节未做性能 / 检出率 / 误报率实测，未改动 §1~§9 任何结论。

