# 外部靶场自测全景（2026-10-21 汇总）

> 一页看清「外部裁判有哪些、各自真值多少、当前红绿、怎么复跑」。
> ⚠ 本文件是**汇总**，不是新证据：每个数字都标注来源文件与实测日期；引用以各自
> `results/` 原始报告为准。
>
> **2026-10-21 二次修订**：当日 D121 之后又做了**一轮 5 裁判全量复跑**（五个靶场全部
> 重搭、重跑），原始日志在 `external-sweep-2026-10-21-*.log`、报告在
> [`external-sweep-2026-10-21-full.md`](external-sweep-2026-10-21-full.md)。
> 该轮回溯发现本表两处**口径过期**（不是新 bug，是汇总没跟上 D113 的扩容）：
> DVWA 真值由 4 → **5**、VAmPI 安全分母由 2 → **5**，合计由 185 → **187**。
> 旧数字保留在下方「修订记录」，不删历史。

## 一、外部裁判清单（真值均来自第三方源码，非本仓断言）

| # | 裁判 | 技术栈 | 注入点形态 | 真值端点 | 当前结论 | 门禁 |
|---|---|---|---|---|---|---|
| 1 | **OWASP Juice Shop** 20.3.0 | Node + Sequelize + SQLite | query + POST JSON body | 2（搜索 LIKE、登录绕过） | ✅ 2/2 检出、0/4 误报 | acceptance `juice-shop` |
| 2 | **VAmPI** | Python + Flask + SQLAlchemy + SQLite | **URL 路径段** `/users/v1/{u}` | 1（+ 同源复检） | ✅ 1/1、0/2 误报（A/B 同形态参数化实例） | acceptance `vampi` |
| 3 | **DVWA** | PHP 8.3 + MariaDB | cookie 注入点 + POST 表单 | **5**（四档难度，含 medium 盲注 POST） | ✅ **5/5**（D113 起；本轮复跑 5/5）、impossible 0/2 误报 | acceptance `dvwa` |
| 4 | **VAmPI Bearer** | 同上 + JWT | 带认证头的参数化端点 | 安全对照 | ✅ **0/5** 误报（3 个 Bearer 安全端点 + 2 个同形态参数化） | acceptance `vampi` |
| 5 | **DVGA** | Python + Flask + Graphene + SQLite | **GraphQL 查询串内部** | 1（`pastes(filter)`） | ✅ **1/1**（D121，本轮复跑 1/1）；安全 `search(keyword)` 0 误报；此前「1/1」假阳性已作废 | 参考靶场，不接门禁 |
| 6 | **OWASP Benchmark** | Java 17 + Spring + HSQLDB | query + **HTTP header** + 参数名 | 178（D115→D117 全量） | ✅ 真值 **178/178**、安全 **0/149**（本轮按三份清单全量复跑，逐条吻合 D117 口径） | acceptance `benchmark`（74 条基线） |

合计外部真值端点：**187 个**（Juice 2 + VAmPI 1 + DVWA 5 + DVGA 1 + Benchmark 178）；
D121 后 **187/187 可打穿**，安全端点误报 0（分母 4 + 5 + 2 + 1 + 149）。

> 修订记录（§3.5「保留旧数字并标注作废」）：首版汇总写「DVWA 4 / VAmPI 安全 0/2 /
> 合计 185」，沿用的是 D112 与 D111 的口径。实际 D113 已给 DVWA 加第 5 个真值点
> （`POST /vulnerabilities/sqli_blind/`，medium 无错误回显只余布尔），并给 VAmPI 加了
> 3 个 Bearer 安全端点——当日 d113 运行实测就是 5/5（数字内联在
> `e2e/dvwa-lab/results/external-judge-2026-10-20-dvwa.md`）。**旧数字 4/185 作废**，
> 新口径 5/187 以本轮复跑日志为准。

## 二、本次自测重启的靶场

> 2026-10-21 二次复跑时**五个靶场全部重新搭起**（含此前「未起」的 DVWA 与 Benchmark），
> 下表「状态」列已按该轮更新；各靶场的从零起法见 `external-sweep-2026-10-21-full.md`。

| 靶场 | 地址 | 状态 | 复跑命令 |
|---|---|---|---|
| Juice Shop | `http://127.0.0.1:3199` | 本轮重起（v20.3.0，前端已构建） | `JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs` |
| VAmPI 漏洞实例 | `http://127.0.0.1:5000` | 本轮重起（`vulnerable=1`，`tokentimetolive=7200`） | `node e2e/vampi-lab/run.mjs` |
| VAmPI 对照实例 | `http://127.0.0.1:5001` | 本轮重起（`vulnerable=0`，参数化） | 同上（套件同时打两个实例） |
| DVGA | `http://127.0.0.1:5013` | 本轮重起 | `DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs` |
| DVWA | `http://127.0.0.1:8099` | **本轮已起**（PHP 8.3 + MariaDB 10.11） | `DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs` |
| Benchmark | `https://127.0.0.1:8443` | **本轮已起**（JDK17 + Maven 打包 + HSQLDB 9001 + cargo Tomcat） | `node e2e/benchmark-lab/run.mjs` |

## 三、DVGA 这条线的完整推翻链（本仓 §3.5 协议实例）

1. **首跑结论**（已作废）：`pastes(filter)` 检出 1/1。
2. **反证**：同一条 payload 在**手工证实不可注入**的 `search(keyword)`（ORM `like` 参数化）
   上同样报 High / CVSS 8.2 ⇒ 两条检出同源，payload 本身是追加在整个查询串之后的无效串
   （GraphQL 语法错误 400）。
3. **根因**：响应体里 payload 是 **JSON 转义形态**（`"` → `\"`），`stripEchoedPayload`
   剔不掉 ⇒ payload 自带的 `extractvalue` 命中 `ERROR_SIG`。
4. **修复**：`echoStrip.js` 变体集合补 `JSON.stringify(payload).slice(1,-1)` 及双层形态；
   契约 `server/tests/echoStrip.jsonEcho.test.js` 4 例（含 §B 弱版敏感性、§C 真报错不误删），
   缺陷注入复验：摘掉修复 → §A/§A2 红，备份还原 → 4/4 绿。
5. **中间结论（已作废）**：D114 后真值点如实变成 0/1，登记为
   `graphql-inline-injection-gap`。
6. **D121 修复**：新增 GraphQL 查询串内联字面量点（`carrier='graphql'`），保持
   `{ pastes(public: true, filter: "<PAYLOAD>") { id title } }` 骨架、只替换值位；
   真值点 **1/1**（union/error/boolean），安全点 0 误报，连续 3 轮一致。
   证据：`e2e/dvga-lab/results/external-judge-2026-10-21-d121.md`；旧 0/1 记录保留作历史。

## 四、VAmPI 这条线（本轮 D111 建立）

- **A/B 设计**：官方 `vulnerable` 开关起两个实例（5000 拼接 / 5001 参数化），
  同一路径、同一参数形态，唯一变量是官方开关 ⇒ 零误报证据钉在**同形态**上。
- **判据修正两处**（真值归类错误，非代码 bug）：
  1. 良性输入 ≠ 安全端点（漏洞实例上换良性值仍是注入点）⇒ 改「同源复检」，不并入真值分母；
  2. 被「输入校验型可证安全跳过」剪枝的 5 请求零检出不算证据 ⇒ 显式 `validationSkip:false`
     + 新增「安全端点证据不足（请求<30）」计数要求为 0。

## 五、边界（不得越界引用）

- 187 个真值端点分布在 5 个项目上，**仍不能外推为「通用外部检出率」** —— 每个项目的
  注入形态、DBMS、框架都不同，样本不独立同分布；且 Benchmark 一个项目就占 178/187。
- GraphQL 面目前只有 DVGA `pastes(filter)` **一个**真值端点（D121 已 1/1），不能外推为
  「GraphQL 通用覆盖」；block string / 裸 `application/graphql` 仍不在该通道内。
- 路径段注入点（`--test-path`）默认关闭；header 注入点（Benchmark header 形态）在 level=2
  下也不生成 ⇒ 套件显式开启的档位不代表默认配置覆盖率。
- `{call <过程名>}` 4 条真值仍未检出（Benchmark 的 7 条 call 形态里），是**已知能力边界**，
  单列不计入 178。
- 2026-10-21 二次复跑是 5 裁判**同一轮**全量重跑（各自日志见 `external-sweep-2026-10-21-*.log`）；
  但 `e2e/run-all.mjs` 全量套件未跑，DVGA 仍不接 acceptance。
