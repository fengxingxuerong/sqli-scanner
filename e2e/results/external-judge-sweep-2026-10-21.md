# 外部靶场自测全景（2026-10-21 汇总）

> 一页看清「外部裁判有哪些、各自真值多少、当前红绿、怎么复跑」。
> ⚠ 本文件是**汇总**，不是新证据：每个数字都标注来源文件与实测日期；引用以各自
> `results/` 原始报告为准。本轮（10-21）**未产生新的实测数字** —— 三个我可控的靶场
> 已重启（VAmPI 5000/5001、DVGA 5013），但引擎侧 `TargetParser.js` 正处于并发会话的
> 编辑中（半写状态、语法不合法），跑不了任何依赖引擎的 e2e，故未复跑。

## 一、外部裁判清单（真值均来自第三方源码，非本仓断言）

| # | 裁判 | 技术栈 | 注入点形态 | 真值端点 | 当前结论 | 门禁 |
|---|---|---|---|---|---|---|
| 1 | **OWASP Juice Shop** 20.3.0 | Node + Sequelize + SQLite | query + POST JSON body | 2（搜索 LIKE、登录绕过） | ✅ 2/2 检出、0/4 误报 | acceptance `juice-shop` |
| 2 | **VAmPI** | Python + Flask + SQLAlchemy + SQLite | **URL 路径段** `/users/v1/{u}` | 1（+ 同源复检） | ✅ 1/1、0/2 误报（A/B 同形态参数化实例） | acceptance `vampi` |
| 3 | **DVWA** | PHP 8.3 + MariaDB | cookie 注入点 + POST 表单 | 4（四档官方难度） | ✅ 4/4 | 见 `e2e/dvwa-lab/` |
| 4 | **VAmPI Bearer** | 同上 + JWT | 带认证头的参数化端点 | 安全对照 | ✅ 0 误报 | 见 `e2e/vampi-lab/` |
| 5 | **DVGA** | Python + Flask + Graphene + SQLite | **GraphQL 查询串内部** | 1（`pastes(filter)`） | ❌ **0/1 已知缺口**（且此前「1/1」系假阳性，已作废） | 参考靶场，不接门禁 |
| 6 | **OWASP Benchmark** | Java 17 + Spring + HSQLDB | query + **HTTP header** + 参数名 | 178（D115→D117 全量） | 真值 178/178、安全 0/149（D117 口径） | 参考 → 见 benchmark-lab |

合计外部真值端点：**185 个**（Juice 2 + VAmPI 1 + DVWA 4 + DVGA 1 + Benchmark 178），
其中 **1 个（DVGA GraphQL）打不穿**。

## 二、本次自测重启的靶场

| 靶场 | 地址 | 状态 | 复跑命令 |
|---|---|---|---|
| Juice Shop | `http://127.0.0.1:3199` | 常驻未回收 | `JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs` |
| VAmPI 漏洞实例 | `http://127.0.0.1:5000` | 本轮重启（`vulnerable=1`） | `node e2e/vampi-lab/run.mjs` |
| VAmPI 对照实例 | `http://127.0.0.1:5001` | 本轮重启（`vulnerable=0`，参数化） | 同上（套件同时打两个实例） |
| DVGA | `http://127.0.0.1:5013` | 本轮重启 | `DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs` |
| DVWA | `http://127.0.0.1:8099` | **未起**（并发会话建，进程已回收） | 见 `e2e/dvwa-lab/README.md` |
| Benchmark | `https://127.0.0.1:8443` | **未起**（需 JDK17 + Maven 打包） | 见 `e2e/benchmark-lab/README.md` |

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
5. **新结论**：真值点**如实变成 0/1** —— 引擎从未真正打穿过它；缺口登记为
   `graphql-inline-injection-gap`（需「字符串内嵌注入」能力：保持
   `{ pastes(public: true, filter: "<PAYLOAD>") { id } }` 骨架，只替换值位）。

## 四、VAmPI 这条线（本轮 D111 建立）

- **A/B 设计**：官方 `vulnerable` 开关起两个实例（5000 拼接 / 5001 参数化），
  同一路径、同一参数形态，唯一变量是官方开关 ⇒ 零误报证据钉在**同形态**上。
- **判据修正两处**（真值归类错误，非代码 bug）：
  1. 良性输入 ≠ 安全端点（漏洞实例上换良性值仍是注入点）⇒ 改「同源复检」，不并入真值分母；
  2. 被「输入校验型可证安全跳过」剪枝的 5 请求零检出不算证据 ⇒ 显式 `validationSkip:false`
     + 新增「安全端点证据不足（请求<30）」计数要求为 0。

## 五、边界（不得越界引用）

- 185 个真值端点分布在 5 个项目上，**仍不能外推为「通用外部检出率」** —— 每个项目的
  注入形态、DBMS、框架都不同，样本不独立同分布。
- `pastes(filter)` 那 1 个缺口会让「GraphQL 面」整体结论为**未覆盖**，不要在任何对外口径里
  把 GraphQL 计入已验证能力。
- 路径段注入点（`--test-path`）默认关闭；header 注入点（Benchmark header 形态）在 level=2
  下也不生成 ⇒ 套件显式开启的档位不代表默认配置覆盖率。
- 本轮未复跑（原因见文件头），表中数字的最后实测日期见各自 `results/` 报告。
