# VAmPI 外部裁判实跑（D110，2026-10-19）

外部裁判 **2 号**：OWASP Juice Shop（1 号）之后，第二个**独立第三方项目**。
补齐的是 1 号没有的注入点形态 —— **URL 路径段（REST 风格 `/users/v1/{username}`）**。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | **VAmPI**（`erev0s/VAmPI`，master；官方定位即「评估第三方工具对 API 的发现能力」） |
| 技术栈 | Python 3.9 + Flask 2.2.2 + connexion 2.14.2（OpenAPI 驱动）+ SQLAlchemy 2.0.2 + **SQLite** |
| 实例 | `5000` = 官方 `vulnerable=1`（拼接）／`5001` = `vulnerable=0`（参数化） |
| 真值来源（外部） | 官方 `models/user_model.py:72`：`f"SELECT * FROM users WHERE username = '{username}'"` |
| 外部对照 | sqlmap **1.10.7** |
| 扫描配置 | `concurrency=1 ratePerSec=0 retry=0 timeoutMs=12000 level=2 risk=2 techniques=union,boolean,error,time testPath=true productionMode=false` |

⚠ **路径段注入点默认关闭**（`--test-path`，零回归设计）。本套件显式开启，测的是
「开启后能否打穿」，**不代表默认配置下的覆盖率**。

## 复跑命令

```bash
# 外部裁判套件（1 真值 + 2 安全对照 + 1 同源复检）
VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 \
  node e2e/vampi-lab/run.mjs

# 官方 acceptance 入口（定向；未就绪会如实 SKIP）
VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 \
  node e2e/acceptance.mjs --only=vampi
```

## 套件结果

| 实例 | 端点 | 类型 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| 5000（vuln=1） | `GET /users/v1/zzz` | 真值漏洞 | ✅ 检出 | union, error, boolean | 95 |
| 5001（vuln=0） | `GET /users/v1/zzz` | 安全对照（同形态参数化） | ✅ 0 误报 | - | 123 |
| 5001（vuln=0） | `GET /users/v1/name1` | 安全对照（良性输入） | ✅ 0 误报 | - | 144 |
| 5000（vuln=1） | `GET /users/v1/name1` | **同源复检**（同点换良性值） | ✅ 检出 | union, error, boolean | 75 |

- 真值漏洞：**1/1 检出（漏检 0）**，命中明细 `path·zzz·dbms=SQLite`（3 条，三通道各一）
- 同源复检：1/1（换良性取值仍检出 ⇒ 判据不是「输入里带引号」的模式匹配）
- 安全端点：**0/2 误报**，且两条都打满请求（123 / 144），不是「没测过」
- 安全端点证据不足（请求 < 30）：**0**

## 真值手工复核（官方源码语义）

| 请求 | 5000（vuln=1） | 5001（vuln=0） |
|---|---|---|
| `/users/v1/zzz` | 404 `User not found` | 404 |
| `/users/v1/zzz' OR 1=1-- -` | 200 `{"username":"name1",...}` | 404 |
| `/users/v1/zzz' OR 1=2-- -` | 404（⇒ 布尔可分） | 404 |
| `/users/v1/zzz' UNION SELECT 1,2,3,4,5-- -` | 200 `{"username":"2","email":"4"}`（⇒ 5 列回显） | 404 |
| `/users/v1/zzz' AND SLEEP(1)-- -` | 500（SQLite 无 sleep，Werkzeug debug 页带 SQL 错误） | 404 |

同组请求在 5001 上**全部 404** —— 这就是「零误报」的真值：官方开关把同一路径从
拼接换成 `User.query.filter_by(...)` 参数化，唯一变量是 `vulnerable`。

## sqlmap 同题对照

```bash
# ⚠ 基线必须用存在的用户（name1 → 200）：用 zzz 起手会被 404 直接劝退
# （sqlmap 报 [CRITICAL] page not found (404) 并终止，需 --ignore-code=404）
sqlmap -u "http://127.0.0.1:5000/users/v1/name1*" --batch --ignore-code=404 \
  --level=3 --risk=2 --technique=BEUST --time-sec=2
```

| 项 | sqlmap 1.10.7 | 本引擎 |
|---|---|---|
| 注入点 | URI `#1*` | `path`（pathSegment） |
| 技术 | boolean-based blind（AND）、UNION（5 列） | boolean、union、error |
| DBMS | SQLite | SQLite |
| 请求数 | 51 | 95 |

两侧在同一外部真值上结论一致；这是**同题对照**，不是检出率胜负。
本引擎多出的 `error` 通道来自 Werkzeug debug 页的 SQL 报错回显（sqlmap 已确认注入后
主动停止后续测试，未继续跑 error 面）。

## 本批在判据上修正的两处（不是代码 bug，是**真值归类**错误）

1. **良性输入 ≠ 安全端点**：首版把 5000 实例的 `/users/v1/name1` 当安全对照，
   结果判为「误报」。实际该点就是官方拼接的注入点，**输入良性不改变「点可注入」这一事实**
   —— 是套件把真值归类错了。现已改为「同源复检」并**单列统计、不并入真值分母**
   （并入即把 1 个真值灌成 2 个）。
2. **5 个请求的 0 检出不是零误报证据**：5001 的 `/users/v1/name1` 被
   「输入校验型可证安全跳过」剪枝（基线 200 → 单引号 404 → 良性非法值同构），
   整点只发 5 个请求。这与本仓在 Juice Shop 首版栽过的形状相同（没测过 ≠ 通过）。
   现对该点显式 `validationSkip:false` 关掉剪枝，打满 144 请求后才计入零误报；
   套件另设 `安全端点证据不足（请求<30）` 计数并要求为 0。

## 边界（不得越界引用）

- **单轮**实跑；外部真值只有 **1 个 SQLi 端点**（官方只有这一处字符串拼接），
  不能外推为「通用外部检出率」。两个外部裁判合计真值 3 个端点（Juice Shop 2 + VAmPI 1）。
- 3 条 finding 是**同一注入点的三种技术命中**，不是 3 个独立漏洞。
- 双实例共用同一份 SQLite 文件（官方 `config.py` 硬编码路径）；本套件只发读请求。
- VAmPI 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 本报告对应提交前的工作区状态；运行产生的 `e2e/results/acceptance-report.partial.md`
  按 `.gitignore` 不入库，本文件保留关键事实与复跑命令。

---

# [D113 2026-10-20] 认证场景扩面：Bearer JWT + BOLA 端点（复跑追加）

D110 只覆盖「匿名、无认证头」。真实渗透中扫描器几乎总是带着会话打的，而本仓最贵的
一类教训恰恰出在认证链路上 —— **D91**：`--header "cookie:"` 双处存储 + axios 同名
大小写头后写赢，124 个探针全打在未注入的值上，**静默假阴性**。本轮把 VAmPI 的认证面
纳入外部裁判。

## 靶场调整（必须）

官方 token 默认 **60 秒**过期（`app.py: alive = getenv('tokentimetolive', 60)`）⇒
一轮 100+ 请求的扫描会跨过期 ⇒ 中途全部 401 ⇒ 真假响应恒等（**假零误报 / 假漏检**）。
起靶场时显式 `tokentimetolive=7200`（官方 env，README 已载）。

## 端点与结果（2026-10-20 01:41 复跑，完整日志 `results/run-2026-10-20-d113.log`） —— 本地产物，`*.log` 按 `.gitignore` 不入库，关键数字已内联本表

| 实例 | 端点 | 类型 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| 5000 | `GET /users/v1/zzz` | 真值漏洞 | ✅ 3 条 | union, error, boolean（`path·zzz·dbms=SQLite`） | 95 |
| 5000 + Bearer | `GET /users/v1/zzz` | 真值漏洞（认证场景） | ✅ 3 条 | union, error, boolean | 95 |
| 5000 + Bearer | `GET /users/v1/name1` | 同源复检（认证场景） | ✅ 3 条 | union, error, boolean | 69 |
| 5000 | `GET /users/v1/name1` | 同源复检 | ✅ 3 条 | union, error, boolean | 75 |
| 5001 | `GET /users/v1/zzz` | 安全对照 | ✅ 0 | - | 123 |
| 5001 | `GET /users/v1/name1` | 安全对照（良性输入） | ✅ 0 | - | 144 |
| 5001 + Bearer | `GET /books/v1/{存在}` | 安全端点（认证 + 参数化） | ✅ 0 | - | 123 |
| 5001 + Bearer | `GET /books/v1/{不存在}` | 安全端点（404 分支） | ✅ 0 | - | 122 |
| 5000 + Bearer | `GET /books/v1/{存在}` | 安全端点（vuln 实例上仍参数化） | ✅ 0 | - | 144 |

- 真值漏洞 **2/2（漏检 0）**；同源复检 **2/2**；安全端点误报 **0/5**；证据不足 **0**；
  Bearer 端点 **5 个全部实跑（未测 0）**。
- `acceptance --only=vampi`：**1 PASS / 0 FAIL / 0 SKIP**。

## 首跑抓到的一处判据缺口（本轮同款陷阱第二次）

5000 的 `/books/v1/{title}`（Bearer）首跑只发 **5 请求** —— 被「输入校验型可证安全
跳过」剪枝（基线 200 → 单引号 404 ⇒ 判为白名单拦死）。这正是 D111 已栽过的形状
（**5 请求的 0 检出不是零误报证据**）。处置：对该点显式 `validationSkip:false`，
打满 144 请求后才计入零误报。同类端点（books 三条）现在全部强制打满。

## 边界

- Bearer 端点的注入点在**路径段**（book_title）；`Authorization` 头本身不作为注入点
  （打了 token 会坏，测的就不是 SQLi）—— 用 `testParameter` 收敛。
- 登录链路是「自注册 → 登录」，不依赖靶场种子用户（官方预置用户密码是 `pass1`，
  但依赖种子数据会让靶场重建后判据失效）。
- 三个外部裁判合计真值端点 7 个（Juice Shop 2 + VAmPI 1 + DVWA 4），仍不能外推
  「全局检出率 N%」。
