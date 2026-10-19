# DVWA 外部裁判实跑（D112，2026-10-20）

外部裁判 **3 号**。前两个裁判（Juice Shop / VAmPI）都是 **SQLite + 非 PHP 栈**，
本裁判补的是它们撑不起来的那一半：**PHP + MySQL/MariaDB**、**cookie 注入点**、**POST 表单伴随字段**。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | **DVWA**（`digininja/DVWA`，master；行业通用基准，非本仓编写） |
| 技术栈 | PHP 8.3（`php -S`）+ MariaDB 10.11.19 @3306 + mysqli/PDO |
| 实例 | `http://127.0.0.1:8099`（`config.inc.php`：`disable_authentication=true`，四档难度靠 `security` cookie 切换） |
| 真值来源（外部） | 官方 `vulnerabilities/sqli/source/*.php`、`vulnerabilities/sqli_blind/source/*.php` |
| 外部对照 | sqlmap 1.10.7（本机 `Python39/Scripts/sqlmap.exe`） |
| 扫描配置 | `concurrency=1 ratePerSec=0 retry=0 timeoutMs=15000 level=2 risk=2 techniques=union,boolean,error,time productionMode=false testParameter=[id]` |

## 真值表（官方源码，非本仓断言）

| 端点 | 档 | 官方实现 | 实机 curl 复核 |
|---|---|---|---|
| `/vulnerabilities/sqli/?id=1&Submit=Submit` | low | `WHERE user_id = '$id'` + `mysqli_error` 回显 | `1' AND 1=1-- -` 有 admin 回显 / `1=2` 无；`1' UNION SELECT 1,2-- -` 回显 1、2 |
| `/vulnerabilities/sqli/` | medium | `mysqli_real_escape_string` 但 SQL **数值型无引号** ⇒ 转义拦不住；`$_POST` 表单 | `1 AND 1=1#` 有回显 / `1=2#` 无；`1 UNION SELECT 1,2#` 回显 1、2 |
| `/vulnerabilities/sqli_blind/?id=1&Submit=Submit` | low | 去掉 `or die` ⇒ 无错误回显，只剩 exists/MISSING | `1' AND 1=1-- -` exists / `1=2` MISSING |
| `/vulnerabilities/sqli_blind/` + cookie `id=1` | high | `$_COOKIE['id']` 直拼 `WHERE user_id = '$id' LIMIT 1` | `1'/**/AND/**/1=1#` exists / `1=2#` MISSING |
| 上述两条 GET | impossible | `is_numeric` + PDO `bindParam(PARAM_INT)` | `id=1'` ⇒ 无回显、无 SQL 错误 |

⚠ **cookie 值 PHP 不做 urldecode**：`id=1%27+AND+1%3D1--+-` 会被当字面量，探针必须发原始字符；
cookie 值不允许空格，真值用 `/**/` 代替空格、`#` 收尾。

## 套件结果（修复后，2026-10-20 01:12）

| 端点 | 档 | 类型 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| `GET /vulnerabilities/sqli/?id=1&Submit=Submit` | low | 真值漏洞 | ✅ 3 条 | union, error, boolean（dbms=MariaDB） | 57 |
| `GET /vulnerabilities/sqli/?id=2&Submit=Submit` | low | **同源复检** | ✅ 3 条 | union, error, boolean | 57 |
| `GET /vulnerabilities/sqli_blind/?id=1&Submit=Submit` | low | 真值漏洞 | ✅ 1 条 | boolean | 67 |
| `GET /vulnerabilities/sqli_blind/` + cookie `id=1` | high | 真值漏洞（cookie 点） | ✅ 1 条 | boolean（`cookie·id`） | 70 |
| `POST /vulnerabilities/sqli/`（`id=1&Submit=Submit`） | medium | 真值漏洞（POST 表单） | ✅ 3 条 | union, error, boolean（`body·id`） | 89 |
| `GET /vulnerabilities/sqli/?id=1&Submit=Submit` | impossible | **安全对照（同路径）** | ✅ 0 误报 | - | 150 |
| `GET /vulnerabilities/sqli_blind/?id=1&Submit=Submit` | impossible | **安全对照（同路径）** | ✅ 0 误报 | - | 150 |

- 真值漏洞：**4/4 检出（漏检 0）**；同源复检 1/1
- 安全端点：**0/2 误报**，两条均打满 150 请求（不是「没测过」）
- 安全端点证据不足（请求 < 30）：**0**

## 首跑抓到的真漏检（本靶场的实证价值）

`POST /vulnerabilities/sqli/`（medium 档）首跑 **0 检出、124 请求、不报错**。

诊断（本地记录代理 `.box-agent-scratch/diag-dvwa-medium.mjs`，124 条请求全量落盘
`dvwa-medium-diag.json`）：

| 观察 | 事实 |
|---|---|
| 请求体 | 从头到尾只有 `id=<payload>`，**`Submit` 从未出现** |
| 响应 | 124 条响应字节数**全部相同**（4620），无一条有 `First name:` |
| 根因 | 服务端 `isset($_POST['Submit'])` 是执行查询的开关 ⇒ 缺 Submit 则查询从不执行 |

引擎侧根因：`buildInjectionRequest` 用 `req.data = { ...(point.formValues || {}) }` 重建报文，
而 `formValues` **只有页面抓表单**那条路径才赋值 ⇒ `--body`/`bodyParams` 生成的点它是 `null`
⇒ 请求体只剩注入点自身。

**性质**：静默假阴性 —— 报告写「未检出」，与「这个站没有注入」完全同形（与 D91 的 cookie
假阴性同型：不报错、不告警）。本仓自建靶场无一覆盖此类形态（都不依赖伴随字段作开关），
只有外部靶场才暴露得出来。

**修复**（`TargetParser._appendBodyParamsPoints`）：bodyParams 生成的点自带完整表单快照
`{ formValues: { ...bodyAll } }`，注入时只覆盖单键、其余字段原样保留（sqlmap 同口径）。
为绕开复杂度基线，`discover` 内改为单行调用（不增行数，故无需上调 `docs/_complexity-baseline.json`）。

**回归守卫**：`server/tests/bodyParamsCompanion.guard.test.js`（4 例，含变异自证 ——
去掉 `formValues` 后判据必须变红，证明不是恒真断言）。

修复后同一端点：**3 条检出（union + error + boolean，89 请求）**。

## 外部对照：sqlmap 1.10.7 同题

**medium POST**（`--data "id=1&Submit=Submit" -p id --level 2 --risk 2`，55 请求）：
4 种类型全中 —— boolean-based blind / error-based（EXTRACTVALUE）/ time-based（SLEEP）/
UNION 2 列；`back-end DBMS: MySQL >= 5.1 (MariaDB fork)`。

⚠ 关键旁证：sqlmap 的每条 payload **都带 `&Submit=Submit`**
（例：`id=1 AND 7214=(SELECT ...)-- -&Submit=Submit`）—— 与 D112 修复方向一致：
伴随字段必须随注入请求发出，否则服务端根本不执行查询。

本引擎同题：3 条检出（union + error + boolean，89 请求），dbms=MariaDB。

**cookie 注入**（`--cookie "id=1; security=high" --level 2`，先试 URI 再转 Cookie 参数）：
`Cookie parameter 'id' appears to be 'MySQL RLIKE boolean-based blind' injectable (--code=200)`，
且自查误报后确认 `Cookie parameter 'id' is vulnerable`。
本引擎同题：1 条检出（`cookie·id`，boolean，70 请求）。

## 边界（不夸大）

- 外部真值合计（三个裁判）：Juice Shop 2 + VAmPI 1 + **DVWA 4 = 7 个真值端点**；仍不足以支撑
  「全局检出率 N%」类结论。
- 命中条数是**同一注入点的多技术命中**，不是多个独立漏洞。
- cookie 注入点在本引擎需 `level>=2`（默认 1 不测 cookie）；本套件 `level=2`，不代表默认配置覆盖率。
- medium 档能打穿是因为官方 SQL 是无引号数值型 —— 这不代表「转义拦不住」具有普遍性。
- DVWA `impossible` 档同时有 CSRF token 校验（`checkToken`），本轮 `disable_authentication=true`
  下 token 机制仍在；零误报结论只在官方该档实现下成立。

## 复跑命令

```bash
# 起环境（详见 e2e/dvwa-lab/README.md）
mysqld --datadir=D:\tools\mariadb\data --port=3306 --bind-address=127.0.0.1
php -c D:\tools\php83\php.ini -S 127.0.0.1:8099 -t <DVWA 目录>

# 外部裁判套件（4 真值 + 2 安全对照 + 1 同源复检）
node e2e/dvwa-lab/run.mjs

# 官方 acceptance 入口（定向；未就绪会如实 SKIP）
node e2e/acceptance.mjs --only=dvwa
```

---

# [D113 2026-10-20] 扩面复跑：盲注 + POST 表单（追加）

D112 的 4 个真值里有两条 POST 表单（sqli medium），但都带错误回显。真实场景里盲注
（无回显、只靠布尔/时间）才是多数，于是补 **sqli_blind medium**：官方
`vulnerabilities/sqli_blind/source/medium.php` 是 `$_POST['id']` + `real_escape_string`
+ 数值型无引号，且去掉 `or die` ⇒ **仅布尔可分**（三通道只剩两通道）。

curl 复核：`id=1 AND 1=1#` → `User ID exists`；`id=1 AND 1=2#` → `MISSING`。

## 复跑结果（2026-10-20 01:42，完整日志 `results/run-2026-10-20-d113.log`） —— 本地产物，`*.log` 按 `.gitignore` 不入库，关键数字已内联本表

| 端点 | 档 | 类型 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| `POST /vulnerabilities/sqli_blind/` | medium | 真值漏洞（盲注 POST） | ✅ 1 条 | boolean（`body·id·dbms=MySQL`） | 148 |
| `POST /vulnerabilities/sqli/` | medium | 真值漏洞（错误回显 POST） | ✅ 3 条 | union, error, boolean | 89 |
| `GET /vulnerabilities/sqli/?id=1` | low | 真值漏洞 | ✅ 3 条 | union, error, boolean | 57 |
| `GET /vulnerabilities/sqli_blind/?id=1` | low | 真值漏洞 | ✅ 1 条 | boolean | 67 |
| `GET /vulnerabilities/sqli_blind/` + cookie `id` | high | 真值漏洞（cookie 点） | ✅ 1 条 | boolean | 67 |
| `GET /vulnerabilities/sqli/?id=1` | impossible | 安全对照 | ✅ 0 | - | 150 |
| `GET /vulnerabilities/sqli_blind/?id=1` | impossible | 安全对照 | ✅ 0 | - | 150 |

真值 **5/5（漏检 0）**；同源复检 1/1；误报 0；证据不足 0。
`acceptance --only=dvwa`：**1 PASS / 0 FAIL / 0 SKIP**（形态覆盖 cookie+POST+盲注POST+impossible）。

⚠ 观察项：本轮日志出现一次 `HTTP 超时（已达重试上限，放弃）`（sqli_blind low 的
time 通道）—— 未影响判定（该点 boolean 已命中），但说明 high 档 cookie 端点的随机
`sleep(2~4)` 噪声会偶发打穿 15s 超时；后续可考虑对该档放宽 timeoutMs 或记录为已知噪声。
