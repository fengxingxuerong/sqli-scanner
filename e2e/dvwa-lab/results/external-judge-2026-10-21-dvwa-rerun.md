# DVWA 外部裁判 3 号 · 2026-10-21 全量复跑（真值 5/5）

> 第三方靶场：`digininja/DVWA`（PHP 8.3 + MySQLi/PDO + MariaDB 10.11）。
> 真值来自官方四档难度源码（`vulnerabilities/sqli/source/*.php`、
> `vulnerabilities/sqli_blind/source/*.php`），不是本仓断言。
> 本文件是 2026-10-21 复跑证据；D112 首跑报告见 `external-judge-2026-10-20-dvwa.md`。

## 与 D112 首跑的区别

D112 报告写「真值 4/4」。该数字**在 D113 当天就已过期**：D113 给本套件加了第 5 个真值点
（`POST /vulnerabilities/sqli_blind/`，medium 档无错误回显、只剩布尔可分），当天的
当日 d113 运行的实际结果就是 5/5（数字内联在 `external-judge-2026-10-20-dvwa.md`）。本轮把报告与口径一并对齐，旧 4/4 保留为历史。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | DVWA master（`disable_authentication=true`，四档难度靠 `security` cookie 切换） |
| 栈 | PHP 8.3（`D:\tools\php83`，`mysqli`/`pdo_mysql`）+ MariaDB 10.11.19 @3306 |
| 地址 | `http://127.0.0.1:8099`（`php -S`，避开 Juice 3199 / VAmPI 5000,5001） |
| 库 | `dvwa` / 专用账号 `dvwa`；`setup.php` 需先 GET 抠 `user_token`（**单引号** value）再 POST |

## 命令

```bash
DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs
```

## 结果（本轮实测）

| 端点 | 档 | 类型 | 结果 |
|---|---|---|---|
| `GET /vulnerabilities/sqli/?id=1&Submit=Submit` | low | 真值（`WHERE user_id = '$id'`） | ✅ vulns=3，57 请求，union+error+boolean，dbms=MariaDB |
| 同上换 `id=2` | low | 同源复检 | ✅ vulns=3，57 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1` | low | 真值（去掉 `or die`，仅 exists/MISSING） | ✅ vulns=1，67 请求，boolean |
| `GET` + `Cookie: id=1` @`sqli_blind` | high | 真值（`$_COOKIE['id']` 直拼） | ✅ vulns=1，67 请求，boolean |
| `POST /vulnerabilities/sqli/` | medium | 真值（`real_escape_string` 但数值型无引号） | ✅ vulns=3，89 请求，union+error+boolean |
| `POST /vulnerabilities/sqli_blind/` | medium | 真值（无错误回显，仅布尔） | ✅ vulns=1，148 请求，boolean |
| `GET /vulnerabilities/sqli/?id=1` | impossible | 安全（`is_numeric` + PDO prepare） | ✅ 0 误报，150 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1` | impossible | 安全（同上 + CSRF token） | ✅ 0 误报，150 请求 |

汇总：**真值 5/5、同源复检 1/1、安全端点 0/2 误报、证据不足 0**；退出码 0。
一处 `HTTP 超时（已达重试上限）` 告警出现在 blind-low 的单个探针上，该点仍判检出，不影响结论。

## 这条线钉住了什么

- **PHP + MySQL 方言**：前两个裁判（Juice Shop / VAmPI）都是 SQLite，MySQL 的 `#` 注释、
  `LIMIT`、`information_schema` 结构与 `mysqli_error` 回显形态在这里才有外部证据。
- **cookie 位置注入点**（high 档）：注入点在 `Cookie: id`，不在 URL/body —— 这条形态
  只有 DVWA 提供。
- **同路径 A/B 由官方源码保证**：`impossible` 档用 PDO 参数化 + `is_numeric`，与 low/medium
  同一路径同一参数名 ⇒ 零误报证据钉在**同形态**上，而非「另找几个无关安全端点」。

## 边界

- 5 个真值点分布在 2 个漏洞页（`sqli` / `sqli_blind`），不是 5 个独立应用；不能外推
  「PHP 生态覆盖率」。
- `disable_authentication=true`：本轮裁判对象是注入点形态，DVWA 的登录流程不是判据
  （登录态由 Juice Shop 套件覆盖）。
- 需手动起靶场（PHP + MariaDB），因此仍以 `acceptance --only=dvwa` 的定向形态接入，
  不是常驻门禁。
