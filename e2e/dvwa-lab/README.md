# DVWA 外部裁判 3 号（PHP + MySQL 栈）

第三方靶场：`digininja/DVWA`（Damn Vulnerable Web Application）。
**外部裁判**的含义：真值不是本仓编写的断言，而是官方源码的分档实现。

## 为什么需要第三个外部裁判

| 裁判 | 栈 | 注入点形态 | 缺口 |
|---|---|---|---|
| Juice Shop（D88/D109） | Node + Sequelize + **SQLite** | query / JSON body | 非 PHP、非 MySQL |
| VAmPI（D110） | Python + SQLAlchemy + **SQLite** | URL 路径段 | 非 PHP、非 MySQL |
| **DVWA（D112）** | **PHP + mysqli/PDO + MySQL(MariaDB)** | GET query / POST 表单 / **cookie** | — |

只靠前两个裁判，「检出率」结论实际只证明「本引擎在 SQLite 上能打」。
MySQL 的差异（`#` 注释、`LIMIT`、`information_schema` 结构、`mysqli_error` 回显形态）需要独立证据。

## 环境准备（本机实测配方）

前置：PHP 8.3（`D:\tools\php83`，需 `pdo_mysql` / `mysqli` / `mbstring`）+ MariaDB 10.11（`D:\tools\mariadb`）。

```bash
# 1) 拉源码（codeload 可用；bash curl -L -o 在沙箱会被拦，改用 PowerShell Invoke-WebRequest）
Invoke-WebRequest https://codeload.github.com/digininja/DVWA/tar.gz/refs/heads/master -OutFile dvwa.tar.gz
tar -xzf dvwa.tar.gz        # → DVWA-master/

# 2) 建库与专用账号（MariaDB 起在 3306）
mysql -h 127.0.0.1 -P 3306 -u root -proot -e \
  "CREATE DATABASE IF NOT EXISTS dvwa; CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL ON dvwa.* TO 'dvwa'@'%'; FLUSH PRIVILEGES;"

# 3) 写 config/config.inc.php（db_user=dvwa / db_password=p@ssw0rd / db_port=3306）
#    本轮 disable_authentication=true（裁判对象是注入点形态，登录态已由 Juice Shop 覆盖）

# 4) 起 PHP 内置服务器（8099 避开 Juice Shop 3199 / VAmPI 5000,5001）
php -c D:\tools\php83\php.ini -S 127.0.0.1:8099 -t DVWA-master

# 5) 建表：setup.php 有 CSRF token ⇒ 先 GET 抠 user_token（value 用**单引号**），再 POST
#    form 字段名：create_db=Create / Reset Database
```

⚠ 两个坑：
- `config.inc.php` 必须保留 `$DBMS = ...`（缺失会在 `dvwaPage.inc.php` 报 Undefined variable）。
- setup 表单的 `user_token` 属性是 `value='...'`（单引号），按双引号 grep 会抠不到 token。

## 真值（官方源码，非本仓断言）

| 端点 | 源码 | 官方实现 |
|---|---|---|
| `/vulnerabilities/sqli/` low | `source/low.php` | `WHERE user_id = '$id'` 直拼 + `mysqli_error` 回显 |
| `/vulnerabilities/sqli/` medium | `source/medium.php` | `mysqli_real_escape_string`，但 SQL 是**数值型无引号** ⇒ 转义拦不住；POST 表单 |
| `/vulnerabilities/sqli_blind/` low | `source/low.php` | 去掉 `or die` ⇒ 无错误回显，只剩 exists / MISSING 布尔 |
| `/vulnerabilities/sqli_blind/` high | `source/high.php` | `$_COOKIE['id']` 直拼 ⇒ **cookie 注入点**；MISSING 分支 `rand(0,5)==3` 时 sleep 2~4s |
| `/vulnerabilities/sqli/` impossible | `source/impossible.php` | `is_numeric` + PDO `bindParam(PARAM_INT)` ⇒ 官方「不可利用」档（A/B 对照） |

实机 curl 复核（写进 results 报告）：

```
sqli low  id=1                       → First name: admin / Surname: admin
sqli low  id=1'                      → You have an error in your SQL syntax ... near ''1'''
sqli low  id=1' AND 1=1-- -          → 有 admin 回显；1=2 → 无回显        ⇒ 布尔可分
sqli low  id=1' UNION SELECT 1,2-- - → 回显 1 / 2                          ⇒ UNION 2 列
blind low id=1' AND 1=1-- -          → User ID exists；1=2 → MISSING
blind high cookie id=1'/**/AND/**/1=1# → exists；1=2 → MISSING            ⇒ cookie 点可分
sqli impossible id=1'                → 无回显、无 SQL 错误（is_numeric 拦死）
```

⚠ **cookie 值 PHP 不做 urldecode**：`id=1%27+AND+1%3D1--+-` 会被当字面量，`$_COOKIE` 里
必须发原始字符。cookie 值不允许空格，真值探针用 `/**/` 代替空格、`#` 收尾。

## 判据口径（与前两个裁判一致）

- 真值漏洞端点必须检出（`❌漏检` 即判红）。
- impossible 档（同路径、官方 PDO 参数化）必须 **0 检出**。
- 安全端点必须**真打满请求**：`< 30` 请求记为「证据不足」并判红 —— impossible 档的
  `is_numeric` 会命中「输入校验型可证安全跳过」剪枝，故显式 `validationSkip:false`
  （VAmPI 已栽过一次：几个请求的 0 检出不是零误报证据）。
- 靶场未就绪 ⇒ 打印 `[SKIP]` 并 **exit 0**，由 acceptance 读文本判据判为 SKIP（不计通过）。

## 复跑

```bash
node e2e/dvwa-lab/run.mjs                       # 默认 http://127.0.0.1:8099
DVWA_BASE=http://127.0.0.1:8099 node e2e/dvwa-lab/run.mjs
```
