# VAmPI 外部裁判靶场（外部裁判 2 号）

第三方外部裁判：**VAmPI**（`erev0s/VAmPI`，故意脆弱 API，官方用途即「评估第三方工具
对 API 的发现能力」）。技术栈与 1 号裁判 Juice Shop 完全不同：Python + Flask +
connexion（OpenAPI 驱动）+ SQLAlchemy + SQLite。

真值来自官方 `models/user_model.py` 的 f-string 拼接，**不是本项目编写的断言**。

## 与 Juice Shop（1 号）的分工

| | Juice Shop（1 号） | VAmPI（2 号，本靶场） |
|---|---|---|
| 注入点形态 | query（`?q=`）+ JSON body | **URL 路径段**（`/users/v1/{username}`，REST 风格） |
| 数据库 | SQLite（Sequelize ORM） | SQLite（SQLAlchemy ORM） |
| 真值数 | 2（搜索 + 登录） | 1（用户查询） |
| 安全对照 | 4 个无关端点 | **同端点 A/B**：官方 `vulnerable=0` 实例（参数化） |

## 起靶场（双实例，A/B 对照的关键）

```bash
# 1. 官方源码
curl -L https://codeload.github.com/erev0s/VAmPI/tar.gz/refs/heads/master -o vampi.tar.gz
tar xzf vampi.tar.gz && cd VAmPI-master

# 2. 隔离 venv + 依赖（Python 3.9；greenlet 在本机无 SDK 编译不了，走预编译 wheel）
python -m venv <venv-dir>
<venv>/Scripts/pip install --only-binary=:all: -r requirements.txt

# 3. 漏洞实例（官方 vulnerable 默认 1）与对照实例（vulnerable=0，参数化）
<venv>/Scripts/python app.py                              # 5000（vuln=1）
curl -s "http://127.0.0.1:5000/createdb"                  # 建库 + 灌入 name1/name2
PORT=5001 vulnerable=0 <venv>/Scripts/python run_port.py   # 5001（vuln=0）
```

⚠ 本机环境纪实：Python 3.9 + `--only-binary=:all:` 是必需的 —— 直接装会去编译
greenlet，本机 MSVC BuildTools 缺 Windows SDK 头文件（`math.h` 找不到）必然失败。

就绪探针：

```bash
curl -s "http://127.0.0.1:5000/users/v1/name1"   # {"username": "name1", "email": "mail1@mail.com"}
curl -s "http://127.0.0.1:5001/users/v1/name1"   # 同上（对照实例共用同一份 SQLite）
```

## 跑判据

```bash
VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 \
  node e2e/vampi-lab/run.mjs

# 门禁入口（未就绪会如实 SKIP）
VAMPI_VULN_BASE=http://127.0.0.1:5000 VAMPI_SAFE_BASE=http://127.0.0.1:5001 \
  node e2e/acceptance.mjs --only=vampi
```

## 真值端点

| 实例 | 端点 | 官方实现 | 类型 |
|---|---|---|---|
| 5000（vuln=1） | `GET /users/v1/{username}` | `f"SELECT * FROM users WHERE username = '{username}'"` | **SQLi** |
| 5001（vuln=0） | `GET /users/v1/{username}` | `User.query.filter_by(username=…)` | 安全对照（同形态参数化） |
| 5001（vuln=0） | `GET /users/v1/name1` | 同上 | 安全对照（良性输入） |
| 5000（vuln=1） | `GET /users/v1/name1` | 拼接但输入无注入语义 | 安全对照（不得误报） |

手工复核（官方源码语义）：

| 请求（5000） | 结果 |
|---|---|
| `/users/v1/zzz` | 404 `User not found` |
| `/users/v1/zzz' OR 1=1-- -` | 200 `{"username":"name1",...}` |
| `/users/v1/zzz' OR 1=2-- -` | 404 ⇒ 布尔可分 |
| `/users/v1/zzz' UNION SELECT 1,2,3,4,5-- -` | 200 `{"username":"2","email":"4"}` ⇒ 5 列回显 |
| `/users/v1/zzz' AND SLEEP(1)-- -` | 500（SQLite 无 sleep，Werkzeug debug 页带 SQL 错误） |

同组请求打到 5001（vuln=0）全部 404 —— 这就是「零误报」的真值来源。

## 当前证据

- `results/` 下的实跑报告（含 sqlmap 同题对照）。
- `docs/_claims-ledger.json`：`external-judge-vampi-d110`。

## 边界（不得越界引用）

- 外部真值只有 **1 个 SQLi 端点**（官方只有这一处字符串拼接），不能外推为「通用外部检出率」。
- 路径段注入点默认关闭（`--test-path`），本套件显式开启 —— 这测的是「开启后能不能打」，
  **不代表默认配置下的覆盖率**。
- VAmPI 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 双实例共用同一份 SQLite 文件（官方 `config.py` 硬编码路径），写操作会互相干扰；
  本套件只发读请求，/createdb 只在 5000 实例上执行一次。
