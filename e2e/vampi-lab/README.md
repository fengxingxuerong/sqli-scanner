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
| 认证场景 | 登录后 JSON body | **Bearer JWT**（D113 起覆盖） |
| 安全对照 | 4 个无关端点 | **同端点 A/B**：官方 `vulnerable=0` 实例（参数化）+ Bearer 门禁的 `/books/v1/{title}` |

## 起靶场（双实例，A/B 对照的关键）

```bash
# 1. 官方源码
curl -L https://codeload.github.com/erev0s/VAmPI/tar.gz/refs/heads/master -o vampi.tar.gz
tar xzf vampi.tar.gz && cd VAmPI-master

# 2. 隔离 venv + 依赖（Python 3.9；greenlet 在本机无 SDK 编译不了，走预编译 wheel）
python -m venv <venv-dir>
<venv>/Scripts/pip install --only-binary=:all: -r requirements.txt

# 3. 漏洞实例（官方 vulnerable 默认 1）与对照实例（vulnerable=0，参数化）
#    [D113] tokentimetolive 必须显式设大：官方默认 60 秒（app.py: alive=getenv(...,60)），
#    一轮扫描（100+ 请求）会跨过期 ⇒ 中途全部 401 ⇒ 真假响应恒等（假零误报/假漏检）。
tokentimetolive=7200 <venv>/Scripts/python app.py                              # 5000（vuln=1）
curl -s "http://127.0.0.1:5000/createdb"                                        # 建库 + 灌入 name1/name2
PORT=5001 vulnerable=0 tokentimetolive=7200 <venv>/Scripts/python <repo>/e2e/vampi-lab/run_port.py   # 5001（vuln=0）
```

> [D188] `npm run labs:up` 起 VAmPI 时**会自动调用 `/createdb`**（`labs.mjs` 的 `seedPath` 钩子）——
> 手工按上面步骤起时仍需自己 curl 一次；不播种则 `/users/v1/name1` 恒 500，外部裁判会因此 FAIL/SKIP。

⚠ `run_port.py` 是**本仓**提供的启动器（`e2e/vampi-lab/run_port.py`，D122 入库）：
上游 `app.py` 把端口硬编码 5000，A/B 对照必须在 5001 再起一个，所以只把 `PORT`
开放出来；`vulnerable` 仍由官方 `config.py` 读 env，未改任何业务逻辑。
在 VAmPI 源码目录内执行即可（脚本 import 的是同目录的 `config.py`）。

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

## [D113] Bearer 认证端点（`/books/v1/{title}`）

官方 `api_views/books.py:get_by_title`：`token_validator(request.headers.get('Authorization'))`
门禁 + `Book.query.filter_by(book_title=…)` 参数化查询 ⇒ **带认证头的安全端点**
（认证头在、参数化、响应可分：200 有书 / 404 无书）。

```bash
# 注册 → 登录拿 auth_token（注意响应字段名是 auth_token，不是 token）
curl -s -X POST :5000/users/v1/register -H 'Content-Type: application/json' \
  -d '{"username":"u1","password":"Password1!","email":"u1@example.com"}'
TOKEN=$(curl -s -X POST :5000/users/v1/login -H 'Content-Type: application/json' \
  -d '{"username":"u1","password":"Password1!"}' | grep -o '"auth_token":"[^"]*"')

# 加一本书（POST 也要 Bearer），然后 GET 它 —— 存在 200 / 不存在 404
curl -s -X POST :5000/books/v1 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"book_title":"mybook","secret":"s"}'
curl -s -H "Authorization: Bearer $TOKEN" :5000/books/v1/mybook
```

⚠ **cookie/header 值不做 urldecode 的同类陷阱**：探针必须按官方语义发 —— token 从
`auth_token` 字段取；登录密码官方预置用户是 `pass1`（`models/user_model.py:99`），
本套件改为**自注册**（随机用户名）以免依赖靶场种子数据。

## 当前证据

- `results/` 下的实跑报告（含 sqlmap 同题对照；D113 起含 Bearer 认证场景）。
- `docs/_claims-ledger.json`：`external-judge-vampi-d110`、`external-judge-vampi-bearer-d113`。

## 边界（不得越界引用）

- 外部真值只有 **1 个 SQLi 端点**（官方只有这一处字符串拼接），不能外推为「通用外部检出率」。
- 路径段注入点默认关闭（`--test-path`），本套件显式开启 —— 这测的是「开启后能不能打」，
  **不代表默认配置下的覆盖率**。
- [D113] Bearer 端点的注入点在路径段（book_title），套件用 `testParameter` 收敛到该点；
  **Authorization 头本身不作为注入点**（打了 token 会坏，测的就不是 SQLi）。
- VAmPI 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 双实例共用同一份 SQLite 文件（官方 `config.py` 硬编码路径），写操作会互相干扰；
  本套件的写操作只有 `/createdb` 与「注册/加书」（各一次，随机名防撞）。
