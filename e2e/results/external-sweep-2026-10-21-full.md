# 外部靶场全量复跑 · 2026-10-21（同一轮，5 裁判）

> 与 `external-judge-sweep-2026-10-21.md`（**汇总**，逐数字引用各自旧报告）的区别：
> 本文件是**本轮自测的原始证据**——5 个外部裁判全部在本机重新起靶场、重新跑判据，
> 数字全部来自本轮日志，不是拼凑既有报告。真值仍来自第三方源码，非本仓断言。
>
> ⚠ 日志留档方式：仓库 `.gitignore` 排除 `*.log`（既有约定，`e2e/**/results/*.log` 一律
> 不入库），因此本轮原始日志只作**本地留档**，文件名见各节；可复核数字已**内联到本文件
> 的表格**，不依赖日志能否取到。复跑命令逐条给出。

## 一、环境与靶场（本轮全部重新搭建）

| 靶场 | 版本/栈 | 地址 | 起法 |
|---|---|---|---|
| OWASP Juice Shop | v20.3.0，Node 24.15.0 + Sequelize + SQLite | `http://127.0.0.1:3199` | `npm install --omit=dev --ignore-scripts` → `npm rebuild sqlite3` → 前端 `npm install && npm run build` → `npx tsc --moduleResolution node` → `PORT=3199 node build/app` |
| VAmPI（漏洞实例） | master，Python 3.9.4 + Flask 2.2.2 + SQLAlchemy 2.0.2 | `http://127.0.0.1:5000` | `tokentimetolive=7200 python app.py` |
| VAmPI（对照实例） | 同上，`vulnerable=0`（参数化） | `http://127.0.0.1:5001` | `PORT=5001 vulnerable=0 tokentimetolive=7200 python run_port.py` |
| DVGA | master 2.2.0，Python 3.9.4 + Graphene 2.1.9 + SQLite | `http://127.0.0.1:5013` | `python setup.py` 建库 → `WEB_PORT=5013 python app.py` |
| DVWA | master，PHP 8.3 + MariaDB 10.11.19 | `http://127.0.0.1:8099` | MariaDB @3306 → `php -S 127.0.0.1:8099`；`disable_authentication=true` |
| OWASP Benchmark | master 1.2，JDK 17.0.2 + Maven 3.9.11 + Tomcat(cargo) + HSQLDB 2.7.4 | `https://127.0.0.1:8443/benchmark`（自签） | `mvn initialize clean package -Pdeploy -DskipTests -Dspotless.*.skip=true` → 手动起 HSQLDB @9001 → `mvn cargo:run -Pdeploy` |

本轮同时把 `run_port.py` 正式入库到 `e2e/vampi-lab/`（此前 README 引用、目录内缺文件；上游 `app.py` 硬编码 5000，A/B 对照需在 5001 再起一个）。
环境侧两个必须记的坑：DVGA 的 `promise==2.3` / `graphql-core==2.3.2` 在 Python 3.9 上
**没有 wheel**，须 `--no-binary=:all: --no-build-isolation` 且先把 setuptools 降到 `<70`；
Benchmark 打 war 后**必须手动**起 HSQLDB（ant `<daemons>` fork 的进程随 mvn 退出被回收）。

## 二、逐裁判结果（本轮实测）

### 1 号 · OWASP Juice Shop —— ✅ 真值 2/2、安全 0/4

| 端点 | 类型 | 结果 |
|---|---|---|
| `GET /rest/products/search?q=apple` | 真值（`routes/search.ts` LIKE 拼接） | ✅ vulns=1，98 请求，boolean |
| `POST /rest/user/login` | 真值（`routes/login.ts` 直拼） | ✅ vulns=2，111 请求，error+boolean |
| `GET /rest/products/search?q=banana` | 同源复检 | ✅ vulns=1，98 请求 |
| `/api/Feedbacks/?limit=2` `/api/Challenges/?name=` `/rest/user/security-question?email=` `/api/Products/?name=` | 安全 ×4 | ✅ 0 误报（124/174/124/124 请求） |

### 2 号 · VAmPI —— ✅ 真值 2/2（同一注入点，匿名 + Bearer）、安全 0/5

| 端点 | 类型 | 结果 |
|---|---|---|
| `GET /users/v1/zzz` | 真值（`models/user_model.py:72` f-string） | ✅ vulns=3，95 请求，union+error+boolean，dbms=SQLite |
| 同端点 + Bearer | 真值（D91 认证夹击回归面） | ✅ vulns=3，95 请求 |
| `GET /users/v1/name1`（vuln 实例，良性值） | 同源复检 | ✅ vulns=3（匿名 75 请求 / Bearer 69 请求） |
| `GET /users/v1/zzz` `.../name1` @5001 | 安全（`vulnerable=0` 参数化，同路径同形态） | ✅ 0 误报（123/144 请求） |
| `GET /books/v1/{title}` @5000/@5001 + Bearer | 安全（`filter_by` 参数化 + token 门禁） | ✅ 0/3 误报（123/122/144 请求） |

证据不足（请求<30）：0；Bearer 端点 5 个，未测 0。

### GraphQL 面 · DVGA —— ✅ 真值 1/1、安全 0 误报

| 端点 | 类型 | 结果 |
|---|---|---|
| `POST /graphql` `{ pastes(public:true, filter:"x"){…} }` | 真值（`core/views.py:320` 拼接） | ✅ vulns=3，98 请求，union+error+boolean |
| `POST /graphql` `{ pastes(public:true){…} }` | 结构对照（无字面量） | ✅ 0 点 / 0 请求（按设计，不计证据） |
| `POST /graphql` `{ search(keyword:"x"){…} }` | 安全（ORM `like` 参数化） | ✅ 0 误报，124 请求 |

命中明细为 `body·query.filter·dbms=SQLite` ⇒ D121 的 `carrier='graphql'` 内联字面量点生效，
替换的是 GraphQL 查询串里的值位，不是整串。

### 3 号 · DVWA —— ✅ 真值 5/5、安全 0/2

| 端点（官方难度档） | 类型 | 结果 |
|---|---|---|
| `GET /vulnerabilities/sqli/?id=1&Submit=Submit`（low，直拼） | 真值 | ✅ vulns=3，57 请求，union+error+boolean，dbms=MariaDB |
| 同点换 `id=2` | 同源复检 | ✅ vulns=3，57 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1`（low，无错误回显） | 真值 | ✅ vulns=1，67 请求，boolean |
| `GET` + `Cookie id=1` @`sqli_blind`（high，`$_COOKIE` 直拼） | 真值 | ✅ vulns=1，67 请求，boolean |
| `POST /vulnerabilities/sqli/`（medium，`real_escape_string` + 数值型无引号） | 真值 | ✅ vulns=3，89 请求，union+error+boolean |
| `POST /vulnerabilities/sqli_blind/`（medium） | 真值 | ✅ vulns=1，148 请求，boolean |
| `GET /vulnerabilities/sqli/?id=1`（impossible，PDO 参数化） | 安全 | ✅ 0 误报，150 请求 |
| `GET /vulnerabilities/sqli_blind/?id=1`（impossible） | 安全 | ✅ 0 误报，150 请求 |

一条 `HTTP 超时（已达重试上限）` 告警出现在 blind-low 的某次探针上，该端点仍判检出，不影响结论。

### 4 号 · OWASP Benchmark —— ✅ 真值 178/178、安全 0/149

本轮按注入面跑完**三份清单**（不是子集抽样）：

| 清单 | 条数 | 真值 | 安全 | 结果 |
|---|---|---|---|---|
| `cases-query.json`（query 形态全量） | 210 | 111 | 99 | ✅ 111/111 检出、0/99 误报 |
| `cases-header.json`（header 形态全量） | 67 | 33 | 34 | ✅ 33/33 检出、0/34 误报 |
| `cases.json`（门禁基线，含参数名形态） | 74 | 43 | 24 | ✅ 43/43 检出、0/24 误报；`{call}` 4 真值未检出（已知边界，不计分母）、3 安全 0 误报 |

三份清单真值 111 + 33 + 34（参数名形态经基线覆盖=34）= **178**，与 D117 登记口径逐条吻合；
安全 99 + 34 + 16 = **149**。证明 `header` 与参数名两条注入面在 `level=2` 下都能实际打到。
命中 DBMS 一律 `HSQLDB`；其中若干用例走了 `[filter-adaptive]` 双写链重跑后以 `error` 通道命中。

## 三、与既有登记的差异（本轮实测纠正）

| 项 | 汇总文档原记 | 本轮实测 | 性质 |
|---|---|---|---|
| DVWA 真值端点数 | 4（四档难度） | **5** | 文档口径过期：D113 已加「盲注 + POST 表单（medium）」第 5 点，当日 d113 运行即 5/5（数字内联在 `e2e/dvwa-lab/results/external-judge-2026-10-20-dvwa.md`），汇总表沿用了 D112 的 4/4 |
| VAmPI 安全端点误报分母 | 0/2 | **0/5** | 同上：D113 扩了 3 个 Bearer 安全端点，分母仍写 D111 的 2 |
| 外部真值端点合计 | 185 | **187** | 前两项相加（2+1+5+1+178） |
| 「同一轮全量复跑」 | 否（只补跑 DVGA） | **是** | 本轮 5 个裁判全部重起、重跑 |

Benchmark 的 178/149 无需修正（111+33+34 / 99+34+16 与该口径一致）。

## 四、门禁侧

```
node e2e/acceptance.mjs --only=juice-shop,vampi,dvwa,benchmark
→ 4 PASS / 0 BLOCKED / 0 FAIL / 0 SKIP（套件范围 4/25，非全量报告）
```

四套件均以「事实断言」模式判 PASS（不采信套件自报）。前置提示 MySQL 连接失败
（`ER_BAD_DB_ERROR`）与本次外部裁判无关——DVWA 用独立 MariaDB 账号 `dvwa/p@ssw0rd`。

## 五、边界（不得越界引用）

- 187 个真值端点分布在 5 个项目上，**仍不能外推为「通用外部检出率」**：注入形态、
  DBMS、框架互不相同，样本不独立同分布；Benchmark 一个项目就占 178/187。
- GraphQL 面仍只有 DVGA `pastes(filter)` **一个**真值端点；block string、variables 内联值、
  裸 `application/graphql` 不在该通道内。
- `{call <过程名>}` 4 条真值仍未检出，是**已知能力边界**，单列不计入 178。
- 路径段注入点依赖 `--test-path`、header 注入点依赖 `testHeaders` ⇒ 套件显式开启的档位
  不代表默认配置覆盖率。
- 本轮未复跑 `e2e/run-all.mjs` 全量；DVGA 仍为参考靶场，不接 acceptance。
