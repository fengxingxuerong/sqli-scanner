# Juice Shop 外部裁判靶场

第三方外部裁判：**OWASP Juice Shop**（Angular + Sequelize ORM + SQLite，官方源码，非本仓依赖）。
真值来自官方 `routes/search.ts` 与 `routes/login.ts` 的字符串拼接，不是本项目编写的断言。

未就绪时 `run.mjs` 输出 `[SKIP]` 并以 exit 0 退出（不计通过）；acceptance 读文本判据，
不会把「没跑」认成「通过」。

## 起靶场（本机已验证链，D88）

```bash
# 1. 官方源码（npm 上的 juice-shop 包已弃用）
curl -L https://codeload.github.com/juice-shop/juice-shop/tar.gz/refs/tags/v20.3.0 -o juice-shop.tar.gz
tar xzf juice-shop.tar.gz && cd juice-shop-20.3.0

# 2. 服务端依赖（跳过后再单独编译原生 SQLite）
npm install --omit=dev --ignore-scripts
npm rebuild sqlite3

# 3. 前端单独安装并构建（production 字体内联需关闭，否则会联网拉 Google Fonts）
cd frontend
npm install
npm run build
cd ..

# 4. 上游 TS 配置与其 devDep 版本不匹配时补这一步
npx tsc --moduleResolution node

# 5. 启动（默认 3000，本仓库判据用 3199）
PORT=3199 node build/app
```

就绪探针：

```bash
curl -s "http://127.0.0.1:3199/rest/products/search?q=apple" | head -c 120
# {"status":"success","data":[...]}
```

## 跑判据

```bash
# 套件：2 个官方 SQLi 真值端点 + 4 个带可测参数的安全端点
JUICE_BASE=http://127.0.0.1:3199 node e2e/juice-shop-lab/run.mjs

# 门禁入口（未就绪会如实 SKIP）
JUICE_BASE=http://127.0.0.1:3199 node e2e/acceptance.mjs --only=juice-shop
```

## 真值端点

| 端点 | 方法 | 真值来源 | 类型 |
|---|---|---|---|
| `/rest/products/search?q=apple` | GET | `routes/search.ts`：`LIKE '%${criteria}%'` 直接拼接 | SQLi（LIKE + 双层括号） |
| `/rest/user/login` | POST JSON | `routes/login.ts`：`email = '${req.body.email}'` 直接拼接 | SQLi（登录绕过） |
| `/api/Feedbacks/?limit=2` | GET | Sequelize ORM 参数化 | 安全对照 |
| `/api/Challenges/?name=Score%20Board` | GET | ORM where 对象 | 安全对照 |
| `/rest/user/security-question?email=x%40y.z` | GET | ORM 参数化 | 安全对照 |
| `/api/Products/?name=apple` | GET | ORM where 对象 | 安全对照 |

## 当前证据

- `results/external-judge-2026-10-19.md`：D109 实跑（2/2 检出、0/4 误报）＋ sqlmap 同题对照。
- `docs/_claims-ledger.json`：`external-judge-juice-shop-d109`。
