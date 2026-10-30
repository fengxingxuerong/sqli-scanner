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

## 2026-10-30 重建实录（供应物丢失后从零重建，与 D88 配方的实测增量）

上表 D88 配方在本机（2026-10-30）实测的偏差与解法，全部当场踩到：

1. **根目录 `npm install` 必挂**（D137 同款 lockfile 病，`Cannot read properties of null`）：
   改 `npx -y pnpm@9 install --shamefully-hoist --ignore-scripts`（Node 22 下跑），
   16.6s 完成（pnpm store 复用）。
2. **原生模块必须手动补预编译**：`--ignore-scripts` 跳过了它们的 install 脚本，且
   pnpm 脚本内自动跑 prebuild-install 会静默失败 → 回退 gyp → 本机无 VS 构建工具报
   `Could not find any Visual Studio installation`。手动逐个执行（网络可达即成，无需 VS）：
   ```bash
   cd node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3   && npx -y prebuild-install -r napi --verbose
   cd node_modules/.pnpm/libxmljs2@0.37.0/node_modules/libxmljs2 && npx -y prebuild-install --verbose
   ```
3. **前端也用 pnpm**：`cd frontend && npx -y pnpm@9 install --ignore-scripts --shamefully-hoist`
   （frontend 无 lockfile，npm 同样挂 `edgesOut`）。
4. **ng build 必须用系统 Node 24（或 26），不能用 22.22.2**：`@angular/*@^22.0.1` 无锁文件
   按范围新鲜解析，今天解析到 22.2.4，其 CLI 要求 Node ≥22.22.3。前端产物与构建用的
   Node 无关，**运行仍必须 Node 22**（D137 的 libuv 断言坑不变）。
5. **production 字体内联需关闭**（本机到 fonts.googleapis.com ECONNRESET）：
   `frontend/angular.json` production 配置 `"optimization": true` 改为
   `{ "scripts": true, "styles": true, "fonts": false }`。
6. 服务端 `npx tsc`（Node 24 下跑无妨，产物 node 无关）产出 `build/app.js`；
   之后 `PORT=3199 NODE_ENV=production <NODE22>/node.exe build/app` 启动，其余不变。

验证：`--only=juice-shop` **2/2 真值检出、安全端点 0 误报**（2026-10-30）。

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
