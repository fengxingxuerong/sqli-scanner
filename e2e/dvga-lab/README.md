# DVGA 外部裁判靶场（GraphQL 面 · D121 起 1/1）

第三方外部裁判：**DVGA**（`dolevf/Damn-Vulnerable-GraphQL-Application`，故意脆弱
GraphQL 应用）。技术栈：Python + Flask + Graphene + SQLAlchemy + SQLite。
它不与 VAmPI/DVWA 共用「外部裁判 N 号」编号（那两项已占 2/3 号），按注入面称为
**GraphQL 面外部裁判**；D121 起真值点已打穿，仍按**单端点参考靶场**处理，不接门禁。

它补的是 1/2 号裁判都没有的注入面：**注入点位于 POST body 里那段 GraphQL 查询字符串的
内部**（`{ pastes(public: true, filter: "…") { … } }`）—— 值替换必须同时保持 GraphQL 语法合法。

真值来自官方 `core/views.py:resolve_pastes` 的字符串拼接，**不是本项目编写的断言**。

## ✅ 当前状态：D121 已打穿（2026-10-21）

真值点 `pastes(filter)` **1/1**（union / error / boolean 三通道命中），安全点
`search(keyword)` **0 误报**（124 请求），无 filter 的 resolver 作为「无字符串字面量 ⇒
0 点/0 请求」的结构对照。连续 3 轮一致，证据见
[`results/external-judge-2026-10-21-d121.md`](results/external-judge-2026-10-21-d121.md)。

它**仍不接入** `e2e/acceptance.mjs` 与 `e2e/run-all.mjs`（单一 GraphQL 端点样本 + 需手动
起靶场），登记在 `e2e/reference-labs.json` 与 `e2e/README.md` 的靶场清单；复跑命令见下。

历史：D114 首次接入时真值点 0/1，登记为 `graphql-inline-injection-gap`；D121 新增
GraphQL 查询串内联字面量点后转绿，旧结论作废（见台账）。

## 它抓到了什么（本靶场的实证价值）

1. **一条真误报（已修，D112）**：在官方 `resolve_search`（ORM `like` 参数化，
   手工证实不可注入）上，引擎报 High / CVSS 8.2 的报错注入。根因 —— 注入值被**整串替换**
   （payload 追加在整个查询串之后），GraphQL 解析失败，服务端把原文塞进
   `{"errors":[{"message":"Syntax Error … extractvalue …"}]}`，其中的 payload 是
   **JSON 转义形态**（`"` → `\"`），旧 `stripEchoedPayload` 剔不掉 ⇒ payload 自带的
   `extractvalue` 命中 `ERROR_SIG`。修复：变体集合补 JSON 转义（含双层），
   契约见 `server/tests/echoStrip.jsonEcho.test.js`（含缺陷注入复验）。
2. **一条真漏检（D121 已修）**：真值点 `pastes(filter)` 此前「检出」用的**就是上面那条
   无效 payload** —— 修复假阳性后，它如实变成 0 检出。也就是说：**之前的「检出」是假阳性，
   真值点其实一直没打穿**。旧注入点形态（query / path / JSON 叶子整串替换）无法在
   GraphQL 语法内部定位到 `filter` 的值位；D121 新增 `carrier='graphql'` 内联字面量点，
   只替换值位、保留查询骨架，真值点恢复 1/1。

## 起靶场（本机已验证链，D112）

```bash
# 1. 官方源码
curl -L https://codeload.github.com/dolevf/Damn-Vulnerable-GraphQL-Application/tar.gz/refs/heads/master -o dvga.tar.gz
tar xzf dvga.tar.gz && cd Damn-Vulnerable-GraphQL-Application-master

# 2. venv + 依赖（Python 3.9）
python -m venv <venv-dir>
# 2a. 有 wheel 的一批（greenlet/gevent 在本机无 SDK 编译不了，必须只装二进制）
<venv>/Scripts/pip install --only-binary=:all: -r <(grep -v '^git+$\|^Flask-GraphQL\|^graphql-server-core' requirements.txt)
# 2b. 三个只有 sdist 的包，单独源码装（纯 Python，不需编译）
<venv>/Scripts/pip install --no-build-isolation Flask-GraphQL==2.0.1
<venv>/Scripts/pip install --no-build-isolation Flask-GraphQL-Auth==1.3.3
# 2c. graphql-server-core 会随上面两个被带进来；若没有，同样 --no-build-isolation 单独装
# 2d. flask-sockets 是 git+https 依赖，本机 git-over-HTTPS 不通 ⇒ 下 tarball 本地装
curl -L https://codeload.github.com/dolevf/flask-sockets/tar.gz/refs/heads/master -o fs.tar.gz
tar xzf fs.tar.gz && <venv>/Scripts/pip install --no-build-isolation ./flask-sockets-master

# 3. 建库（⚠ app.py 里是 os.popen("python3 setup.py")，Windows 没有 python3 ⇒ 必须手动跑）
<venv>/Scripts/python setup.py

# 4. 启动（默认 5013）
WEB_PORT=5013 <venv>/Scripts/python app.py
```

就绪探针：

```bash
curl -s -X POST http://127.0.0.1:5013/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ pastes(public: true) { id title } }"}'
# {"data":{"pastes":[...]}}
```

## 跑判据

```bash
DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs
```

## 真值端点

| 端点 | 类型 | 官方实现 | 手工复核 |
|---|---|---|---|
| `POST /graphql` `{ pastes(public: true, filter: "x") { id title } }` | **SQLi** | `views.py:320` `text("title = '%s' or content = '%s'" % …)` | `x' OR 1=1-- -` → 返回全部；`x' OR 1=2-- -` → `[]`；`x'` → SQL 语法错误（布尔/报错两通道均有信号） |
| `POST /graphql` `{ pastes(public: true) { id title } }` | 安全 | 同 resolver 不带 filter ⇒ 纯 ORM | — |
| `POST /graphql` `{ search(keyword: "x") { __typename } }` | 安全 | `resolve_search` → `like(search)` 参数化 | `x'` / `x' OR 1=1-- -` / `x' UNION SELECT 1-- -` **全部** 200 `{"data":{"search":[]}}`（无任何 SQL 报错） |

## 当前证据

- `results/` 下的实跑报告（D114 入库时保留；靶场当前未常驻，复跑按本 README 起 DVGA）。
- `docs/_claims-ledger.json`：`external-judge-dvga-d114` 与 `graphql-inline-injection-gap`。

## 边界（不得越界引用）

- 真值端点只有 1 个（官方 GraphQL 侧只此一处拼接）；不能外推为「GraphQL 面覆盖率」。
- 本套件红 = **已知能力缺口**，不是环境故障；不要为了让门禁绿而删端点或放宽判据。
- DVGA 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
