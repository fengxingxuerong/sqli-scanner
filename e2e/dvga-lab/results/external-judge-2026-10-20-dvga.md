# DVGA 外部裁判实跑（D111 靶场 / D112 修复，2026-10-20）

外部裁判 **3 号**：DVGA（GraphQL）。本轮最重要的产出不是「跑了个新靶场」，
而是它当场抓出**两条真问题**：一条误报（已修）、一条被误报掩盖的漏检（能力缺口，未修）。

## 环境

| 项 | 值 |
|---|---|
| 靶场 | **DVGA**（`dolevf/Damn-Vulnerable-GraphQL-Application`，master） |
| 技术栈 | Python 3.9 + Flask 2.2.2 + Graphene 2.1.9 + SQLAlchemy 1.4.44 + SQLite |
| 地址 | `http://127.0.0.1:5013`（`WEB_PORT`） |
| 真值来源（外部） | 官方 `core/views.py:320` `result.filter(text("title = '%s' or content = '%s'" % (filter, filter)))` |
| 扫描配置 | `concurrency=1 ratePerSec=0 retry=0 timeoutMs=12000 level=2 risk=2 techniques=union,boolean,error,time productionMode=false` |

## 真值手工复核（官方源码语义，先于扫描器）

| 请求（`POST /graphql`） | 响应 |
|---|---|
| `{ search(keyword: "x") { __typename } }` | 200 `{"data":{"search":[]}}` |
| `{ search(keyword: "x'") … }` | 200 `{"data":{"search":[]}}`（**无 SQL 报错**） |
| `{ search(keyword: "x' OR 1=1-- -") … }` | 200 `{"data":{"search":[]}}` |
| `{ search(keyword: "x' UNION SELECT 1-- -") … }` | 200 `{"data":{"search":[]}}` ⇒ **该点不可注入**（ORM `like` 参数化） |
| `{ pastes(public: true, filter: "x") { id title } }` | 200 `{"data":{"pastes":[]}}` |
| `{ pastes(public: true, filter: "x'") … }` | 200 `errors`：`(sqlite3.OperationalError) near "x''": syntax error` |
| `{ pastes(public: true, filter: "x' OR 1=1-- -") … }` | 200 返回全部 pastes ⇒ **布尔可分（真值点）** |
| `{ pastes(public: true, filter: "x' OR 1=2-- -") … }` | 200 `[]` |

## 结果（修复前 vs 修复后）

| 端点 | 修复前 | 修复后（D112） |
|---|---|---|
| 真值 `pastes(filter)` | ✅「检出 1」error —— **实为假阳性** | ❌ 漏检 0/1（149 请求） |
| 安全 `pastes` 无 filter | ✅ 0 误报 | ✅ 0 误报（149 请求） |
| 安全 `search(keyword)` | ❌ **误报 1**（High/CVSS 8.2） | ✅ 0 误报（149 请求） |

两条「检出」用的是**同一条 payload**，而这 payload 本身就无效：

```
{ search(keyword: "x") { __typename } }' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
```

它是把 payload **追加在整个 GraphQL 查询串之后**（JSON 叶子整串替换的必然结果），
GraphQL 解析失败 → 400 → 服务端把原文回显进 `errors.message`。

## 根因（误报）

响应里 payload 是 **JSON 转义形态**（`"` → `\"`、换行 → `\n`）：

```
{"errors":[{"message":"Syntax Error GraphQL (1:40) Unexpected character \"'\".\n\n1: { search(keyword: \"x\") … }' AND extractvalue(…)…"}]}
```

旧 `stripEchoedPayload` 的变体集合只覆盖 SQL 转义（`''`）、反斜杠转义、`encodeURIComponent`
与 HTML 实体，不含 JSON 转义 ⇒ 剔除失败 ⇒ payload 自带的 `extractvalue` 命中 `ERROR_SIG`
（签名里包含 payload 关键字）⇒ 在**手工证实不可注入**的点上误报。

**修复**：`echoStrip.js` 变体集合补 `JSON.stringify(payload).slice(1,-1)` 及其双层形态
（与服务端序列化规则同源，覆盖控制字符）。
**契约测试**：`server/tests/echoStrip.jsonEcho.test.js` 4 例（含 §B 弱版敏感性、
§C 真报错不得被误删）。
**缺陷注入复验**：摘掉 JSON 变体 → §A / §A2 红（2 fail）；备份还原 → 4/4 绿。

## 暴露的缺口（未修，如实记录）

真值点 `pastes(filter)` 修复后**如实变成漏检**：说明此前那次「检出」纯属假阳性，
**引擎从来没真正打穿过它**。

根因是注入点形态：现有 JSON 叶子注入点把 `query` 这个**整串**当作值，注入即整串替换
（±后缀），生成的请求不是合法 GraphQL，服务端永远返回语法错误 ⇒ 布尔/UNION/报错
（真信号）三通道全部无从建立。要打穿需要**字符串内嵌注入**：保持
`{ pastes(public: true, filter: "<PAYLOAD>") { id } }` 的骨架，只替换 `filter` 的值位。

⇒ 已记入 `docs/_claims-ledger.json` 的 `graphql-inline-injection-gap`；本套件**保持红**，
不接入 acceptance / run-all（不为了让门禁绿而删端点或放宽判据）。

## 边界（不得越界引用）

- 单轮实跑；外部真值只有 1 个 GraphQL 端点，不能外推为「GraphQL 面覆盖率」。
- 「修复前误报 1 → 修复后 0」不代表整体误报率改善多少 —— 它只证明 JSON 转义回显这一类
  假阳性被消除；其余回显形态（XML/HTML 属性、日志截断）仍未覆盖。
- DVGA 是外部项目，仓库不 vendor；未就绪时套件按设计 SKIP，不计通过。
