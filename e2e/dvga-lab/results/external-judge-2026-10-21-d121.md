# DVGA GraphQL 外部裁判 · 2026-10-21（D121）

> 第三方靶场：`dolevf/Damn-Vulnerable-GraphQL-Application`（Flask + Graphene + SQLAlchemy + SQLite）。
> 真值来自官方 `core/views.py:320` 字符串拼接，不是本仓断言。
> 本文件是 D121 的落盘证据；旧 0/1 记录见 `external-judge-2026-10-20-dvga.md`（已作废，保留历史）。

## 命令

```bash
DVGA_BASE=http://127.0.0.1:5013 node e2e/dvga-lab/run.mjs
```

环境：Windows + Python 3.10.11；DVGA master 源码；依赖按 `e2e/dvga-lab/README.md`
的离线 `--target deps` 变体安装；`WEB_PORT=5013 python app.py`。

## 结果（连续 3 轮一致）

| 端点 | 类型 | 轮 1 | 轮 2 | 轮 3 |
|---|---|---|---|---|
| `{ pastes(public: true, filter: "x") { id title } }` | 真值 SQLi | ✅ 1/1（3 条：union / error / boolean，98 请求） | ✅ 1/1（98 请求） | ✅ 1/1（98 请求） |
| `{ pastes(public: true) { id title } }` | 结构对照 | ✅ 0 误报（0 点/0 请求） | ✅ 同左 | ✅ 同左 |
| `{ search(keyword: "x") { __typename } }` | 安全（ORM like 参数化） | ✅ 0 误报（124 请求） | ✅ 同左 | ✅ 同左 |

汇总：**真值 1/1、安全端点误报 0、证据不足 0**；退出码 0。

## 机制

- `TargetParser._collectGraphqlQueryLeaf`：识别 `query` 字段为 GraphQL 查询串，扫描其中
  双引号字符串字面量，生成 `carrier='graphql'` 的独立注入点（`query.filter`）。
- `injection.buildGraphQLBodyRequest`：只替换该字面量，保留
  `{ pastes(public: true, filter: "<PAYLOAD>") { id title } }` 骨架；基线请求逐字不变。
- 回归：`server/tests/graphqlInline.injection.test.js`（12 例）+ `graphqlInline.scan.test.js`
  （2 例，本地同构靶场 + 真 `ScanManager`）。

## 边界

- 单一 GraphQL 端点样本（DVGA `pastes(filter)`）；不能外推为 GraphQL 通用覆盖率。
- block string、variables 内联值、裸 `application/graphql` 不在本通道内（variables 走既有
  JSON 叶子通道）。
- 本套件仍为**参考靶场**，未接入 `acceptance` / `run-all` 门禁；复跑需先起 DVGA。
