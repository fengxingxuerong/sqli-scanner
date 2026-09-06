# 进度记录：G3 布尔子句轮接入 + G1 复核

> 挥起时间：2026-09-06　｜　阶段：第 4 步．G3 修复（完成）/ G1 复核（进行中）

## 1. G3 缺陷描述

- **位置**：`server/src/engine/detectors/BooleanBlindDetector.js`
- **现象**：`_getBooleanPairs` useRegistry 路径下 `selectPayloads` **未传入 `clause: ['where']`**，仅以
  `(p.clause || []).includes('where')` 断定。但实际注册表条目 `clause` 字段是数组字面量；未显式收敛的后果是，
  useRegistry 路径与子句轮存在**双拷贝漂移**：
  - useRegistry=true 时 `_clauseRoundEnabled` **整体跳过子句轮** → 在 `--level>=2` 显式配置下，
    `ORDER BY/GROUP BY/HAVING/LIMIT` 位置探测**缺失**。
  - sqlmap 对标：`--level>=2` 才消费子句位置变体，且注册表 `<test>` 的主轮 `WHERE` 与子句轮 `order/gby/having/limit`
    是**独立**探测阶段。

## 2. 修复措施

| 编号 | 改动 | 目的 |
|---|---|---|
| G3-1 | `_clauseRoundEnabled` 移除 `useRegistry === true` 短路 | 子句轮对 `level>=2` 独立承担，不受注册表优化掩盖 |
| G3-2 | `_getBooleanPairs` useRegistry 路径显式 `clause: ['where']` 收敛 | 主轮仅投放 WHERE 子句条目，消除位置变体双投 |
| G3-3 | 补充说明注释（含 `→`/`/`） | 标记为 G3-FIX，方便后续 diff 回溯 |

> 注：修复历经一次中间态失误——Node `String.replace` replacement 中 `$5` 未被正确解析为分组 5
> 而残留为字面文本 `$5`，导致函数闭合缺失 (`node --check` SyntaxError)。
> 采用直接字面量替换 (`'    return true;\n$5\n' → '    return true;\n  }'`) 修正。

## 3. 回归验证

| 用例 | 条件 | 期望 | 结果 |
|---|---|---|---|
| G3-a | useRegistry=true，level=2 | 子句轮发出 orderby 逗号拼接 / having 位置布尔对 | ✅ 通过 |
| G3-b | useRegistry=true，level=1 | 不发出任何子句位置 payload | ✅ 通过 |
| G3-c | useRegistry=true，level=3 | 主轮仅含 where 条目（含 id）；不含 orderby 位置条目 | ✅ 通过 |

**注意点**：`ORDER BY` 位置探测的模板形态是**逗号拼接标量子查询** `,{ORIG},(SELECT 1)-- -`，
而非字面 `ORDER BY` 关键字——因此测试断言匹配 `/,\\(SELECT 1\\)|HAVING 1=1/` 而非 `/ORDER BY/`。

运行命令：
```bash
node --test tests/booleanBlind.clause.test.js
# ℹ tests 3 | ℹ pass 3 | ℹ fail 0
```

## 4. 行为零变更保证

- `level=1/undefined`：`Number(undefined)>=2` → `NaN>=2` → `false` → 子句轮仍跳过，**请求数与行为与历史一致**。
- `useRegistry=false`（defaults）：回退至固定索引 `[0,2]/[1,3]/[4,5]/[6,7]`，zero 回归。
- useRegistry=true + level>=2 新增请求 = 子句轮补发的 orderby/groupby/having/limit 布尔对（~5~6 对 × 2 = 14），
  这是 **与 sqlmap `--level>=2` 同级能力** 的收敛，而非额外冗余。

## 5. G1 复核（进行中）

- 校验 `defaults.js` 中 `useRegistry` 文档（原 07 文档写“默认 true”，现为 false）是否仍存在滞后陈述。
- 核对 `SELECT 1` / `SLEEP` 等注册表条目的 `level` 标记，确保 level=1 不外泄到 level>=2 专属。

---
*相关文件：`server/src/engine/detectors/BooleanBlindDetector.js`,
`server/src/engine/payloads/index.js`, `server/src/engine/payloads/mysql.js`,
`server/tests/booleanBlind.clause.test.js`*