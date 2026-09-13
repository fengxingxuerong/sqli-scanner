# 交付物样例（deliverables-demo）

三份**真实扫描**产出的报告，覆盖三种典型场景。生成方式：

```bash
node e2e/diag/deliverable-demo.mjs <目标URL> <子目录名>
# 例
node e2e/diag/deliverable-demo.mjs "http://target/num?id=1"    01-numeric
node e2e/diag/deliverable-demo.mjs "http://target/like?q=key"  02-like
node e2e/diag/deliverable-demo.mjs "http://target/waf?id=1"    03-waf-blocked
```

每次产出同源四件套：`report.html` / `report.md` / `report.json` / `report.csv`。

## 三份样例的差异

| 目录 | 场景 | 检出技术 | 拦截处置 | 看什么 |
|---|---|---|---|---|
| `01-numeric` | 数值型注入点（无防护） | union, error, boolean | `none` | 完整的三通道命中 + PoC 复现 |
| `02-like` | 搜索型（`%' ` 闭合） | union, error, boolean | `none` | 非数值上下文的闭合与提取 |
| `03-waf-blocked` | WAF 关键字拦截 | boolean | `adaptiveTamper` | **被压制后引擎做了什么**（换链重跑 + 命中） |

`03` 是这一版最有价值的一份：它证明「被拦 ≠ 没漏洞」。报告里会写明
`blockHits`、`实际换用的 tamper 链`，以及结论可信度受抑制的程度——这些是
sqlmap 类工具默认不会告诉你的。

## 四种格式给谁看

| 格式 | 给谁 | 特点 |
|---|---|---|
| `report.html` | 客户 / 领导 | 可直接浏览器打开，带 PoC 折叠块 |
| `report.md` | 技术同事 / 粘进文档 | 结构清晰，便于二次编辑 |
| `report.json` | 下游系统 | 全字段（含 `summary.dbmsEvidence` / `blockPolicy` / `wafAdaptive`） |
| `report.csv` | Excel 台账 | 一维漏洞清单，**不含 PoC 与上下文**，仅用于汇总 |

⚠️ CSV 与另外三份定位不同：它丢失了 PoC 分层与边界声明，**不要单独交付给客户**。

## 报告里必须看的三处

1. **漏洞清单的"说明"列** —— 每条都带判定依据（回显列 / 报错特征 / 统计量与 z 值）
2. **复现方式（PoC）** —— curl 命令 + 原始 HTTP 报文，存成 `.txt` 可用 `-r` 导入 Burp
3. **本次抑制项 / 拦截处置** —— 明确区分「测了没问题」和「本次根本没测」
