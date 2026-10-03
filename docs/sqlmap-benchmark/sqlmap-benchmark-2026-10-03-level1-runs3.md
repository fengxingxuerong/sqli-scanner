# sqlmap 对标评测报告

- 日期：2026-10-03
- 基准：sqli-labs Python 靶场（SQLite 后端，23 关）
- 我方：ScanManager（union/error/boolean/time/stacked/inline，level3 等效）
- sqlmap：1.10.7 --batch --level=1 --risk=1 --technique=BEUSQ --no-cast -p <param>
- 方法论：**同靶点双方各跑 3 次** —— 检出取多数决（标注命中轮次），耗时取中位数，技术取命中轮并集。这是 2026-10-03 项目评价指出的缺口收口：单轮数字受单机抖动影响，撑不起强断言；多轮中位才是可复现的定版口径。

| 关卡 | 描述 | 我方检出(命中轮) | 我方技术 | sqlmap 检出(命中轮) | sqlmap 技术 | 一致 | 我方耗时(中位) | sqlmap 耗时(中位) |
|---|---|---|---|---|---|---|---|---|
| L1 | GET 单引号字符串 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 124ms | 2.2s |
| L2 | GET 数值型 | ✅(3/3) | union/error/boolean | ✅(3/3) | boolean/union | ✅ | 169ms | 2.2s |
| L3 | GET 单引号+括号 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 125ms | 2.1s |
| L4 | GET 双引号+括号 | ✅(3/3) | union/error/boolean | ❌(0/3) | - | ❌ | 164ms | 2.0s |
| L5 | GET 双注入单引号 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 123ms | 2.1s |
| L6 | GET 双注入双引号 | ✅(3/3) | union/error/boolean | ❌(0/3) | - | ❌ | 92ms | 2.1s |
| L8 | GET 布尔盲注 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 124ms | 2.1s |
| L9 | GET 时间盲注 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 94ms | 2.1s |
| L10 | GET 时间盲注双引号 | ✅(3/3) | union/error/boolean | ❌(0/3) | - | ❌ | 93ms | 2.1s |
| L23 | OR/AND 过滤 | ✅(3/3) | error/inline | ❌(0/3) | - | ❌ | 170ms | 3.2s |
| L25 | 注释过滤 | ✅(3/3) | error/boolean/inline | ✅(3/3) | boolean | ✅ | 126ms | 2.5s |
| L26 | 空格过滤 | ✅(3/3) | error/boolean/inline | ❌(0/3) | - | ❌ | 124ms | 2.2s |
| L28 | UNION SELECT 过滤 | ✅(3/3) | union/error/boolean/inline | ✅(3/3) | boolean/union | ✅ | 94ms | 2.2s |
| L29 | UNION 过滤 | ✅(3/3) | error/inline | ❌(0/3) | - | ❌ | 124ms | 2.7s |
| L30 | UNION+注释过滤 | ✅(3/3) | error/boolean/inline | ✅(3/3) | boolean | ✅ | 123ms | 2.5s |
| L31 | 堆叠注入 | ✅(3/3) | union/error/boolean | ✅(3/3) | boolean/union | ✅ | 93ms | 2.0s |
| L32 | 宽字节 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 93ms | 2.1s |
| L38 | 堆叠+数值 | ✅(3/3) | union/error/boolean | ✅(3/3) | boolean/union | ✅ | 92ms | 2.1s |
| L46 | ORDER BY 注入 | ✅(3/3) | error | ❌(0/3) | - | ❌ | 94ms | 2.1s |
| L47 | ORDER BY 单引号 | ✅(3/3) | error/inline | ❌(0/3) | - | ❌ | 125ms | 2.2s |
| L54 | 无回显数值 | ✅(3/3) | union/error/boolean | ✅(3/3) | boolean/union | ✅ | 93ms | 2.1s |
| L61 | 挑战多过滤 | ✅(3/3) | error/inline | ❌(0/3) | - | ❌ | 123ms | 2.7s |
| L66 | XML 注入 | ✅(3/3) | union/boolean/inline | ✅(3/3) | boolean/union | ✅ | 93ms | 2.1s |

## 汇总

- 我方命中率：100.0%（23/23）
- sqlmap 命中率：60.9%（14/23）
- 结论一致率：60.9%
- 双方均命中 14 / 仅我方 9 / 仅 sqlmap 0 / 双方未检出 0
- 平均耗时（命中场景）：我方 116ms vs sqlmap 2.2s

## 差异分析

- L4 GET 双引号+括号: 我方命中 union/error/boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L6 GET 双注入双引号: 我方命中 union/error/boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L10 GET 时间盲注双引号: 我方命中 union/error/boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L23 OR/AND 过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L26 空格过滤: 我方命中 error/boolean/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L29 UNION 过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L46 ORDER BY 注入: 我方命中 error，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L47 ORDER BY 单引号: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L61 挑战多过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
