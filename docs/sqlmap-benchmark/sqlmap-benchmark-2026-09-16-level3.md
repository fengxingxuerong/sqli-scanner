# sqlmap 对标评测报告

- 日期：2026-09-16
- 基准：sqli-labs Python 靶场（SQLite 后端，23 关）
- 我方：ScanManager（union/error/boolean/time/stacked/inline，level3 等效）
- sqlmap：1.10.7 --batch --level=1 --risk=1 --technique=BEUSQ --no-cast -p <param>

| 关卡 | 描述 | 我方检出 | 我方技术 | sqlmap 检出 | sqlmap 技术 | 一致 | 我方耗时 | sqlmap 耗时 |
|---|---|---|---|---|---|---|---|---|
| L1 | GET 单引号字符串 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 348ms | 3.2s |
| L2 | GET 数值型 | ✅ | error | ✅ | boolean/union | ✅ | 417ms | 2.2s |
| L3 | GET 单引号+括号 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 381ms | 2.3s |
| L4 | GET 双引号+括号 | ✅ | boolean | ✅ | boolean/union | ✅ | 579ms | 2.6s |
| L5 | GET 双注入单引号 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 415ms | 2.4s |
| L6 | GET 双注入双引号 | ✅ | boolean | ✅ | boolean/union | ✅ | 543ms | 2.4s |
| L8 | GET 布尔盲注 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 378ms | 2.3s |
| L9 | GET 时间盲注 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 372ms | 2.2s |
| L10 | GET 时间盲注双引号 | ✅ | boolean | ✅ | boolean/union | ✅ | 678ms | 2.7s |
| L23 | OR/AND 过滤 | ✅ | error/inline | ✅ | union | ✅ | 210ms | 15.4s |
| L25 | 注释过滤 | ✅ | boolean/inline | ✅ | boolean | ✅ | 213ms | 3.6s |
| L26 | 空格过滤 | ✅ | error/boolean/inline | ❌ | - | ❌ | 168ms | 14.7s |
| L28 | UNION SELECT 过滤 | ✅ | union/error/boolean/inline | ✅ | boolean/union | ✅ | 204ms | 2.1s |
| L29 | UNION 过滤 | ✅ | error/inline | ❌ | - | ❌ | 252ms | 25.2s |
| L30 | UNION+注释过滤 | ✅ | error/boolean/inline | ✅ | boolean | ✅ | 216ms | 3.6s |
| L31 | 堆叠注入 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 461ms | 2.1s |
| L32 | 宽字节 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 328ms | 2.3s |
| L38 | 堆叠+数值 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 374ms | 2.0s |
| L46 | ORDER BY 注入 | ✅ | error | ✅ | boolean | ✅ | 172ms | 7.6s |
| L47 | ORDER BY 单引号 | ✅ | inline | ✅ | boolean | ✅ | 246ms | 8.6s |
| L54 | 无回显数值 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 378ms | 2.3s |
| L61 | 挑战多过滤 | ✅ | error/inline | ❌ | - | ❌ | 206ms | 27.3s |
| L66 | XML 注入 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 369ms | 2.3s |

## 汇总

- 我方命中率：100.0%（23/23）
- sqlmap 命中率：87.0%（20/23）
- 结论一致率：87.0%
- 双方均命中 20 / 仅我方 3 / 仅 sqlmap 0 / 双方未检出 0
- 平均耗时（命中场景）：我方 344ms vs sqlmap 3.7s

## 差异分析

- L26 空格过滤: 我方命中 error/boolean/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L29 UNION 过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L61 挑战多过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
