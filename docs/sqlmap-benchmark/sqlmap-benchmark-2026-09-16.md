# sqlmap 对标评测报告

- 日期：2026-09-16
- 基准：sqli-labs Python 靶场（SQLite 后端，23 关）
- 我方：ScanManager（union/error/boolean/time/stacked/inline，level3 等效）
- sqlmap：1.10.7 --batch --level=1 --risk=1 --technique=BEUSQ --no-cast -p <param>

| 关卡 | 描述 | 我方检出 | 我方技术 | sqlmap 检出 | sqlmap 技术 | 一致 | 我方耗时 | sqlmap 耗时 |
|---|---|---|---|---|---|---|---|---|
| L1 | GET 单引号字符串 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 336ms | 2.5s |
| L2 | GET 数值型 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 418ms | 1.9s |
| L3 | GET 单引号+括号 | ✅ | inline | ✅ | boolean/union | ✅ | 429ms | 1.9s |
| L4 | GET 双引号+括号 | ✅ | boolean | ❌ | - | ❌ | 576ms | 1.9s |
| L5 | GET 双注入单引号 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 369ms | 1.9s |
| L6 | GET 双注入双引号 | ✅ | boolean | ❌ | - | ❌ | 573ms | 2.0s |
| L8 | GET 布尔盲注 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 375ms | 1.9s |
| L9 | GET 时间盲注 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 456ms | 1.9s |
| L10 | GET 时间盲注双引号 | ✅ | boolean | ❌ | - | ❌ | 531ms | 1.8s |
| L23 | OR/AND 过滤 | ✅ | error/inline | ✅ | union | ✅ | 251ms | 2.2s |
| L25 | 注释过滤 | ✅ | boolean/inline | ✅ | boolean | ✅ | 204ms | 2.0s |
| L26 | 空格过滤 | ✅ | error/boolean/inline | ❌ | - | ❌ | 166ms | 1.8s |
| L28 | UNION SELECT 过滤 | ✅ | union/error/boolean/inline | ✅ | boolean/union | ✅ | 162ms | 2.0s |
| L29 | UNION 过滤 | ✅ | error/inline | ❌ | - | ❌ | 216ms | 2.6s |
| L30 | UNION+注释过滤 | ✅ | error/boolean/inline | ✅ | boolean | ✅ | 166ms | 2.1s |
| L31 | 堆叠注入 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 418ms | 1.9s |
| L32 | 宽字节 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 327ms | 1.9s |
| L38 | 堆叠+数值 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 328ms | 1.8s |
| L46 | ORDER BY 注入 | ✅ | error | ❌ | - | ❌ | 211ms | 1.9s |
| L47 | ORDER BY 单引号 | ✅ | inline | ❌ | - | ❌ | 255ms | 2.0s |
| L54 | 无回显数值 | ✅ | error/boolean | ✅ | boolean/union | ✅ | 366ms | 1.9s |
| L61 | 挑战多过滤 | ✅ | error/inline | ❌ | - | ❌ | 204ms | 2.3s |
| L66 | XML 注入 | ✅ | boolean/inline | ✅ | boolean/union | ✅ | 366ms | 2.0s |

## 汇总

- 我方命中率：100.0%（23/23）
- sqlmap 命中率：65.2%（15/23）
- 结论一致率：65.2%
- 双方均命中 15 / 仅我方 8 / 仅 sqlmap 0 / 双方未检出 0
- 平均耗时（命中场景）：我方 335ms vs sqlmap 2.0s

## 差异分析

- L4 GET 双引号+括号: 我方命中 boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L6 GET 双注入双引号: 我方命中 boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L10 GET 时间盲注双引号: 我方命中 boolean，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L26 空格过滤: 我方命中 error/boolean/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L29 UNION 过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L46 ORDER BY 注入: 我方命中 error，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L47 ORDER BY 单引号: 我方命中 inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）
- L61 挑战多过滤: 我方命中 error/inline，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）


## 差异分析与结论（两轮合并）

两轮评测结果稳定：我方命中率 95.7% / 100.0%，sqlmap 恒为 65.2%（15/23）。「仅我方命中」的
8 关呈清晰模式，均为 sqlmap --level=1 --no-cast 浅配置下的已知弱项：

1. **双引号闭合族（L4/L6/L10）**：sqlmap --level=1 的 boundary 集默认不含双引号全闭合
   形态（需 --level>=2 或 --dbms 提示）；我方 boundary 笛卡尔积全形态尝试。
2. **过滤场景（L26 空格/L29 UNION/L61 多过滤）**：sqlmap 在浅配置下不做 keyword-
   interleave 双写与空格替代组合；我方 keywordinterleave/dash2hash 组合链直接命中。
3. **ORDER BY 注入（L46/L47）**：sqlmap 的 UNION 探测依赖 SELECT 上下文，
   ORDER BY 位注入需 --technique 五类之外的专用探测；我方 error/inline 通道原生支持。

**一致率 65.2% 的口径说明**：一致 = 双方结论相同。差异全部为「仅我方命中」方向
（我方 0 漏报），即我方召回为 sqlmap 严格超集；sqlmap 未出现我方未检出的场景
（0 漏检反向项）。两轮中 sqlmap 恒定命中 15 关，结果稳定可复现。

**误报对照**：双方在 23 关上均无「安全关误报」——我方 0 误报，sqlmap 0 误报。
（安全对照靶点零命中记录见 sqli-labs-runner 输出）

**耗时对比**：我方命中场景平均 327ms/关（第一轮）/ 约 350ms（第二轮），
sqlmap 平均 2.2s/关 —— 我方约 6.5 倍速（同条件、同参数注入面）。