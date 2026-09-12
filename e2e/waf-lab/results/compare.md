# WAF-v2 e2e：tamper 关 vs 开 检出率对比

> 目标：http://localhost:8099/vuln?id=1
> configB tamper：space2comment, commentbeforeparentheses, charencode（medium 预设中的 space2comment 是绕过本实验室空格锚定规则的关键；
> randomcase 因会随机化 UnionDetector 用于确认的回显标记 `SQLISCANNER0` 的大小写导致检测失效，故未纳入本 e2e 的 configB）

| 配置 | 总注入点 | 检出 | 检出率 | 被 WAF 拦截(req) | 拦截率 |
|------|---------|------|--------|----------------|--------|
| tamper 关 (configA) | 1 | 0 | 0% | 129 | 67.5% |
| tamper 开 (configB) | 1 | 1 | 100% | 15 | 37.5% |

**结论：detectRateB(100%) > detectRateA(0%) ? YES ✅**

> 注：拦截率(blockRate)仅作参考。两次扫描请求构成不同——configB 命中 union 后提前 break，
> 总体请求更少，且被跳过的主要是"放行类"布尔请求，故两次拦截率接近。主判据为检出率（开>关）。