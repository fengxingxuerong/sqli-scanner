# WAF 绕过 A/B 实验（真 MySQL 靶场）

> 目标：http://127.0.0.1:8099/num?id=1
> 后端：真 MySQL 8.0.28（隔离沙箱）＋ real-mysql-lab 真注入点
> WAF profile：modsecurity_crs
> configB tamper：space2comment, commentbeforeparentheses, charencode

## 检出侧（靶子是否真被打进）

| 配置 | 注入点 | 检出点 | 检出率 | 漏洞条目 | 命中技术 |
|------|-------|--------|--------|---------|---------|
| tamper 关 (configA) | 1 | 1 | 100% | 1 | error |
| tamper 开 (configB) | 1 | 1 | 100% | 2 | error/boolean |

## WAF 侧（tamper 是否真绕过）—— 主判据

| 配置 | 总请求 | 被拦截 | 拦截率 | 高危规则命中 |
|------|-------|--------|--------|-------------|
| tamper 关 (configA) | 175 | 139 | 79.4% | 30 |
| tamper 开 (configB) | 35 | 16 | 45.7% | 0 |

**判据① 拦截率下降（79.4% → 45.7%）? YES ✅**
**判据② 高危规则命中下降（30 → 0，规则 crs_942141/crs_942142/crs_942180）? YES ✅**

**结论：tamper 确已绕过 WAF ✅**

> 口径说明：
> · 检出率 = 去重 pointId 数 / report.points.length（对齐 metrics.js 注释）。
> · 本装置单注入点且 error/boolean 双通道均可打进，检出率两侧触顶 100%，
>   故**不作主判据**（旧版以此为判据，恒为 NO，属指标选择错误）。
> · 漏洞条目按 technique 拆分，仅作附加信息。

> configA 命中规则：{"crs_942120":5,"crs_942130":87,"crs_942141":18,"crs_942142":8,"crs_942180":4,"crs_942200":17}
> configB 命中规则：{"crs_942120":1,"crs_942130":11,"crs_942200":4}