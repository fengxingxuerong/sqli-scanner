# WAF 绕过 A/B 实验（真 MySQL 靶场）

> 目标：http://127.0.0.1:8099/num?id=1
> 后端：真 MySQL 8.0.28（隔离沙箱）＋ real-mysql-lab 真注入点
> WAF profile：modsecurity_crs
> configB tamper：space2comment, commentbeforeparentheses, charencode

## 检出侧（有效性前置：靶子是否真被打进）

| 配置 | 注入点 | 检出点 | 检出率 | 漏洞条目 | 命中技术 |
|------|-------|--------|--------|---------|---------|
| tamper 关 (configA) | 1 | 1 | 100% | 1 | error |
| tamper 开 (configB) | 1 | 1 | 100% | 2 | error/boolean |

## WAF 侧（tamper 是否真绕过）—— 主判据

| 配置 | 总请求 | 被拦截 | 拦截率 | 高危规则命中 |
|------|-------|--------|--------|-------------|
| tamper 关 (configA) | 175 | 139 | 79.4% | 30 |
| tamper 开 (configB) | 35 | 16 | 45.7% | 0 |

**前置 两侧都必须有检出（A=1/1　B=1/1）? YES ✅**

**判据① 拦截率下降（79.4% → 45.7%）? YES ✅**
**判据② 高危规则命中下降（30 → 0，规则 crs_942141/crs_942142/crs_942180）? YES ✅**

**结论：tamper 确已绕过 WAF ✅**

> 口径说明：
> · 检出率 = 去重 pointId 数 / report.points.length（对齐 metrics.js 注释）。
> · 检出率**不作 A/B 比较判据**：单注入点下 error/boolean 双通道两侧同时触顶 100%，
>   比较不出差异（旧版以此为判据，恒为 NO，属指标选择错误）。
> · 但它是**有效性前置**：任一侧零检出 ⇒ 本实验不成立、判红。依据（2026-09-25）：
>   A3 通道降级初版把 CRS 画像下的 error 通道判死，configA 检出 1/1 → 0/1、
>   请求数 175 → 246，而当时退出码仍是 0、报告照印 ✅。
> · 漏洞条目按 technique 拆分，仅作附加信息。

> configA 命中规则：{"crs_942120":5,"crs_942130":87,"crs_942141":18,"crs_942142":8,"crs_942180":4,"crs_942200":17}
> configB 命中规则：{"crs_942120":1,"crs_942130":11,"crs_942200":4}