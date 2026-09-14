# 多引擎 tamper A/B（H2 / HSQLDB / Derby × CRS v4.1.0）

> 生成：2026-09-14T04:37:49.279Z　｜　引擎：真实 JDBC 引擎（内存库）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3

| 引擎 | 场景 | tamper off | tamper on | 说明 |
|---|---|---|---|---|
| h2 | num | boolean,union | union,boolean | 检出 |
| h2 | str | - | - | 检出 |
| h2 | blind | boolean,union | union,boolean | 检出 |
| hsqldb | num | boolean,union | union,boolean | 检出 |
| hsqldb | str | - | - | 检出 |
| hsqldb | blind | boolean,union | union,boolean | 检出 |
| derby | num | boolean,union | union,boolean | 检出 |
| derby | str | - | - | 检出 |
| derby | blind | boolean,union | union,boolean | 检出 |

安全对照（参数化）：零误报

> 诚实边界：仅验证布尔通道在 CRS 下的检测/绕过；dash2hash 有方言门控（MySQL 系），
> H2 以 MODE=MySQL 运行故 `#` 注释可用；Derby/HSQLDB 不认 `#`，方言门控生效时 tamper 不投放。