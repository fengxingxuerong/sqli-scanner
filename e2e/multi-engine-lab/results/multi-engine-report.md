# 多引擎 tamper A/B（H2 / HSQLDB / Derby）　—　WAF：on（CRS v4.1.0 ≈PL3）

> 生成：2026-09-20T11:40:39.258Z　｜　引擎：真实 JDBC 引擎（内存库）　｜　本档 WAF：on（CRS v4.1.0 ≈PL3）
>
> **口径必须先看这行**：WAF=on 时 CRS 会把 UNION 哨兵探针整条 403 掉，**版本回显定库通道
> 根本不会被执行**，所以那一档里的 `dbms=null` 只说明"没定出库"，不能读成"探针在该库上跑不动"。
> 要判探针本身是否可用，跑 `NO_WAF=1`（本文件 [LAB-FIX 2026-09-20]）。两档数字不可互换。

| 引擎 | 场景 | tamper off | tamper on | 说明 |
|---|---|---|---|---|
| h2 | num | - | - | 检出 |
| h2 | str | - | - | 检出 |
| h2 | blind | - | - | 检出 |
| hsqldb | num | - | - | 检出 |
| hsqldb | str | - | - | 检出 |
| hsqldb | blind | - | - | 检出 |
| derby | num | - | - | 检出 |
| derby | str | - | - | 检出 |
| derby | blind | - | - | 检出 |

安全对照（参数化）：零误报

> 诚实边界：仅验证布尔通道在 CRS 下的检测/绕过；dash2hash 有方言门控（MySQL 系），
> H2 以 MODE=MySQL 运行故 `#` 注释可用；Derby/HSQLDB 不认 `#`，方言门控生效时 tamper 不投放。