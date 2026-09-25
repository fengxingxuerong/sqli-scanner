# 多引擎 tamper A/B（H2 / HSQLDB / Derby）　—　WAF：on（CRS v4.1.0 ≈PL1）

> 生成：2026-09-25T15:20:24.802Z　｜　引擎：真实 JDBC 引擎（内存库）　｜　本档 WAF：on（CRS v4.1.0 ≈PL1）
>
> **口径必须先看这行**：WAF=on 时 CRS 会把 UNION 哨兵探针整条 403 掉，**版本回显定库通道
> 根本不会被执行**，所以那一档里的 `dbms=null` 只说明"没定出库"，不能读成"探针在该库上跑不动"。
> 要判探针本身是否可用，跑 `NO_WAF=1`（本文件 [LAB-FIX 2026-09-20]）。两档数字不可互换。

| 引擎 | 场景 | tamper off | tamper on | 定库 off/on | 说明 |
|---|---|---|---|---|---|
| h2 | num | error,boolean | error,boolean | -/- | 技术位与 tamper 前一致 |
| h2 | str | boolean | boolean | -/- | 技术位与 tamper 前一致 |
| h2 | blind | boolean | boolean | -/- | 技术位与 tamper 前一致 |
| hsqldb | num | boolean | boolean | -/- | 技术位与 tamper 前一致 |
| hsqldb | str | boolean | boolean | -/- | 技术位与 tamper 前一致 |
| hsqldb | blind | boolean | boolean | -/- | 技术位与 tamper 前一致 |
| derby | num | error,boolean | error,boolean | -/- | 技术位与 tamper 前一致 |
| derby | str | error,boolean | error,boolean | -/- | 技术位与 tamper 前一致 |
| derby | blind | boolean | boolean | -/- | 技术位与 tamper 前一致 |

> **本档有效性**：off 检出合计 9、on 检出合计 9 ⇒ 两侧**持平**：本档证明"CRS 这一档下探针能送达并被检出"，但**不**证明 tamper 带来增益（MySQL 在 PL1 上也是同一形状：off=on=8，见 acceptance.mjs 里 waf-real 那段基线注释）。

> **定库基线**：本档不适用 —— CRS 把带版本回显的 UNION 探针整条拦掉，所以那一档里的 `dbms=-` 只说明"没送达"，不说明"探不出来"。

安全对照（参数化）：零误报

> 诚实边界：本档是 CRS **官方默认部署档 PL1**，三引擎布尔通道 9/9 检出 ⇒
> 可以据此说"这三库在默认 CRS 下可被检出"；但**定库不在本档口径内**
> （UNION 哨兵被吃、回显通道没送达，判探针本身可用请看 `.no-waf` 那份产物）。
> 也别把它外推到高 paranoid 档：PL2/PL3/PL4 实测 0/9（PL1→PL2 之间是断崖，不是渐变；
> 复测：`CRS_PL=2 node e2e/multi-engine-lab/verify.mjs`，产物按档落到 `.pl2.md`，不会覆盖本文件）。
> 档位取自 crs-engine 的 EFFECTIVE_PL（当前 1）：`CRS_PL=1..4` 改档，抬头与文件名一起变。
> dash2hash 有方言门控（MySQL 系），H2 以 MODE=MySQL 运行故 `#` 注释可用。