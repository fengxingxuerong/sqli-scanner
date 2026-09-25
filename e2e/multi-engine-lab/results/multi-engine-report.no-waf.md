# 多引擎 tamper A/B（H2 / HSQLDB / Derby）　—　WAF：off（NO_WAF=1）

> 生成：2026-09-25T15:20:19.732Z　｜　引擎：真实 JDBC 引擎（内存库）　｜　本档 WAF：off（NO_WAF=1）
>
> **口径必须先看这行**：WAF=on 时 CRS 会把 UNION 哨兵探针整条 403 掉，**版本回显定库通道
> 根本不会被执行**，所以那一档里的 `dbms=null` 只说明"没定出库"，不能读成"探针在该库上跑不动"。
> 要判探针本身是否可用，跑 `NO_WAF=1`（本文件 [LAB-FIX 2026-09-20]）。两档数字不可互换。

| 引擎 | 场景 | tamper off | tamper on | 定库 off/on | 说明 |
|---|---|---|---|---|---|
| h2 | num | union,error,boolean | union,error,boolean | H2/H2 | 技术位与 tamper 前一致 |
| h2 | str | union,error,boolean | union,error,boolean | H2/H2 | 技术位与 tamper 前一致 |
| h2 | blind | union,boolean | union,boolean | -/- | 技术位与 tamper 前一致 |
| hsqldb | num | union,boolean | union,boolean | HSQLDB/HSQLDB | 技术位与 tamper 前一致 |
| hsqldb | str | union,boolean | union,boolean | HSQLDB/HSQLDB | 技术位与 tamper 前一致 |
| hsqldb | blind | union,boolean | union,boolean | -/- | 技术位与 tamper 前一致 |
| derby | num | error,boolean | union,error,boolean | -/- | tamper 新增 union |
| derby | str | union,error,boolean | error,boolean | -/- | tamper 丢失 union |
| derby | blind | boolean | union,boolean | -/- | tamper 新增 union |

> **本档有效性**：off 检出合计 9、on 检出合计 9 ⇒ 覆盖面类断言成立。但本档**没有 WAF**，所以两侧差值不是绕过收益，只是 tamper 改写 payload 的副作用（见说明列）。

> **定库基线（本档实测）**：h2 → H2、hsqldb → HSQLDB、derby → **未定出**（已知缺口）。README「部分通道验证」那一栏只能引这一行，不许再写"× CRS"。

安全对照（参数化）：零误报

> 诚实边界（本档 WAF=off）：测的是**引擎覆盖面**（布尔/UNION/回显定库跑得通吗），
> 与"能不能绕过 WAF"无关 —— 绕过结论只能引 CRS-on 那份产物。
> 本档行内的技术位差异因此**不是**绕过收益：dash2hash 会把 `--` 改写成 `#`，
> 而 Derby/HSQLDB 不认 `#`（方言门控只在 dbms 已定时生效，Derby 恰好定不出库 ⇒ 门控不挡）。
> 逐请求归因没做，别把 derby 行里 union 的得失读成能力变化。
> 档位取自 crs-engine 的 EFFECTIVE_PL（当前 3）：`CRS_PL=1..4` 改档，抬头与文件名一起变。
> dash2hash 有方言门控（MySQL 系），H2 以 MODE=MySQL 运行故 `#` 注释可用。