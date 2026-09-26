# MariaDB 11.4.13 真实引擎 tamper A/B（CRS v4.1.0）

> 生成：2026-09-09T13:23:30.097Z　｜　靶场：真实 MariaDB 11.4.13（e2e/real-mysql-lab/lab-app 连 3308）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3

> ⚠️ **本文件被人工改过一次（2026-09-25）：只重算了「结论」列，off / on 两列原样未动。**
> 原因：原结论列由 `on.length > off.length ⇒ 绕过生效` 生成，于是 `num`、`blind` 两行
> 前后完全相同（`boolean` / `boolean`）也印「绕过生效」。这个缺陷在生成端已修
> （`mariadb-verify.mjs` 的 `verdictOf()`，改成集合差），但**产物没法重跑再生**：
> 本机 3308 上没有 MariaDB 常驻，而那台便携版装的是 **09-09 当时的旧执行器口径**之外的东西
> —— 用今天修准过的 CRS 执行器重跑会得到另一组数字，直接覆盖就等于把 09-09 的观测换掉。
>
> **因此这份产物能说什么、不能说什么**：
> - ✅ 能说明"那天的 MariaDB 上，探针在 str/like/orderby 三点被 CRS 拦掉、挂 dash2hash 后恢复"。
> - ❌ 不能与 `waf-real/results/waf-real-report.md`（PL1 口径）横向比强弱：两者档位不同。
> - ❌ 自 2026-09-19 CRS 执行器保真度修复（`(?i)` 与 `TX/MATCHED_VARS` 两处结构性缺陷）之后，
>   **本文件未再复跑过**，其拦截行为与今天的口径不可互换。
>
> 复跑：`node e2e/multi-engine-lab/mariadb-verify.mjs`（前置：MariaDB 11.4.13 @3308，见
> `e2e/README.md` 的 `mariadb-verify` 行）。脚本现在会先读服务端自报版本，**不是 MariaDB 就硬退**
> —— 因为 3308 与 `e2e/udf-lab/mysql_sandbox.py` 起的 MySQL 8 沙箱同端口同库名，
> 不校验就会把 MySQL 的数字写进这份标着 MariaDB 的产物里。

| 场景 | tamper off | tamper on | 结论（2026-09-25 按本行两列重算） |
|---|---|---|---|
| num | boolean | boolean | 技术位持平 |
| str | - | boolean | 绕过生效（新增 boolean） |
| like | - | boolean | 绕过生效（新增 boolean） |
| orderby | - | error,boolean | 绕过生效（新增 error,boolean） |
| blind | boolean | boolean | 技术位持平 |

安全对照误拦：无
