# MariaDB 11.4.13 真实引擎 tamper A/B（CRS v4.1.0）

> 生成：2026-09-09T13:23:30.097Z　｜　靶场：真实 MariaDB 11.4.13（e2e/real-mysql-lab/lab-app 连 3308）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3

| 场景 | tamper off | tamper on | 结论 |
|---|---|---|---|
| num | boolean | boolean | 绕过生效 |
| str | - | boolean | 绕过生效 |
| like | - | boolean | 绕过生效 |
| orderby | - | error,boolean | 绕过生效 |
| blind | boolean | boolean | 绕过生效 |

安全对照误拦：无