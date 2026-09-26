# 真实 CRS v4.1.0 下 tamper 开/关 A/B（对外唯一口径）

> 生成：2026-09-25T15:02:49.588Z　｜　靶场：真实 MySQL 8.0.28（e2e/real-mysql-lab/lab-app）　｜　CRS：官方规则原文 + 自实现执行器，档位 **PL4**（本档为 PL4（非默认口径），产物是独立文件、不是对外那份；改档 `CRS_PL=1..4 npm run waf-real` 各写各的文件，互不覆盖；CRS 官方默认部署为 PL1）

| 场景 | tamper 关 | tamper 开 | 结论 |
|---|---|---|---|
| num | - | - | 全拦 |
| str | - | - | 全拦 |
| like | - | - | 全拦 |
| orderby | - | - | 全拦 |
| blind | - | - | 全拦 |

安全对照误拦：无

> ⚠️ 该执行器为简化版 ModSecurity（无 libinjection @detectSQLi、无排除集），检出强度略低于真实部署，绕过率据此略偏高；商业云 WAF 未实测，禁止据此声明可绕过。
