# 真实 CRS v4.1.0 下 tamper 开/关 A/B（对外唯一口径）

> 生成：2026-09-25T15:02:44.471Z　｜　靶场：真实 MySQL 8.0.28（e2e/real-mysql-lab/lab-app）　｜　CRS：官方规则原文 + 自实现执行器，档位 **PL1**（本文件是**默认口径 PL1** 那份；改档 `CRS_PL=1..4 npm run waf-real` 各写各的文件，互不覆盖；CRS 官方默认部署为 PL1）

| 场景 | tamper 关 | tamper 开 | 结论 |
|---|---|---|---|
| num | error,boolean | error,boolean | 技术位持平 |
| str | error,boolean | error,boolean | 技术位持平 |
| like | error,boolean | error,boolean | 技术位持平 |
| orderby | error | error | 技术位持平 |
| blind | boolean | boolean | 技术位持平 |

安全对照误拦：无

> ⚠️ 该执行器为简化版 ModSecurity（无 libinjection @detectSQLi、无排除集），检出强度略低于真实部署，绕过率据此略偏高；商业云 WAF 未实测，禁止据此声明可绕过。
