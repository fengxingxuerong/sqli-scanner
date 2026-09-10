# real-mysql-lab 说明

- 真实 MySQL 8.0.28（D:/mysql 便携版，实际监听 3307，root/root）
- `init-db.mjs`：只读自检（库表由使用者维护，users/products 已有数据）
- `verify.mjs`：引擎 9 端点验证（--sqlmap 可选对拍）→ results/real-mysql-report.json
- 2026-09-08 结果：9/9 PASS，dbms 全部识别 MySQL；sqlmap 零配置 0 检出（121s）vs 引擎 130ms
- 注意：stacked/inline 是 opt-in 技术需显式 techniques；ORDER BY 子句轮需 level≥2
