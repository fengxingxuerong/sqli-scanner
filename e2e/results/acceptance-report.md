# 全方位验收门禁报告

> 生成：2026-09-12T16:36:05.514Z　｜　执行器：`node e2e/acceptance.mjs`
> 前置：MySQL 8.0.28 @127.0.0.1:3306；secure_file_priv="NULL"

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 报告契约（自报字段必须与真实状态一致） | 通过=8　不一致=0 |
| ⏭ SKIP | fileRead 真闭环 | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |
| ⏭ SKIP | fileWrite 真闭环（文件系统侧断言） | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |

**汇总：1 PASS / 0 FAIL(含 BLOCKED) / 2 SKIP**


## 跳过原因
- **fileRead 真闭环**：secure_file_priv 未放行（MySQL 8 默认 NULL）
- **fileWrite 真闭环（文件系统侧断言）**：secure_file_priv 未放行（MySQL 8 默认 NULL）
