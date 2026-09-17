# 全方位验收门禁报告

> 生成：2026-09-17T16:41:14.759Z　｜　执行器：`node e2e/acceptance.mjs`
> 前置：MySQL 不可用（端口 3306 未监听——请先启动 MySQL）；secure_file_priv=null

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 服务端单测 | tests=1850　pass=1847　fail=0　skipped=3 |
| ⛔ BLOCKED | 独立刁钻靶场（11 场景） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | 检测回归（19 场景） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | 真 MySQL 靶场 | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ✅ PASS | 真 PG 靶场（含二阶注入） | 全部通过=true　引擎=PGlite |
| ⛔ BLOCKED | 报告契约（自报字段必须与真实状态一致） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | CRS v4.1.0 人工挂链 A/B | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | CRS 自动选链绕过 | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⏭ SKIP | 红队实战评测（ground-truth 真值对照 + sqlmap 同题） | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |
| ⏭ SKIP | fileRead 真闭环 | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |
| ⏭ SKIP | fileWrite 真闭环（文件系统侧断言） | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |

**汇总：2 PASS / 6 FAIL(含 BLOCKED) / 3 SKIP**

## 失败详情
- **独立刁钻靶场（11 场景）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **检测回归（19 场景）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **真 MySQL 靶场**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **报告契约（自报字段必须与真实状态一致）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **CRS v4.1.0 人工挂链 A/B**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **CRS 自动选链绕过**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL

## 跳过原因
- **红队实战评测（ground-truth 真值对照 + sqlmap 同题）**：secure_file_priv 未放行（MySQL 8 默认 NULL）
- **fileRead 真闭环**：secure_file_priv 未放行（MySQL 8 默认 NULL）
- **fileWrite 真闭环（文件系统侧断言）**：secure_file_priv 未放行（MySQL 8 默认 NULL）
