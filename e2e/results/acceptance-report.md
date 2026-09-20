# 全方位验收门禁报告

> 生成：2026-09-20T05:21:36.871Z　｜　执行器：`node e2e/acceptance.mjs`
> 前置：MySQL 8.0.28 @127.0.0.1:3306；secure_file_priv="NULL"

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 服务端单测 | tests=1903　pass=1902　fail=0　skipped=1 |
| ✅ PASS | 独立刁钻靶场（11 场景） | 漏洞场景=10/10　安全误报=0 |
| ✅ PASS | 检测回归（19 场景） | PASS=19　FAIL=0 |
| ✅ PASS | 真 MySQL 靶场 | PASS=10　FAIL=0 |
| ✅ PASS | 真 PG 靶场（含二阶注入） | 全部通过=true　引擎=PGlite |
| ✅ PASS | 报告契约（自报字段必须与真实状态一致） | 通过=8　不一致=0 |
| ✅ PASS | CRS 人工挂链 A/B（PL1 档基线） | off=8　on=8　基线=off≥8 on≥8　安全对照误拦=false |
| ✅ PASS | CRS 自动选链绕过（PL1 档基线） | 技术位=8　基线=≥8　安全误报=0 |
| ✅ PASS | CRS 执行器保真度（官方回归集） | 保真度=99.3%　未点名分歧=0　已消失=0　误触=4 |
| ✅ PASS | 红队实战评测（ground-truth 真值对照 + sqlmap 同题） | 检出=19/19　检出率=100%　安全点=7　误报=0 |
| ✅ PASS | fileRead 真闭环 | PASS=true　SKIP=false　方式=隔离沙箱重试 |
| ✅ PASS | fileWrite 真闭环（文件系统侧断言） | PASS=true　SKIP=false　文件落盘=true　方式=隔离沙箱重试 |

**汇总：12 PASS / 0 FAIL(含 BLOCKED) / 0 SKIP**


