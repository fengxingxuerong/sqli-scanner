# 全方位验收门禁报告

> 生成：2026-09-24T17:16:34.727Z　｜　执行器：`node e2e/acceptance.mjs`　｜　Node v24.18.0
> 代码版本：`d5ab742`　⚠️ **工作区 dirty**（跑验收前有 8 个未提交改动：e2e/detection-runner/results/detection-report.md、e2e/multi-engine-lab/results/multi-engine-report.md、e2e/oob-real-lab/results/oob-real-report.md 等）—— **本报告不对应任何提交**
> 套件范围：**13/14 跑出断言**　｜　⚠️ **判定：不完整 —— 不得当作该代码版本的整体验收结论**
> 前置：MySQL 8.0.28 @127.0.0.1:3306；secure_file_priv="NULL"

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 服务端单测 | tests=2305　pass=2302　fail=0　skipped=3 |
| ✅ PASS | 独立刁钻靶场（11 场景） | 漏洞场景=11/11　安全误报=0 |
| ✅ PASS | 检测回归（19 场景） | PASS=19　FAIL=0 |
| ✅ PASS | 真 MySQL 靶场 | PASS=10　FAIL=0 |
| ✅ PASS | 真 PG 靶场（含二阶注入） | 全部通过=true　引擎=PGlite |
| ⏭ SKIP | OOB 带外通道真机（真 PG COPY TO PROGRAM 真实回连） | 原因=端口 5432 未监听（CI 需先启动 PostgreSQL） |
| ✅ PASS | 报告契约（自报字段必须与真实状态一致） | 通过=8　不一致=0 |
| ✅ PASS | CRS 人工挂链 A/B（PL1 档基线） | off=8　on=8　基线=off≥8 on≥8　安全对照误拦=false |
| ✅ PASS | CRS 自动选链绕过（PL1 档基线） | 技术位=8　基线=≥8　安全误报=0 |
| ✅ PASS | CRS 执行器保真度（官方回归集） | 保真度=99.3%　未点名分歧=0　已消失=0　误触=2 |
| ✅ PASS | WAF 定向变异搜索（A2）端到端 | A档生成链=2　B档生成链=0　验证条数=6/6 |
| ✅ PASS | 红队实战评测（ground-truth 真值对照 + sqlmap 同题） | 检出=19/19　检出率=100%　安全点=7　误报=0 |
| ✅ PASS | fileRead 真闭环 | PASS=true　SKIP=false　方式=隔离沙箱重试 |
| ✅ PASS | fileWrite 真闭环（文件系统侧断言） | PASS=true　SKIP=false　文件落盘=true　方式=隔离沙箱重试 |

**汇总：13 PASS / 0 FAIL(含 BLOCKED) / 1 SKIP**


## 跳过原因
- **OOB 带外通道真机（真 PG COPY TO PROGRAM 真实回连）**：端口 5432 未监听（CI 需先启动 PostgreSQL）
