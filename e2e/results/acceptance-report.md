# 全方位验收门禁报告

> 生成：2026-10-17T09:24:03.536Z　｜　执行器：`node e2e/acceptance.mjs`　｜　Node v24.15.0
> 代码版本：`817e34e`　⚠️ **工作区 dirty**（跑验收前有 4 个未提交改动：src/App.tsx、src/i18n/en.json、src/i18n/zh.json 等）—— **本报告不对应任何提交**
> 套件范围：**8/19 跑出断言**　｜　⚠️ **判定：不完整 —— 不得当作该代码版本的整体验收结论**
> 前置：MySQL 不可用（端口 3306 未监听——请先启动 MySQL）；secure_file_priv=null

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 服务端单测 | tests=3600　pass=3596　fail=0　skipped=4 |
| ⛔ BLOCKED | 独立刁钻靶场（11 场景） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | 检测回归（19 场景） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | 真 MySQL 靶场 | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ✅ PASS | 真 PG 靶场（含二阶注入） | 全部通过=true　引擎=PGlite |
| ✅ PASS | 批量编排故障隔离（-m：死目标不拖垮整批，结论不乱写） | PASS=1　FAIL=0 |
| ✅ PASS | 登录编排自动重登（真表单登录 + 会话反复过期，含「不给登录则 0 检出」对照） | PASS=1　FAIL=0 |
| ⏭ SKIP | OOB 带外通道真机（真 PG COPY TO PROGRAM 真实回连） | 原因=端口 5432 未监听（CI 需先启动 PostgreSQL） |
| ⏭ SKIP | OOB 外部隧道真机（interactsh 协作端回连 → 轮询取回 → 检出） | 原因=环境不满足，未执行断言 |
| ⏭ SKIP | 第三方真框架外部裁判（Juice Shop：真漏洞须检出 + 安全端点零误报） | 原因=环境不满足，未执行断言 |
| ⛔ BLOCKED | 报告契约（自报字段必须与真实状态一致） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | CRS 人工挂链 A/B（PL1 档基线） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ⛔ BLOCKED | CRS 自动选链绕过（PL1 档基线） | 缺失依赖=端口 3306 未监听——请先启动 MySQL |
| ✅ PASS | CRS 执行器保真度（官方回归集） | 保真度=99.6%　未点名分歧=0　已消失=0　误触=2 |
| ✅ PASS | WAF 定向变异搜索（A2）端到端 | A档生成链=2　B档生成链=0　验证条数=6/6 |
| ✅ PASS | WAF 通道降级编排（A3）端到端 | 画像双拦=and,or,union,select　画像单拦=and,or,union　决策双拦=error,boolean　决策单拦=union,error,boolean |
| ✅ PASS | 红队实战评测（ground-truth 真值对照 + sqlmap 同题） | 检出=18/19　检出率=95%　安全点=7　误报=0 |
| ⏭ SKIP | fileRead 真闭环 | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |
| ⏭ SKIP | fileWrite 真闭环（文件系统侧断言） | 原因=secure_file_priv 未放行（MySQL 8 默认 NULL） |

**汇总：8 PASS / 6 FAIL(含 BLOCKED) / 5 SKIP**

## 失败详情
- **独立刁钻靶场（11 场景）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **检测回归（19 场景）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **真 MySQL 靶场**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **报告契约（自报字段必须与真实状态一致）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **CRS 人工挂链 A/B（PL1 档基线）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL
- **CRS 自动选链绕过（PL1 档基线）**：必需依赖缺失：端口 3306 未监听——请先启动 MySQL

## 跳过原因
- **OOB 带外通道真机（真 PG COPY TO PROGRAM 真实回连）**：端口 5432 未监听（CI 需先启动 PostgreSQL）
- **OOB 外部隧道真机（interactsh 协作端回连 → 轮询取回 → 检出）**：环境不满足，未执行断言
- **第三方真框架外部裁判（Juice Shop：真漏洞须检出 + 安全端点零误报）**：环境不满足，未执行断言
- **fileRead 真闭环**：secure_file_priv 未放行（MySQL 8 默认 NULL）
- **fileWrite 真闭环（文件系统侧断言）**：secure_file_priv 未放行（MySQL 8 默认 NULL）
