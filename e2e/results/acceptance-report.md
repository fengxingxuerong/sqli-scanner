# 全方位验收门禁报告

> 生成：2026-10-17T18:40:59.738Z　｜　执行器：`node e2e/acceptance.mjs`　｜　Node v22.22.3
> 代码版本：`0839667`　⚠️ **工作区 dirty**（跑验收前有 6 个未提交改动：CHANGELOG.md、README.md、docs/_facts.json 等）—— **本报告不对应任何提交**
> 套件范围：**19/20 跑出断言**　｜　⚠️ **判定：不完整 —— 不得当作该代码版本的整体验收结论**
> 前置：MySQL 8.0.28 @127.0.0.1:3306；secure_file_priv="NULL"

> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。

| 结果 | 套件 | 事实 |
|---|---|---|
| ✅ PASS | 服务端单测 | tests=3616　pass=3614　fail=0　skipped=2 |
| ✅ PASS | 独立刁钻靶场（11 场景） | 漏洞场景=11/11　安全误报=0 |
| ✅ PASS | 检测回归（19 场景） | PASS=19　FAIL=0 |
| ✅ PASS | 真 MySQL 靶场 | PASS=11　FAIL=0 |
| ✅ PASS | 参数名注入真靶场（键名拼 SQL 检出 + 白名单对照零检出 + 开关语义） | PASS=1　FAIL=0 |
| ✅ PASS | 真 PG 靶场（含二阶注入） | 全部通过=true　引擎=PGlite |
| ✅ PASS | 批量编排故障隔离（-m：死目标不拖垮整批，结论不乱写） | PASS=1　FAIL=0 |
| ✅ PASS | 登录编排自动重登（真表单登录 + 会话反复过期，含「不给登录则 0 检出」对照） | PASS=1　FAIL=0 |
| ✅ PASS | OOB 带外通道真机（真 PG COPY TO PROGRAM 真实回连） | OOB真实回连=✅　对照组=0 检出（OOB 唯一可达） |
| ✅ PASS | OOB 外部隧道真机（interactsh 协作端回连 → 轮询取回 → 检出） | OOB外部隧道=✅ 检出　靶站回连=14 DNS + 14 HTTP |
| ⏭ SKIP | 第三方真框架外部裁判（Juice Shop：真漏洞须检出 + 安全端点零误报） | 原因=环境不满足，未执行断言 |
| ✅ PASS | 报告契约（自报字段必须与真实状态一致） | 通过=8　不一致=0 |
| ✅ PASS | CRS 人工挂链 A/B（PL1 档基线） | off=8　on=8　基线=off≥8 on≥8　安全对照误拦=false |
| ✅ PASS | CRS 自动选链绕过（PL1 档基线） | 技术位=9　基线=≥8　安全误报=0 |
| ✅ PASS | CRS 执行器保真度（官方回归集） | 保真度=99.6%　未点名分歧=0　已消失=0　误触=2 |
| ✅ PASS | WAF 定向变异搜索（A2）端到端 | A档生成链=2　B档生成链=0　验证条数=6/6 |
| ✅ PASS | WAF 通道降级编排（A3）端到端 | 画像双拦=and,or,union,select　画像单拦=and,or,union　决策双拦=error,boolean　决策单拦=union,error,boolean |
| ✅ PASS | 红队实战评测（ground-truth 真值对照 + sqlmap 同题） | 检出=19/19　检出率=100%　安全点=7　误报=0 |
| ✅ PASS | fileRead 真闭环 | PASS=true　SKIP=false　方式=隔离沙箱重试 |
| ✅ PASS | fileWrite 真闭环（文件系统侧断言） | PASS=true　SKIP=false　文件落盘=true　方式=隔离沙箱重试 |

**汇总：19 PASS / 0 FAIL(含 BLOCKED) / 1 SKIP**


## 跳过原因
- **第三方真框架外部裁判（Juice Shop：真漏洞须检出 + 安全端点零误报）**：环境不满足，未执行断言
