# docs 导航索引

> 由 `node scripts/gen-docs-index.mjs` 生成（2026-10-06），
> 覆盖 docs/ 下 74 篇 md。文档增删后重跑即可；标题取各文件的一级标题。

## 其它（专题笔记与过程记录）（8）

- [CI-集成.md](./CI-%E9%9B%86%E6%88%90.md) — 在 CI 里用 sqli-scanner 当 SQLi 门禁
- [blackbox-lab-已知问题与修复记录.md](./blackbox-lab-%E5%B7%B2%E7%9F%A5%E9%97%AE%E9%A2%98%E4%B8%8E%E4%BF%AE%E5%A4%8D%E8%AE%B0%E5%BD%95.md) — 黑盒评测：已知问题与修复记录
- [optimization-report-2026-08-25.md](./optimization-report-2026-08-25.md) — sqli-scanner 全面优化分析报告（2026-08-25）
- [全方面优化测试-2026-09-12.md](./%E5%85%A8%E6%96%B9%E9%9D%A2%E4%BC%98%E5%8C%96%E6%B5%8B%E8%AF%95-2026-09-12.md) — 全方面优化测试报告（2026-09-12）
- [安全与架构全面审计-2026-09-17.md](./%E5%AE%89%E5%85%A8%E4%B8%8E%E6%9E%B6%E6%9E%84%E5%85%A8%E9%9D%A2%E5%AE%A1%E8%AE%A1-2026-09-17.md) — sqli-scanner 全面审计：架构 / 攻防 / 工程质量
- [实战视角全面分析-2026-10-02.md](./%E5%AE%9E%E6%88%98%E8%A7%86%E8%A7%92%E5%85%A8%E9%9D%A2%E5%88%86%E6%9E%90-2026-10-02.md) — 实战视角全面分析 —— 渗透工程师视角（2026-10-02）
- [性能基线-2026-10-03.md](./%E6%80%A7%E8%83%BD%E5%9F%BA%E7%BA%BF-2026-10-03.md) — 性能端到端基线（2026-10-03）
- [服务端类型化.md](./%E6%9C%8D%E5%8A%A1%E7%AB%AF%E7%B1%BB%E5%9E%8B%E5%8C%96.md) — 服务端类型化档案（checkJs → strictNullChecks）

## 设计文档与 PRD（为什么这么设计）（17）

- [M2-列数探测加固-实施计划.md](./M2-%E5%88%97%E6%95%B0%E6%8E%A2%E6%B5%8B%E5%8A%A0%E5%9B%BA-%E5%AE%9E%E6%96%BD%E8%AE%A1%E5%88%92.md) — M2 列数探测加固：实施计划（含测试适配）
- [blind_robust_design.md](./blind_robust_design.md) — 盲注判定鲁棒性增强（统计判定）增量设计
- [dbms-fingerprint-refactor.md](./dbms-fingerprint-refactor.md) — 定库通道重构方案（DBMS Fingerprint Refactor）
- [design_three_features.md](./design_three_features.md) — sqli-scanner 增量能力设计：可插拔 tamper / OOB 带外 / 指纹扩展+表单爬取
- [prd_f19_stacked.md](./prd_f19_stacked.md) — SQL 注入检测工具「sqli-scanner」— F-19 增量 PRD（仅变更部分 · 堆叠注入 Stacke…
- [prd_p2_incremental.md](./prd_p2_incremental.md) — SQL 注入检测工具「sqli-scanner」— P2 增量 PRD（仅变更部分）
- [runScanLoop-拆分方案-2026-09-12.md](./runScanLoop-%E6%8B%86%E5%88%86%E6%96%B9%E6%A1%88-2026-09-12.md) — runScanLoop 拆分方案（2026-09-12）
- [system_design.md](./system_design.md) — SQL 注入检测工具 — 系统架构设计 + 任务分解（完整版）
- [system_design_f19.md](./system_design_f19.md) — SQL 注入检测工具「sqli-scanner」— F-19 增量设计 + 任务分解（堆叠注入 Stacked Q…
- [system_design_p2.md](./system_design_p2.md) — SQL 注入检测工具「sqli-scanner」— P2 增量设计 + 文件级任务分解
- [system_design_second_order.md](./system_design_second_order.md) — 二阶注入（Second-order / Stored SQLi）检测 — 增量设计 + 任务分解
- [优化任务清单-渗透实战视角-2026-09-08.md](./%E4%BC%98%E5%8C%96%E4%BB%BB%E5%8A%A1%E6%B8%85%E5%8D%95-%E6%B8%97%E9%80%8F%E5%AE%9E%E6%88%98%E8%A7%86%E8%A7%92-2026-09-08.md) — sqli-scanner 优化任务清单（渗透实战视角 → 全栈开发执行版）
- [全方位优化建议-2026-09-30.md](./%E5%85%A8%E6%96%B9%E4%BD%8D%E4%BC%98%E5%8C%96%E5%BB%BA%E8%AE%AE-2026-09-30.md) — 全方位优化建议（全栈视角）
- [全方面优化方案-渗透实战视角-2026-09-21.md](./%E5%85%A8%E6%96%B9%E9%9D%A2%E4%BC%98%E5%8C%96%E6%96%B9%E6%A1%88-%E6%B8%97%E9%80%8F%E5%AE%9E%E6%88%98%E8%A7%86%E8%A7%92-2026-09-21.md) — sqli-scanner 全方面优化方案（渗透实战视角）
- [实战测试与优化计划-2026-09-17.md](./%E5%AE%9E%E6%88%98%E6%B5%8B%E8%AF%95%E4%B8%8E%E4%BC%98%E5%8C%96%E8%AE%A1%E5%88%92-2026-09-17.md) — 实战测试与优化计划（2026-09-17）
- [接口缺口清单-2026-09-11.md](./%E6%8E%A5%E5%8F%A3%E7%BC%BA%E5%8F%A3%E6%B8%85%E5%8D%95-2026-09-11.md) — 接口缺口清单（2026-09-11）
- [统一探测判据-设计.md](./%E7%BB%9F%E4%B8%80%E6%8E%A2%E6%B5%8B%E5%88%A4%E6%8D%AE-%E8%AE%BE%E8%AE%A1.md) — 统一探测判据：设计（把「二分探测」的判据收敛到一处）

## 实测口径与验证记录（数字怎么来的）（8）

- [P2-dialect-probe-2026-09-22.md](./P2-dialect-probe-2026-09-22.md) — P2 方言审计取证：H2 / HSQLDB / Derby 真引擎实测（2026-09-22）
- [dbms-验证复核-2026-09-12.md](./dbms-%E9%AA%8C%E8%AF%81%E5%A4%8D%E6%A0%B8-2026-09-12.md) — DBMS 支持验证等级 —— 复核记录（2026-09-12）
- [udf-沙箱验证环境与边界.md](./udf-%E6%B2%99%E7%AE%B1%E9%AA%8C%E8%AF%81%E7%8E%AF%E5%A2%83%E4%B8%8E%E8%BE%B9%E7%95%8C.md) — UDF 接管：验证环境与边界（2026-09-18 起，如实说明，勿夸大）
- [假绿排查-schedule-only-job-2026-09-27.md](./%E5%81%87%E7%BB%BF%E6%8E%92%E6%9F%A5-schedule-only-job-2026-09-27.md) — 假绿模式排查：schedule / workflow_dispatch-only job（2026-09-27）
- [大文件拆分-五刀复盘-2026-09-21.md](./%E5%A4%A7%E6%96%87%E4%BB%B6%E6%8B%86%E5%88%86-%E4%BA%94%E5%88%80%E5%A4%8D%E7%9B%98-2026-09-21.md) — 大文件拆分复盘（2026-09-20 ~ 09-21，五刀）
- [实战渗透实测评估-2026-09-10.md](./%E5%AE%9E%E6%88%98%E6%B8%97%E9%80%8F%E5%AE%9E%E6%B5%8B%E8%AF%84%E4%BC%B0-2026-09-10.md) — sqli-scanner 实战渗透实测评估（2026-09-10）
- [实战能力实测评估-2026-09-09.md](./%E5%AE%9E%E6%88%98%E8%83%BD%E5%8A%9B%E5%AE%9E%E6%B5%8B%E8%AF%84%E4%BC%B0-2026-09-09.md) — sqli-scanner 实战能力实测评估（渗透工程师视角）
- [检测与定库-实测口径.md](./%E6%A3%80%E6%B5%8B%E4%B8%8E%E5%AE%9A%E5%BA%93-%E5%AE%9E%E6%B5%8B%E5%8F%A3%E5%BE%84.md) — 检测与定库：实测口径（真机靶场记录）

## WAF 真机对拍与绕过能力（对外口径的唯一来源）（10）

- [WAF-真机对拍-2026-09-27.md](./WAF-%E7%9C%9F%E6%9C%BA%E5%AF%B9%E6%8B%8D-2026-09-27.md) — 真机 ModSecurity 对拍（首次）—— 2026-09-27
- [WAF-真机对拍-2026-09-28.md](./WAF-%E7%9C%9F%E6%9C%BA%E5%AF%B9%E6%8B%8D-2026-09-28.md) — 真机 ModSecurity 对拍（第二轮：真库靶站）—— 2026-09-28
- [WAF-真机链对拍-2026-10-05.md](./WAF-%E7%9C%9F%E6%9C%BA%E9%93%BE%E5%AF%B9%E6%8B%8D-2026-10-05.md) — 真机 ModSecurity 链对拍（2026-10-05，modsec-live #162）
- [WAF-语义族离线筛选-2026-10-05.md](./WAF-%E8%AF%AD%E4%B9%89%E6%97%8F%E7%A6%BB%E7%BA%BF%E7%AD%9B%E9%80%89-2026-10-05.md) — WAF 语义族离线筛选（2026-10-05）
- [prd_f20_waf.md](./prd_f20_waf.md) — SQL 注入检测工具「sqli-scanner」— F-20 增量 PRD（仅变更部分 · WAF 绕过优化 / …
- [prd_wafv2.md](./prd_wafv2.md) — SQL 注入检测工具「sqli-scanner」— WAF-v2 增量 PRD（仅变更部分 · 指纹库 7→~30…
- [system_design_f20.md](./system_design_f20.md) — SQL 注入检测工具「sqli-scanner」— F-20 增量设计 + 任务分解（WAF 绕过优化 / tam…
- [system_design_wafv2.md](./system_design_wafv2.md) — SQL 注入检测工具「sqli-scanner」— WAF-v2 增量设计 + 任务分解（指纹库 7→~30 + …
- [waf-绕过能力实测口径.md](./waf-%E7%BB%95%E8%BF%87%E8%83%BD%E5%8A%9B%E5%AE%9E%E6%B5%8B%E5%8F%A3%E5%BE%84.md) — WAF 绕过能力实测口径（2026-09-19 重写：旧数字已作废）
- [waf_runbook.md](./waf_runbook.md) — WAF-v2 真实云 WAF 闭环 runbook（Cloudflare / AWS WAF + 授权靶机）

## 使用与交付（怎么部署、怎么用）（7）

- [api.md](./api.md) — sqli-scanner REST API 文档
- [deploy.md](./deploy.md) — sqli-scanner 部署指南
- [faq.md](./faq.md) — sqli-scanner 常见问题（FAQ）
- [release-notes-v1.1.0.md](./release-notes-v1.1.0.md) — sqli-scanner v1.1.0
- [user-guide.md](./user-guide.md) — sqli-scanner 用户手册
- [交付文档.md](./%E4%BA%A4%E4%BB%98%E6%96%87%E6%A1%A3.md) — sqli-scanner 交付文档
- [使用手册与交接文档.md](./%E4%BD%BF%E7%94%A8%E6%89%8B%E5%86%8C%E4%B8%8E%E4%BA%A4%E6%8E%A5%E6%96%87%E6%A1%A3.md) — sqli-scanner 使用手册与交接文档

## 对标与竞品分析（sqlmap / Arjun / ZAP）（2）

- [technique_inline_oob_tradeoff.md](./technique_inline_oob_tradeoff.md) — 检测技术取舍说明：Inline Queries（sqlmap `Q`）与 OOB 替代决策
- [竞品对标分析-2026-10-03.md](./%E7%AB%9E%E5%93%81%E5%AF%B9%E6%A0%87%E5%88%86%E6%9E%90-2026-10-03.md) — 竞品对标分析：sqli-scanner vs GitHub 同类精品（2026-10-03）

## 批次纪要与推进记录（按时间序的战报）（16）

- [优化推进-批次纪要-2026-09-29.md](./%E4%BC%98%E5%8C%96%E6%8E%A8%E8%BF%9B-%E6%89%B9%E6%AC%A1%E7%BA%AA%E8%A6%81-2026-09-29.md) — 优化推进批次纪要（2026-09-29）
- [优化推进-批次纪要-2026-10-01.md](./%E4%BC%98%E5%8C%96%E6%8E%A8%E8%BF%9B-%E6%89%B9%E6%AC%A1%E7%BA%AA%E8%A6%81-2026-10-01.md) — 优化推进批次纪要（2026-10-01）
- [优化推进-批次纪要-2026-10-02-第五批.md](./%E4%BC%98%E5%8C%96%E6%8E%A8%E8%BF%9B-%E6%89%B9%E6%AC%A1%E7%BA%AA%E8%A6%81-2026-10-02-%E7%AC%AC%E4%BA%94%E6%89%B9.md) — 优化推进 · 批次纪要（2026-10-02 第五批 · 登录编排收口）
- [优化推进-批次纪要-2026-10-02.md](./%E4%BC%98%E5%8C%96%E6%8E%A8%E8%BF%9B-%E6%89%B9%E6%AC%A1%E7%BA%AA%E8%A6%81-2026-10-02.md) — 优化推进 · 批次纪要（2026-10-02）
- [优化推进-批次纪要-2026-10-03.md](./%E4%BC%98%E5%8C%96%E6%8E%A8%E8%BF%9B-%E6%89%B9%E6%AC%A1%E7%BA%AA%E8%A6%81-2026-10-03.md) — 优化推进 · 批次纪要（2026-10-03 · CI 双红收口 + UI-REACH 14 键）
- [优化空间勘查-2026-09-23.md](./%E4%BC%98%E5%8C%96%E7%A9%BA%E9%97%B4%E5%8B%98%E6%9F%A5-2026-09-23.md) — 优化空间勘查（静态）—— 2026-09-23
- [优化空间勘查-2026-10-03.md](./%E4%BC%98%E5%8C%96%E7%A9%BA%E9%97%B4%E5%8B%98%E6%9F%A5-2026-10-03.md) — sqli-scanner 优化空间勘查（2026-10-03）
- [优化空间评估-2026-09-26.md](./%E4%BC%98%E5%8C%96%E7%A9%BA%E9%97%B4%E8%AF%84%E4%BC%B0-2026-09-26.md) — 优化空间评估（2026-09-26）
- [实战审计与优化-2026-09-08-批次.md](./%E5%AE%9E%E6%88%98%E5%AE%A1%E8%AE%A1%E4%B8%8E%E4%BC%98%E5%8C%96-2026-09-08-%E6%89%B9%E6%AC%A1.md) — sqli-scanner 实战审计与优化（2026-09-08 渗透视角批次）
- [实战审计与优化-2026-09-09-批次.md](./%E5%AE%9E%E6%88%98%E5%AE%A1%E8%AE%A1%E4%B8%8E%E4%BC%98%E5%8C%96-2026-09-09-%E6%89%B9%E6%AC%A1.md) — sqli-scanner 实战审计与优化（2026-09-09 渗透视角 · 第二批）
- [实战审计与优化-2026-09-09-批次2.md](./%E5%AE%9E%E6%88%98%E5%AE%A1%E8%AE%A1%E4%B8%8E%E4%BC%98%E5%8C%96-2026-09-09-%E6%89%B9%E6%AC%A12.md) — sqli-scanner 实战审计与优化（2026-09-09 渗透视角 · 第三批）
- [实战审计与优化-2026-09-09-批次3.md](./%E5%AE%9E%E6%88%98%E5%AE%A1%E8%AE%A1%E4%B8%8E%E4%BC%98%E5%8C%96-2026-09-09-%E6%89%B9%E6%AC%A13.md) — sqli-scanner 实战审计与优化（2026-09-09 渗透视角 · 第四批 / P1）
- [待办全景与执行分解-2026-09-22.md](./%E5%BE%85%E5%8A%9E%E5%85%A8%E6%99%AF%E4%B8%8E%E6%89%A7%E8%A1%8C%E5%88%86%E8%A7%A3-2026-09-22.md) — sqli-scanner 待办全景与执行分解（2026-09-22）
- [待办盘点-2026-09-12.md](./%E5%BE%85%E5%8A%9E%E7%9B%98%E7%82%B9-2026-09-12.md) — 待办盘点（2026-09-12）
- [竞品吸收-tamper语义对上游-2026-10-06.md](./%E7%AB%9E%E5%93%81%E5%90%B8%E6%94%B6-tamper%E8%AF%AD%E4%B9%89%E5%AF%B9%E4%B8%8A%E6%B8%B8-2026-10-06.md) — 竞品吸收批次 D7 · tamper 语义反测上游官方 doctest（2026-10-06）
- [竞品对照与吸收-2026-10-02.md](./%E7%AB%9E%E5%93%81%E5%AF%B9%E7%85%A7%E4%B8%8E%E5%90%B8%E6%94%B6-2026-10-02.md) — 竞品对照与吸收 —— 2026-10-02 批次

## 体检与评价（项目当前水准的定期体检）（6）

- [发布就绪度评估-2026-09-18.md](./%E5%8F%91%E5%B8%83%E5%B0%B1%E7%BB%AA%E5%BA%A6%E8%AF%84%E4%BC%B0-2026-09-18.md) — sqli-scanner 发布就绪度评估（2026-09-18）
- [状态收拢设计方案-2026-09-12.md](./%E7%8A%B6%E6%80%81%E6%94%B6%E6%8B%A2%E8%AE%BE%E8%AE%A1%E6%96%B9%E6%A1%88-2026-09-12.md) — runScanLoop 状态收拢设计方案（2026-09-12）
- [项目评价-2026-09-23.md](./%E9%A1%B9%E7%9B%AE%E8%AF%84%E4%BB%B7-2026-09-23.md) — sqli-scanner 项目评价（2026-09-23）
- [项目评价-2026-10-03-v2.md](./%E9%A1%B9%E7%9B%AE%E8%AF%84%E4%BB%B7-2026-10-03-v2.md) — sqli-scanner 项目评价 v2（2026-10-03 · 晚间复评）
- [项目评价-2026-10-03.md](./%E9%A1%B9%E7%9B%AE%E8%AF%84%E4%BB%B7-2026-10-03.md) — sqli-scanner 项目评价（2026-10-03）
- [验收门禁-判定纪律与事故记录.md](./%E9%AA%8C%E6%94%B6%E9%97%A8%E7%A6%81-%E5%88%A4%E5%AE%9A%E7%BA%AA%E5%BE%8B%E4%B8%8E%E4%BA%8B%E6%95%85%E8%AE%B0%E5%BD%95.md) — 验收门禁：事故记录与历史口径
