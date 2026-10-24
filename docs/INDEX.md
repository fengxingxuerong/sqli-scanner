# docs 导航索引

> 由 `node scripts/gen-docs-index.mjs` 生成（2026-10-24），
> 覆盖 docs/ 下 45 篇 md。文档增删后重跑即可；标题取各文件的一级标题。

## 其它（专题笔记与过程记录）（7）

- [Bearer令牌续期.md](./Bearer%E4%BB%A4%E7%89%8C%E7%BB%AD%E6%9C%9F.md) — Bearer/Token 自动续期（长扫描的会话维持）
- [CI-集成.md](./CI-%E9%9B%86%E6%88%90.md) — 在 CI 里用 sqli-scanner 当 SQLi 门禁
- [blackbox-lab-已知问题与修复记录.md](./blackbox-lab-%E5%B7%B2%E7%9F%A5%E9%97%AE%E9%A2%98%E4%B8%8E%E4%BF%AE%E5%A4%8D%E8%AE%B0%E5%BD%95.md) — 黑盒评测：已知问题与修复记录
- [优化底账-2026-10-18.md](./%E4%BC%98%E5%8C%96%E5%BA%95%E8%B4%A6-2026-10-18.md) — 优化底账 · sqli-scanner（2026-10-18 建账）
- [服务端类型化.md](./%E6%9C%8D%E5%8A%A1%E7%AB%AF%E7%B1%BB%E5%9E%8B%E5%8C%96.md) — 服务端类型化档案（checkJs → strictNullChecks）
- [自定义检测条目.md](./%E8%87%AA%E5%AE%9A%E4%B9%89%E6%A3%80%E6%B5%8B%E6%9D%A1%E7%9B%AE.md) — 自定义检测条目（`--payload-file`）
- [请求变换脚本.md](./%E8%AF%B7%E6%B1%82%E5%8F%98%E6%8D%A2%E8%84%9A%E6%9C%AC.md) — 自定义请求变换脚本（签名 / 加密参数接口）

## 设计文档与 PRD（为什么这么设计）（11）

- [M2-列数探测加固-实施计划.md](./M2-%E5%88%97%E6%95%B0%E6%8E%A2%E6%B5%8B%E5%8A%A0%E5%9B%BA-%E5%AE%9E%E6%96%BD%E8%AE%A1%E5%88%92.md) — M2 列数探测加固：实施计划（含测试适配）
- [blind_robust_design.md](./blind_robust_design.md) — 盲注判定鲁棒性增强（统计判定）增量设计
- [dbms-fingerprint-refactor.md](./dbms-fingerprint-refactor.md) — 定库通道重构方案（DBMS Fingerprint Refactor）
- [design_three_features.md](./design_three_features.md) — sqli-scanner 增量能力设计：可插拔 tamper / OOB 带外 / 指纹扩展+表单爬取
- [prd_f19_stacked.md](./prd_f19_stacked.md) — SQL 注入检测工具「sqli-scanner」— F-19 增量 PRD（仅变更部分 · 堆叠注入 Stacke…
- [prd_p2_incremental.md](./prd_p2_incremental.md) — SQL 注入检测工具「sqli-scanner」— P2 增量 PRD（仅变更部分）
- [system_design.md](./system_design.md) — SQL 注入检测工具 — 系统架构设计 + 任务分解（完整版）
- [system_design_f19.md](./system_design_f19.md) — SQL 注入检测工具「sqli-scanner」— F-19 增量设计 + 任务分解（堆叠注入 Stacked Q…
- [system_design_p2.md](./system_design_p2.md) — SQL 注入检测工具「sqli-scanner」— P2 增量设计 + 文件级任务分解
- [system_design_second_order.md](./system_design_second_order.md) — 二阶注入（Second-order / Stored SQLi）检测 — 增量设计 + 任务分解
- [统一探测判据-设计.md](./%E7%BB%9F%E4%B8%80%E6%8E%A2%E6%B5%8B%E5%88%A4%E6%8D%AE-%E8%AE%BE%E8%AE%A1.md) — 统一探测判据：设计（把「二分探测」的判据收敛到一处）

## WAF 真机对拍与绕过能力（对外口径的唯一来源）（11）

- [WAF-弹药库审计-2026-10-08.md](./WAF-%E5%BC%B9%E8%8D%AF%E5%BA%93%E5%AE%A1%E8%AE%A1-2026-10-08.md) — WAF 弹药库体检
- [WAF-真机对拍-2026-09-28.md](./WAF-%E7%9C%9F%E6%9C%BA%E5%AF%B9%E6%8B%8D-2026-09-28.md) — 真机 ModSecurity 对拍（第二轮：真库靶站）—— 2026-09-28
- [WAF-真机样本采集-runbook.md](./WAF-%E7%9C%9F%E6%9C%BA%E6%A0%B7%E6%9C%AC%E9%87%87%E9%9B%86-runbook.md) — WAF 真机样本采集 Runbook（P0-1）
- [WAF-真机链对拍-2026-10-05.md](./WAF-%E7%9C%9F%E6%9C%BA%E9%93%BE%E5%AF%B9%E6%8B%8D-2026-10-05.md) — 真机 ModSecurity 链对拍（2026-10-05，modsec-live #162）
- [WAF-语义族离线筛选-2026-10-05.md](./WAF-%E8%AF%AD%E4%B9%89%E6%97%8F%E7%A6%BB%E7%BA%BF%E7%AD%9B%E9%80%89-2026-10-05.md) — WAF 语义族离线筛选（2026-10-05）
- [prd_f20_waf.md](./prd_f20_waf.md) — SQL 注入检测工具「sqli-scanner」— F-20 增量 PRD（仅变更部分 · WAF 绕过优化 / …
- [prd_wafv2.md](./prd_wafv2.md) — SQL 注入检测工具「sqli-scanner」— WAF-v2 增量 PRD（仅变更部分 · 指纹库 7→~30…
- [system_design_f20.md](./system_design_f20.md) — SQL 注入检测工具「sqli-scanner」— F-20 增量设计 + 任务分解（WAF 绕过优化 / tam…
- [system_design_wafv2.md](./system_design_wafv2.md) — SQL 注入检测工具「sqli-scanner」— WAF-v2 增量设计 + 任务分解（指纹库 7→~30 + …
- [waf-绕过能力实测口径.md](./waf-%E7%BB%95%E8%BF%87%E8%83%BD%E5%8A%9B%E5%AE%9E%E6%B5%8B%E5%8F%A3%E5%BE%84.md) — WAF 绕过能力实测口径（自实现口径 2026-09-19 重写；真机现行版 2026-10-14 补立）
- [waf_runbook.md](./waf_runbook.md) — WAF-v2 真实云 WAF 闭环 runbook（Cloudflare / AWS WAF + 授权靶机）

## 使用与交付（怎么部署、怎么用）（5）

- [api.md](./api.md) — sqli-scanner REST API 文档
- [deploy.md](./deploy.md) — sqli-scanner 部署指南
- [faq.md](./faq.md) — sqli-scanner 常见问题（FAQ）
- [release-process.md](./release-process.md) — 发布流程（Release process）
- [user-guide.md](./user-guide.md) — sqli-scanner 用户手册

## 对标与竞品分析（sqlmap / Arjun / ZAP）（4）

- [nuclei模板生态可行性调研-2026-10-25.md](./nuclei%E6%A8%A1%E6%9D%BF%E7%94%9F%E6%80%81%E5%8F%AF%E8%A1%8C%E6%80%A7%E8%B0%83%E7%A0%94-2026-10-25.md) — nuclei 式模板生态 · 可行性调研（2026-10-25，W43 对标排队项收口）
- [technique_inline_oob_tradeoff.md](./technique_inline_oob_tradeoff.md) — 检测技术取舍说明：Inline Queries（sqlmap `Q`）与 OOB 替代决策
- [竞品对标-2026W43.md](./%E7%AB%9E%E5%93%81%E5%AF%B9%E6%A0%87-2026W43.md) — 竞品对标 · 2026-W43（10-19 ~ 10-25）
- [竞品对标分析-2026-10-03.md](./%E7%AB%9E%E5%93%81%E5%AF%B9%E6%A0%87%E5%88%86%E6%9E%90-2026-10-03.md) — 竞品对标分析：sqli-scanner vs GitHub 同类精品（2026-10-03）

## 体检与评价（项目当前水准的定期体检）（3）

- [release-readiness-2026-10-23.md](./release-readiness-2026-10-23.md) — 发布就绪度评估 · sqli-scanner（2026-10-23，v1.1.1 工作区）
- [项目评价-2026-10-03-v2.md](./%E9%A1%B9%E7%9B%AE%E8%AF%84%E4%BB%B7-2026-10-03-v2.md) — sqli-scanner 项目评价 v2（2026-10-03 · 晚间复评）
- [验收门禁-判定纪律与事故记录.md](./%E9%AA%8C%E6%94%B6%E9%97%A8%E7%A6%81-%E5%88%A4%E5%AE%9A%E7%BA%AA%E5%BE%8B%E4%B8%8E%E4%BA%8B%E6%95%85%E8%AE%B0%E5%BD%95.md) — 验收门禁：事故记录与历史口径

## 实测口径与验证记录（数字怎么来的）（3）

- [udf-沙箱验证环境与边界.md](./udf-%E6%B2%99%E7%AE%B1%E9%AA%8C%E8%AF%81%E7%8E%AF%E5%A2%83%E4%B8%8E%E8%BE%B9%E7%95%8C.md) — UDF 接管：验证环境与边界（2026-09-18 起，如实说明，勿夸大）
- [verification-2026-10-22-full-sweep.md](./verification-2026-10-22-full-sweep.md) — 全方面验证报告 · 2026-10-22（从头实跑，不引用历史结论）
- [检测与定库-实测口径.md](./%E6%A3%80%E6%B5%8B%E4%B8%8E%E5%AE%9A%E5%BA%93-%E5%AE%9E%E6%B5%8B%E5%8F%A3%E5%BE%84.md) — 检测与定库：实测口径（真机靶场记录）

## 批次纪要与推进记录（按时间序的战报）（1）

- [竞品吸收-tamper语义对上游-2026-10-06.md](./%E7%AB%9E%E5%93%81%E5%90%B8%E6%94%B6-tamper%E8%AF%AD%E4%B9%89%E5%AF%B9%E4%B8%8A%E6%B8%B8-2026-10-06.md) — 竞品吸收批次 D7 · tamper 语义反测上游官方 doctest（2026-10-06）
