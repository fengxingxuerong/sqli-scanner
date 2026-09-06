# sqli-scanner 二轮审查 —— 测试覆盖与文档质量（r2-05）

> 审查日期：2026-08-25 晚 · 审查人：quality-docs 主代理直审（子代理额度耗尽后补位）· 基于上一轮（05-quality-docs.md）修复后的复检 + 新增面

---

## 一、上一轮遗留项复核

| 上轮发现 | 本轮状态 |
|---|---|
| CI test-frontend 无 --coverage → thresholds 不生效 | ✅ 已修（ci.yml 接入 `--coverage`，本地实测门槛 60/55/45/60 真实生效）|
| README 92/733 过期数字 | ✅ 已修并再次同步（本轮实测 **前端 109 / 服务端 1050**）|
| docs/optimization-report-2026-08-20.md 空文件 | ✅ 已删除 |
| preview-server.err/server.err 被 git 跟踪 | ✅ 已出库（7ca2add）|

## 二、测试资产现状（实测）

- server/tests：**110 文件 ≈1050 用例**；src/tests：24 文件 ≈109 用例
- 一轮补零后仍无任何测试引用的源文件已清零：healthRoutes / reportAiRoutes / ReportAI / payloads/others / scanRunner.runScanLoop / WAF 厂商 tamper 链路均已补测（本日 commit）
- 回归防护质量抽查：union.numericMarker、stackedDetector.f19、inlineQuery、scanRunner.loop 四个新增文件均为行为断言而非 mock 互证，断言强度合格 ✓

## 三、剩余缺口（按价值排序）

1. **[中] e2e 四实验室未进 CI**：recall-lab 有 npm script 且 CI 有 job，但 sqli-labs/waf-lab-v2/tamper-matrix 三个仅能本地手动跑；waf-lab-v2 script 的 Unix 前缀在 Windows CI runner 上会挂（上轮已指出，仍未改）。建议至少把 waf-lab-v2 改成 node 脚本消除平台耦合。
2. **[中] eventBus 双写回归无守卫**：本轮修复的终态事件双发 bug（listener 与 terminalListener 各 write 一次），现有 eventBus.test.js 未断言「单连接只收到一条终态事件」。建议补一条断言防止回归。
3. **[低] vitest thresholds 对 hooks 层偏低**：hooks 目录行覆盖约 55% 刚过线，useEvents 的重连分支（seq 游标/lastEventId 续传）只有间接路径覆盖。
4. **[低] CHANGELOG 缺失**：近两日 10+ 个提交横跨安全修复与引擎行为变化，用户可感知（如 gzip tamper 输出格式变化），无版本化记录载体。

## 四、文档同步状态

- README 测试数字 ✓ 已对齐实测；能力表与 payloadRegistry 数量一致 ✓
- docs/vs-sqlmap-analysis/05-execution-summary.md 尾部「最终状态 1010」与本日实际 1050+ 存在时间性漂移——属历史执行快照性质文档，可不改，但建议文末加一行「数字截至 2026-08-16」防误读。

## 五、汇总

高：0 ｜ 中：2（e2e 平台耦合、双写回归守卫）｜ 低：2。一轮的四个 HIGH 全部闭环，当前测试体系的主要矛盾从「缺口」转为「CI 可重复性与回归守卫密度」。