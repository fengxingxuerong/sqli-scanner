# sqli-scanner 测试与文档质量、仓库卫生审查报告（05）

> 基线：commit `a3ef37b`（master）。所有结论基于实际读取的源码、`git ls-files` / `git log` / `git status` 输出与 CI 配置。
> 审查范围：测试覆盖缺口、测试质量、e2e 四实验室可靠性、覆盖率门槛执行、文档同步、仓库卫生。

---

## 一、测试覆盖缺口

### 1.1 规模盘点（实测）

| 维度 | 实测 | 说明 |
|---|---|---|
| 前端测试文件（src/tests） | 24 个 | `git ls-files src/tests` 确认 |
| 前端用例数（grep `\bit\(`） | 约 108 个 | README 写 92，已过期 |
| 服务端测试文件（server/tests） | 110 个 + `_setup.mjs` = 111 | `git ls-files server/tests` 确认 |
| 服务端用例数（grep `\btest\(`） | 约 1144 处声明 | README 写 733，已过期 |

### 1.2 核心路径覆盖对照

**已覆盖（质量可接受）：**

- **ScanManager 状态机**：`scanSession.test.js`、`scanManager.retire/scheduling/f19/secondOrder/sysdbs.test.js` 覆盖 start→run→complete/error、retire TTL、分层调度。缺口见下。
- **9 种检测器**：union/error/boolean/time/stacked/oob/second_order/inline/nosql 各有对应测试（detectors.test.js、errorDetector.highfreq、blindRobust、oracleTime、stackedDetector.f19、oobDetector(.dns)、secondOrderDetector、inlineQuery、noSqlInjection/noSql.phase3），无整块缺失。
- **tamper 链**：`tamper.chaining.test.js` 验证多插件按序串联、输出传递、未知插件跳过、config 开关；`tamper.test.js`/`tamper.f20.test.js` 覆盖注册表。
- **WAF 识别**：`waf.f20.test.js`、`waf_rules_v2/v3.test.js`、`waf_recommend_v2.test.js`、`scheduler.waf.test.js`、`detect.phase2.test.js` 共 6 个文件触及 WafIdentifier/wafRecommend。
- **CLI 解析（bin/cli.js）**：`cli.enum.test.js` / `cli.search.test.js` 直接 import `parseArgs/buildConfig/buildExtractScope/validateEnumArgs` 断言解析结果——是真实行为断言，不是 mock 掏空。

**明确缺口：**

1. **[高] ScanManager stop/cancel 生命周期无服务级测试**。全仓 `server/tests/*.js` 中 `.stop(` 仅出现在 oobDetector/oobReceiver 相关测试；`scanManager.*.test.js` 与 `scanRoutes.*.test.js` 均未覆盖「运行中调用 POST /api/scan/stop → 扫描中止 → 状态落盘 → 报告可取」这条路径。这是并发生命周期的核心分支（含 stop 与完成竞态），完全裸奔。
2. **[高] 并发生命周期边界**：`maxScans` 上限拒绝、retire 后 scanId 复用、SSE 订阅在扫描 error 态下的收尾，均无直接用例（retire 测试只覆盖 TTL 过期本身）。
3. **[中] API 路由层部分裸奔**：`reportAiRoutes.js`、`tamperRoutes.js`、`healthRoutes.js` 无对应路由测试（exploitRoutes/scanRoutes/sqlmapRoutes 有）；`services/ReportAI.js`（LLM 调用、key 轮换、缓存）无单测——恰是外部依赖最重、最需要契约测试的模块。
4. **[中] sessionStore 恢复语义不完整**：`sessionStore.test.js` 只测 `isSafeSessionPath` 白名单和写队列串行化；「从中断快照恢复扫描」的端到端语义（points 部分完成 → resume 跳过 done 点）只在 `phase3.sessionDefault*.test.js` 侧面触及，缺一个显式的中断-恢复回归用例。前端侧倒有 `qa_resume.test.tsx` 兜 UI 行为。
5. **[中] tamper 插件 203 个仅链路抽测**：chaining 测试只用了 space2plus/randomcase/space2comment 等 5~6 个插件；200+ 插件无参数化全量快照测试，单个插件回归坏掉不会被发现（tamper-matrix e2e 是周级 schedule 且 continue-on-error，兜不住）。
6. **[低] 前端 24 文件偏 QA 场景化**（qa_*.test.tsx 8 个），apiClient/tauriBridge 有测试但 SSE 重连退避等异步逻辑依赖组件级间接覆盖。

---

## 二、测试质量抽查

抽查 5 个文件（scanStore.test.ts、sessionStore.test.js、scanManager.scheduling.test.js、tamper.chaining.test.js、cli.enum.test.js）：

**总体结论：未发现「mock 掏空」型测试。** 抽查样本的断言均指向真实行为：

- `sessionStore.test.js`：并发写队列用例验证的是真实落盘文件内容 + 完成顺序（`assert.deepEqual(order, [...])` + 读回 JSON 断言），不是验证 mock 被调用。
- `scanManager.scheduling.test.js`：替换 detectors 为桩是合理的注入点用法，但断言的是墙钟并发性（`wall < 220ms`）、慢速层是否被调用的调度语义、报告中的风险级别——验证 ScanManager 真实编排逻辑。
- `tamper.chaining.test.js`：对转换结果做内容级断言（`'a+AND+b'`、`/**/` 保留）。
- `cli.enum.test.js`：直接 import bin/cli.js 的纯函数断言解析产物。

**质量问题（中低）：**

1. **[中] 墙钟类断言脆弱**：scheduling 测试的 `wall < 220ms` 阈值在 CI 慢机上有抖动风险（作者已留余量并注释，但本质仍是时间敏感断言，建议改为观测并发计数器而非时钟）。
2. **[中] 随机化插件断言弱**：randomcase 相关用例只能断言「不变量」（不含空格、含 +、大小写有变化），无法锁定输出——可接受但覆盖率贡献有限；建议 randomcase 支持种子注入以便精确断言。
3. **[低] 部分冒烟测试存在**：`dbDrivers.smoke.test.js`、`appMount.smoke.test.tsx` 属于「不崩即可」级别，作为分层最低档可接受，但不应计入 README 的能力宣传数字。

---

## 三、e2e 四实验室可靠性

### 3.1 结果产物入库 → diff 噪音（确认）

`git ls-files e2e` 确认以下产物被跟踪：

```
e2e/sqli-labs/results/sqli-labs.md
e2e/tamper-matrix/results/matrix.json / matrix.md
e2e/waf-lab/results/compare.json / compare.md / validate.json / validate.md
```

而 `.gitignore` 只忽略了 `e2e/recall-lab/results/`（四室仅其一）。当前 `git status` 就挂着一条 `M e2e/sqli-labs/results/sqli-labs.md`——每次跑批都会污染工作区和 PR diff。recall-lab 被 ignore 而其余三室被跟踪，策略自相矛盾。

### 3.2 CI 可运行性

- **recall-lab job：可靠**。`recall.e2e.js` 同进程起 lab-server（127.0.0.1:8123），直接 import ScanManager 驱动真实 HTTP 扫描，不依赖外部预启动 server；CI 有独立 job（timeout 5min），must 未命中 exit 1 会红。✅
- **waf-lab / tamper-matrix job：名存实亡**。`ci.yml` 的 `tamper-waf-matrix` job 调用：
  - `node e2e/tamper-matrix/run.js` —— **该文件不存在**（实际入口是 `tamper-test.mjs`）
  - `node e2e/waf-lab/run.js` —— **该文件不存在**（实际入口是 `compare.e2e.js` / `validate-tamper.mjs`）
  
  两个 step 都套了 `continue-on-error: true`，失败被静默吞掉；job 又只在 `schedule: '0 3 * * 1'` + workflow_dispatch 触发——即每周一凌晨跑两个必然 ENOENT 失败的命令，无人知晓。**死配置**。
- **sqli-labs：无 CI 入口**。runner 是 `sqli-labs-runner.mjs` + `sqli-labs.py`（Python 依赖），package.json 无 script，ci.yml 不调用，纯手动。
- **waf-lab compare.e2e.js 本身**：同进程 lab-server（端口 8099），设计上可在 CI 稳定跑，但目前没有任何 CI job 引用它；`npm run waf-e2e`/`tamper-matrix` 仅本地手动。

---

## 四、覆盖率门槛执行（核实）

**核实结论：前端 thresholds 在 CI 确实不生效。**

- `.github/workflows/ci.yml` 的 `test-frontend` job 执行 `npx vitest run --reporter=verbose`——**无 `--coverage` 标志**。vitest 的 `coverage.thresholds`（vitest.config.ts: 60/55/45/60）只在启用 coverage 收集时才评估，普通 run 直接跳过。test-matrix job 同样裸跑 `npx vitest run`。→ **门槛形同虚设，确认属实**。
- 覆盖率仅能通过本地 `npm run test:coverage`（scripts/run-coverage.mjs wrapper）触发，无 CI 强制。
- 服务端：`server/package.json` 的 `test:coverage` 用 `--test-coverage-include` 只圈定 **3 个文件**（`src/core/httpClient.js`、`src/engine/Detector.js`、`src/engine/ScanManager.js`），阈值 lines 80 / branches 70 / functions 75 仅约束这 3 个文件；Extractor/Exploiter/9 个 detector/tamper 链/sessionStore/Scheduler 均不在覆盖统计内。且 CI 的 test-server job 只跑 `npm test`，连这 3 文件的覆盖率门槛也不执行。
- 附带发现：`docs/optimization-report-2026-08-25.md`（未跟踪的新文件）第 4 节已独立指出同一问题，与本报告结论一致。

---

## 五、文档同步

1. **[中] README 测试数字过期**：README L106/L109/L119/L120 写「前端测试 92 个」「服务端测试 733 个」；实测 grep 为 **约 108 前端用例 / 约 1144 处服务端 test() 声明**（110 个文件）。数字落后于现实约 17%/56%。建议改为「以 CI 最新结果为准」或加生成脚本。
2. **[中] `docs/optimization-report-2026-08-20.md` 是空文件**（0 字符）却被 git 跟踪。应删除或补内容。
3. **[低] `docs/archive/api-audit.md` 日期为占位符**「生成日期：2026-01-xx」。归档文档可接受，但占位日期削弱可信度。
4. **[低] README 架构描述漂移**：README 写 `frontend/`+`backend/` 目录结构，实际是根目录 `src/` + `server/src/`；README 未提 CLI 入口 `server/bin/cli.js`（43+ 参数是其宣传点）与 e2e 实验室的运行方式。
5. **[低] docs/optimization-report-2026-08-25.md 尚未入库**（untracked），其中含真实 API key 泄露的高危结论，建议尽快提交并按其处置建议执行。

---

## 六、仓库卫生

### 6.1 被 git 跟踪的垃圾/敏感文件（`git ls-files` 实证）

| 文件 | 状态 | 说明 |
|---|---|---|
| `.env.ai` | **被跟踪** | LLM API 配置；08-25 报告指出含真实 key（`sk-...`），**需立即轮换** |
| `.env.development` / `.env.tauri` | 被跟踪 | 当前仅 `VITE_API_BASE` 等非密钥项，但模式危险 |
| `preview-server.err` | 被跟踪 | 根目录错误日志产物 |
| `server.err` | 被跟踪 | 同上 |

`.gitignore` 缺口分析：
- 只忽略 `.env` 和 `.env.local`，**未覆盖 `.env.*` 家族**（`.env.ai/.env.development/.env.tauri/.env.test` 全部漏网）。
- 只有 `server/*.err`，**未覆盖根目录 `*.err`**（preview-server.err、server.err 因此入库）；也未忽略 `*.log` 之外的变体（当前工作区还有 untracked 的 `sqli-labs.err`）。
- e2e 产物只忽略 recall-lab 一室（见第三节）。
- 工作区杂物：untracked 的 `quit`、`server/_audit_tmp.mjs`、`server/_audit_tmp2.mjs`、`sqli-labs.err` 散落根目录/server 下。

### 6.2 建议清理动作

```bash
git rm --cached .env.ai .env.development .env.tauri preview-server.err server.err docs/optimization-report-2026-08-20.md
# .gitignore 追加：
.env.*
!.env.example
*.err
e2e/*/results/
```

若仓库已推远端：`.env.ai` 涉嫌泄露 key，须先服务商侧轮换，再考虑 `git filter-repo` 清历史。

---

## 七、优先级汇总

### 高优先级
1. **`.env.ai` 疑似真实 LLM key 入库** → 服务商侧吊销/轮换 + `git rm --cached` + 补 `.gitignore`（配合 08-25 报告处置）。
2. **CI tamper-waf-matrix 引用不存在的脚本**（`e2e/tamper-matrix/run.js`、`e2e/waf-lab/run.js`）且 `continue-on-error: true` 掩盖失败 → 改为真实入口或删除该 job。
3. **ScanManager stop/cancel 生命周期零测试**（运行中止、stop-完成竞态、maxScans 拒绝）→ 补路由级 + ScanManager 级用例。
4. **覆盖率门槛 CI 不生效确认属实** → test-frontend 加 `--coverage`；server 覆盖范围从 3 文件逐步扩大并在 CI 执行。

### 中优先级
5. README 测试数字过期（92/733 vs 实测约 108/约1144）、空报告文件 `optimization-report-2026-08-20.md` 删除。
6. e2e 结果产物三室被跟踪产生持续 diff 噪音 → 统一 gitignore + CI artifact 化。
7. ReportAI/reportAiRoutes/tamperRoutes/healthRoutes 无测试；sessionStore 缺中断-恢复端到端回归。
8. 根目录 `*.err` 与 `.env.*` 忽略缺口；工作区杂物（_audit_tmp*.mjs、quit、sqli-labs.err）清理。

### 低优先级
9. tamper 插件缺参数化全量回归（203 个仅抽测链路）。
10. scheduling 测试墙钟断言改并发计数器；randomcase 种子化。
11. api-audit.md 占位日期补正；README 架构目录描述与实际对齐。
12. sqli-labs（Python）无 npm script/CI 入口，至少补文档说明运行方式。
