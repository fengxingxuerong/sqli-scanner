# runScanLoop 拆分方案（2026-09-12）

> 结论先行：**分三批渐进拆，每批独立提交 + 独立验证；不建议一次性重写。**

## 实施进度

| 批次 | 内容 | 状态 |
|---|---|---|
| 第一批 | `finalize.js`（阶段5）+ `supplemental.js`（3.5/3.6） | ✅ **已完成**（1184 → 1042 行） |
| 第二批 | `aggregate.js`（阶段3）+ `extract.js`（阶段4） | ✅ **已完成**（1042 → 948 行） |
| 第三批 | `discover.js` + `context.js` + `detect.js`（~550 行，高风险） | ⏳ 待做 |

累计：**1184 → 948 行（-236）**，已抽出 4 个阶段模块。

**第二批次的两个注意点**（供第三批参考）：
1. 阶段 3 末尾的 `if (s.cancelled) { …收尾…; return; }` **没有一起搬出** —— 它含早退 `return`，
   属主流程控制而非聚合逻辑，留在 `runScanLoop` 中（搬移脚本对该行做了边界断言）。
2. 报告 diff 曾误报一次"行为差异"：`diff-reports.mjs` 原先用 `readdirSync().find()` 取第一个匹配，
   目录里 `<id>.r1.json`（默认档）与 `<id>.r2.json`（实战档）并存时读到了旧档位。
   已修为「精确名优先、其余取 mtime 最新」。**教训：对比工具自身的文件匹配必须确定**，
   否则会把档位差异误判成重构回归（当时靠 6/6 对照实验排除后才定位到工具）。

**第一批的验证结果**（三件套全过）：

1. 全量单测 **1735/1735 通过**
2. 靶场全量复测 **18/18 漏洞点命中 + 7/7 安全点零误报**
3. **报告字段级等价**（`e2e/redteam-lab/diff-reports.mjs` 对比 A1/C7/D13 三靶点，无差异）

顺带产出正式工具 `e2e/redteam-lab/diff-reports.mjs`（可复用，任何重构都能拿它做行为等价性门禁）。

## 一、现状

`server/src/engine/scanRunner.js` 全文 1184 行，其中 `runScanLoop(sm, scanId)` 一个函数占
**第 37–1184 行 ≈ 1148 行**。内部阶段划分（按现有注释标记）：

| 阶段 | 行范围 | 行数 | 职责 |
|---|---|---|---|
| 0 初始化 | 37–181 | ~145 | 取扫描状态、作用域 HttpClient、AbortSignal、DbHealthGuard、ScanValidityGuard、Scheduler 构造 |
| 1 发现注入点 | 182–354 | ~173 | `parser.discover` + 表单/链接爬取 + 空注入点告警 + 会话 resume |
| 2 检测调度 | 355–616 | ~262 | 并发池 + 令牌桶限速 + 重试 + per-point × per-technique 检测 |
| 3.x WAF 自适应重跑 | 617–904 | ~288 | 识别拦截证据 → 选 tamper 链 → 链验证 → 换算子族重跑未命中点 |
| 3 聚合去重 | 905–954 | ~50 | stacked 去重、风险定级、finalVulns 组装 |
| 3.5 二阶补充趟 | 955–960 | ~6 | `sm._runSecondOrder(...)` |
| 3.6 非 SQL 补充趟 | 961–965 | ~5 | `sm._runNoSql(...)` |
| 4 提取 | 966–1038 | ~73 | 对最终漏洞做拖库/版本证明，合并进 `extracted` |
| 5 汇总报告 | 1039–1184 | ~146 | 风险定级、summary/constraints、PoC、落盘、事件收尾 |

### 为什么现在该拆

拆它不是洁癖。本周已经**两次被迫绕开它**：

- 二阶注入存储点 → 不敢改检测流程，改在 `TargetParser` 打标
- 单点重测 → 不敢抽 per-point 入口，改用 `config.onlyPoint` 收敛

每加一个能力都要在 1148 行里穿针引线，理解成本与回归风险都在累积。

### 抽取难点（必须先承认）

函数内 40+ 个 `const` 局部变量被后续阶段闭包引用（`s / target / report / client / scanSignal /
guard / validity / observeValidity / schedulerRef / ctxBase / foundByPoint / finalVulns / extracted …`）。
**抽取的前提是先引入一个显式的运行期上下文对象 `run`**，把跨阶段状态挂上去，否则抽出来的函数
要么参数爆炸，要么靠闭包隐式耦合（更糟）。

## 二、目标结构

```
engine/
  scanRunner.js          # 只剩编排：初始化 run → 依次调用各阶段（目标 ~250 行）
  scan/
    context.js           # 构造 run 上下文（阶段 0 的产物，含守卫/信号/限速器）
    discover.js          # 阶段 1
    detect.js            # 阶段 2 + 3.x（WAF 自适应）
    aggregate.js         # 阶段 3
    supplemental.js      # 阶段 3.5 / 3.6
    extract.js           # 阶段 4
    finalize.js          # 阶段 5
```

约定：每个阶段函数签名统一 `async function stage(run) → void`（就地更新 `run.report` /
`run.extracted` 等可变对象）。**禁止传副本**——阶段间靠可变对象共享状态是本函数既有语义。

## 三、分批执行计划（每批独立提交）

### 第一批（低风险，建议先做）
- 抽 `finalize.js`（阶段 5，~146 行）：输入 `run.report / run.finalVulns / run.state`，输出写回 `run.report`
- 抽 `supplemental.js`（阶段 3.5 + 3.6，~11 行）：已是独立方法调用，纯搬移
- 预期：`runScanLoop` 从 1148 → **~990 行**

### 第二批（中风险）
- 抽 `extract.js`（阶段 4，~73 行）
- 抽 `aggregate.js`（阶段 3，~50 行）
- 预期：→ **~860 行**

### 第三批（高风险，最后做）
- 抽 `discover.js`（阶段 1，~173 行）
- 抽 `context.js`（阶段 0，~145 行）
- 抽 `detect.js`（阶段 2 + 3.x，**~550 行**）——与 `scheduler` / `ctxBase` / `foundByPoint`
  深度交织，需要把限速器生命周期一并搬入
- 预期：→ **~250 行**（纯编排）

## 四、每批的验证协议（缺一不可）

```bash
# 1) 全量单测（当前基线 1735 通过）
cd server && NO_PROXY=127.0.0.1 node --test --test-concurrency=1

# 2) 靶场全量复测（当前基线：实战档 17/17 + 7 个安全点零误报）
cd .. && NO_PROXY=127.0.0.1 node e2e/redteam-lab/run-scan.mjs r2

# 3) 报告 diff（行为等价性，比"测试通过"更强）
#    同一目标在改动前后各扫一次，除时间戳/请求数外，报告结构必须一致
node e2e/redteam-lab/run-scan.mjs r2 A1-int-union && cp e2e/redteam-lab/out/A1-int-union.r2.json /tmp/a1-before.json
# 改完再跑一次 → 对比 points / vulns[].technique / riskLevel
```

**硬要求**：每批只做纯搬移，**不顺手"优化"逻辑**。任何行为改动混进来，报告 diff 就失去意义。

## 五、风险与回退

| 风险 | 表现 | 对策 |
|---|---|---|
| 传副本而非引用 | 报告的 points/vulns 更新丢失，测试可能仍过 | 阶段函数只接 `run` 对象，回写 `run.report` |
| 事件时序改变 | 前端进度条错乱（`eventBus.emit` 在阶段内散落） | 搬移时保持 emit 相对顺序；靶场 r2 会暴露 |
| `stop()` 中断语义破坏 | `s.cancelled` 检查漏搬 → 停不下来的扫描 | 阶段 2/3.x 的取消检查逐处核对 |
| 一次性重写引入难查回归 | 大面积行为漂移 | 已排除：分三批，每批可单独回退 |

## 六、收益（诚实评估）

- **不带来任何用户可见的功能变化**，纯粹是后续迭代速度与回归风险的投资
- 抽完后：新增一条检测通道（如又一次加"XX 注入"）可以只改 `detect.js`，不必碰 1148 行巨函数
- 若近期以交付/售卖为优先，本项**可让位于**「DBMS 支持口径订正」（宣称 11 库、实测仅 MySQL/PG，属对外风险）
