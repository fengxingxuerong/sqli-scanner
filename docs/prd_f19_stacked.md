# SQL 注入检测工具「sqli-scanner」— F-19 增量 PRD（仅变更部分 · 堆叠注入 Stacked Queries）

> 作者：产品经理 许清楚（Xu）
> 版本：F-19 增量（基于已交付完整版 v1.0.0 + P2 增强）
> 语言：简体中文
> 配套架构背景：`docs/system_design.md`（完整版）、`docs/prd_p2_incremental.md`（P2 增量）

---

## 1. 增量概述

在已交付的 4 类注入检测（UNION 回显 / 报错 / 布尔盲注 / 时间盲注）之上，F-19 新增第 5 类检测技术 **「堆叠注入 Stacked Queries」**，让用户在扫描配置中可勾选该技术，并由引擎确认目标是否存在"可追加执行多条语句"的注入点（如 `id=1; SELECT ...`、`id=1; SLEEP(5)`）。

堆叠注入的本质不是"回显/盲注某一查询结果"，而是**利用 `;`（分号）把一条 SQL 追加成多条独立语句并都能执行**。它不同于 UNION/盲注：核心判据是"第二条语句是否被成功执行"，典型的稳定佐证是注入后产生**时间延迟**（如 `; WAITFOR DELAY '0:0:5'` / `; SLEEP(5)`）。一旦确认，通常意味着可直接写文件 / 命令执行，风险等级一般定为 **Critical**。

### 1.1 现状核查（重要，与需求说明前提不符之处，如实标注）

编写前已阅读 `server/src/engine/`、`server/src/engine/detectors/`、`payloads.js`、`ScanManager.js` 与前端 `src/shared/*`、`src/components/*`，发现以下与"让用户可勾选该技术进行扫描"这一前提**不一致**的现状，需工程/架构确认：

1. **当前不存在"技术选择"机制。** `ScanConfig`（`src/shared/types.ts`）**没有 `techniques` 字段**；`ScanConfigPanel.tsx` / `TargetForm.tsx` 中**没有任何技术多选/勾选控件**；`ScanManager._run()` 中对 `this.detectors` 做**无条件 `for…of` 全跑**，不按任何技术集合过滤。即今天 4 类检测是"始终全量执行、用户无法开关"。
2. **技术枚举分散，后端无集中定义。** 前端 `TechniqueType`（`types.ts`）为联合类型 `'union' | 'error' | 'boolean' | 'time'`；`TECHNIQUES`（`constants.ts`）为展示用数组、`TECHNIQUE_LABEL` 为中文映射。后端**没有集中 `TechniqueType` 枚举**，各 `Detector` 仅在构造时以 `super('time')` 自报技术名，`PAYLOADS[dbms][technique]` 的键需与该字符串严格一致。
3. **SQL Server 的 `time` 技术 payload 已是堆叠式。** `payloads.js` 中 `SQL Server.time` 为 `"{ORIG}; WAITFOR DELAY '0:0:{SLEEP}'-- -"`——即 `time` 技术对 SQL Server 实际已用 `;` 分隔触发延迟。因此 stacked 与 time 在 SQL Server 上会**相互印证/可能重复报告**（见 §7 待确认 Q7）。
4. **Oracle 标准驱动不支持堆叠查询。** Oracle（OCI/多数驱动）不允许单语句外执行第二条语句，堆叠注入对其基本不适用，需明确"不投放 / 标注不适用"。

> 结论：要满足"让用户可勾选堆叠"，F-19 **必须同时引入技术选择机制**（新增 `config.techniques` + UI 多选 + `ScanManager` 按集合过滤），而不能仅在引擎里加一个永远随全量跑的检测器。该机制本期建议一并落地，默认保持"4 类全选 + 堆叠默认不选"以维持向后兼容。具体见 §5 P0-5 与 §7 Q1。

---

## 2. 产品目标

| # | 目标 | 说明（可衡量） |
|---|------|----------------|
| G1 | 能力补齐：新增可确认"堆叠可用"的第 5 类检测技术 | 5 种 DBMS 中至少 4 种（PostgreSQL/SQL Server/SQLite/MySQL）可投放堆叠 payload 并完成检测；Oracle 明确标注不适用。 |
| G2 | 用户可控：在扫描配置中暴露并可选是否启用堆叠检测 | ScanConfigPanel 提供"堆叠注入"可勾选项；勾选才对该技术发起检测，不勾选则跳过（需配套技术选择机制，见 §1.1）。 |
| G3 | 结果可信：堆叠命中在报告中明确呈现并定级为高危 | 报告中 `technique='stacked'` 可区分展示，风险定级为 **Critical**，并附"可直接写文件/命令执行"的专项说明。 |

三个目标彼此正交：G1 是引擎能力、G2 是用户交互、G3 是报告与风险表达。

---

## 3. 用户故事

| # | 角色 | 期望 | 价值 |
|---|------|------|------|
| US1 | 安全测试人员 | 作为测试人员，我希望在扫描配置里勾选"堆叠注入"，以便专门验证目标是否允许执行多条语句。 | 针对高危场景做定向验证，不依赖全量盲扫。 |
| US2 | 安全测试人员 | 作为测试人员，当引擎通过"注入后产生时间延迟"确认堆叠可用时，我希望在报告中看到明确的高危标记与证据 Payload。 | 快速判断目标是否可被用于写文件/命令执行。 |
| US3 | 安全测试人员 | 作为测试人员，我希望默认扫描行为不被改变（原有 4 类照常全跑），堆叠作为可选增强按需开启。 | 向后兼容，避免影响既有扫描结果与脚本。 |
| US4 | 审计/合规人员 | 作为审计人员，我希望报告中能区分"堆叠注入"与其他注入类型，并标注其 Critical 风险与潜在利用面。 | 准确评估资产风险敞口，支撑整改优先级。 |

---

## 4. 变更点清单（按模块）

| 编号 | 变更描述 | 影响模块 | 验收标准（要点） | 风险等级 |
|------|----------|----------|------------------|----------|
| F-19a | 新增 `stacked` 技术枚举与中文标签：前端 `TechniqueType` 加入 `'stacked'`；`TECHNIQUES` 加入 `'stacked'`；`TECHNIQUE_LABEL` 加入 `stacked: '堆叠注入'`。 | 前端 `types.ts` / `constants.ts` | 类型与常量包含 `stacked`；列表/报告中可用 `TECHNIQUE_LABEL` 取到中文。 | 低 |
| F-19b | 新增 `StackedDetector`（`super('stacked')`），实现以 `;` 追加独立延迟语句、按响应耗时判定堆叠可用的检测逻辑，并复用统一 `HttpClient`/`obfuscateValue`。 | 后端 `detectors/StackedDetector.js` | 对已知 dbms 注入 `; SLEEP/WAITFOR/pg_sleep` 后，延迟稳定 ≥ 阈值即判 vulnerable，evidence 含判据说明。 | 中 |
| F-19c | `payloads.js` 为各 DBMS 新增 `stacked` 模板（MySQL/PostgreSQL/SQL Server/SQLite；Oracle 标注不适用、不投放）。 | 后端 `payloads.js` | 5 库均有 `stacked` 键（Oracle 为占位/标记位）；占位符 `{ORIG}/{SLEEP}` 可正常填充。 | 低 |
| F-19d | 报告与风险定级：stacked 命中在 `riskOf` 中映射为 **Critical**；`VulnList`/`VulnDetail` 经 `TECHNIQUE_LABEL` 显示"堆叠注入"；JSON/HTML 导出按现有技术字段呈现并含 `byTechnique` 统计。 | 后端 `ReportGenerator.js` / 前端 `VulnList.tsx` / `VulnDetail.tsx` | 报告 `technique='stacked'`、`riskLevel='Critical'`；导出 HTML 风险列显红、技术列显示中文。 | 中 |
| F-19e | 引入技术选择机制并在 UI 暴露堆叠选项：`ScanConfig` 新增 `techniques: TechniqueType[]`；`ScanConfigPanel` 新增"检测技术"多选组（含 4 既有+堆叠）；`ScanManager` 按 `config.techniques` 过滤检测器（未定义/空视为全选以维持兼容）。 | 前端 `types.ts`/`constants.ts`/`ScanConfigPanel.tsx` + 后端 `ScanManager.js`/`models.js`/`defaults.js` | 可多选技术并仅对勾选项检测；默认 4 类全选、堆叠默认不选；老配置（无 techniques）等同全选，行为不变。 | 高 |
| F-19f | WAF 规避混淆对堆叠 payload 生效（复用 `obfuscateValue`，确认 `;` 不被破坏）。 | 后端 `StackedDetector.js` | 开启混淆时堆叠 payload 经统一 `send`/`obfuscateValue` 通道发送，`;` 与延迟函数名保留。 | 低 |

---

## 5. 需求池（P0 / P1 / P2 分级）

> 优先级：P0 = 必须（本期交付）；P1 = 应当（高价值，力争本期）；P2 = 可选（后续或增强）。
> 范围边界：本期仅做"检测/确认堆叠可用 + UI 暴露 + 报告呈现"，**不做自动利用层**（写文件 / 命令执行 / 拖库），详见 §6。

### P0（必须）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P0-1 | 新增 `stacked` 技术枚举与中文标签（前端 `TechniqueType` 联合 + `TECHNIQUES` 数组 + `TECHNIQUE_LABEL['stacked']='堆叠注入'`）。 | `types.ts`, `constants.ts` | 编译通过；任意展示处用 `TECHNIQUE_LABEL['stacked']` 取到"堆叠注入"。 |
| P0-2 | 实现 `StackedDetector`：对指纹已识别的 dbms，以 `;` 分隔追加一条独立延迟语句（MySQL `SLEEP` / PostgreSQL `pg_sleep` / SQL Server `WAITFOR DELAY` / SQLite 重运算近似），以"响应耗时 ≥ 阈值且稳定多次"为主判据确认堆叠可用；复用 `timeThresholdMs` 与采样次数；经统一 `HttpClient` 发送、`obfuscateValue` 包裹。 | `detectors/StackedDetector.js` | 对存在堆叠的目标，连续 N/2 次以上延迟 ≥ 阈值判 vulnerable；evidence 说明"`;` 后第二条语句被执行"。 |
| P0-3 | `payloads.js` 为 5 库新增 `stacked` 模板（占位符 `{ORIG}`/`{SLEEP}`），Oracle 以"不适用"占位并显式跳过投放。 | `payloads.js` | 各库 `PAYLOADS[dbms].stacked` 存在；Oracle 不进入实际检测。 |
| P0-4 | 风险定级：stacked 命中在 `ReportGenerator.riskOf` 中映射为 **Critical**（高于 union/error=High、boolean/time=Medium）。 | `ReportGenerator.js` | 仅 stacked 命中时整体 riskLevel=Critical；与既有定级规则共存不冲突。 |
| P0-5 | 技术选择机制 + 堆叠选项暴露：①`ScanConfig` 新增 `techniques: TechniqueType[]`；②`ScanConfigPanel` 新增"检测技术"多选组（联合/报错/布尔/时间/堆叠）；③`ScanManager` 按 `config.techniques` 过滤检测器；④`config.techniques` 为空/未定义时视为"全选"（维持向后兼容）。默认 4 类勾选、堆叠默认**不勾选**（opt-in）。 | `types.ts`, `defaults.js`, `models.js`, `ScanManager.js`, `ScanConfigPanel.tsx` | 可勾选并仅对所选技术检测；默认态下既有 4 类全跑、堆叠不跑；老配置/无 techniques 字段等同全选，行为不变。 |
| P0-6 | 报告呈现堆叠漏洞：JSON/HTML 导出含 `technique='stacked'` 与 `riskLevel='Critical'`，`byTechnique` 统计计数；`VulnList`/`VulnDetail` 经 `TECHNIQUE_LABEL` 显示"堆叠注入"。 | `ReportGenerator.js`, `VulnList.tsx`, `VulnDetail.tsx` | 报告中堆叠漏洞可区分、显 Critical；前端列表/详情显示中文标签与风险 Chip。 |

### P1（应当）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P1-1 | 副作用副判据（可选补充）：在时间延迟主判据之外，提供"建/删临时表"类副作用探针作为补充确认；因具破坏性，默认**关闭**，需显式开启。 | `StackedDetector.js`, `payloads.js` | 开启后能用副作用语句间接佐证堆叠；关闭时仅用时间判据。 |
| P1-2 | 堆叠专项风险说明：在 `VulnDetail` 描述与 HTML 导出中，附"堆叠注入可进一步用于写文件/命令执行（非本期自动利用）"的提示，帮助用户评估利用面。 | `VulnDetail.tsx`, `ReportGenerator.js` | 详情与导出均含堆叠专项说明文本。 |
| P1-3 | 堆叠检测复用统一超时/混淆通道：确认 `StackedDetector` 走 `Detector.send`/`obfuscateValue`，WAF 规避开启时 `;` 不被混淆破坏，延迟函数名保留。 | `StackedDetector.js`, `Detector.js` | 开启 WAF 混淆时堆叠检测仍可正常判定。 |
| P1-4 | 延迟参数策略：明确堆叠延迟秒数与判定阈值——建议堆叠 `SLEEP` 固定 2–5s，判定阈值复用 `timeThresholdMs`（不新增独立参数）。 | `defaults.js`, `StackedDetector.js` | 参数来源清晰，无需新增配置项即可运行。 |

### P2（可选 / 后续增强）

| ID | 需求 | 说明 |
|----|------|------|
| P2-1 | Oracle 显式提示：在 UI 技术选择或报告中标注"Oracle 不支持堆叠查询，该技术不适用"。 | 降低误投放与误报。 |
| P2-2 | 重叠去重：SQL Server 的 `time` payload 已是 `; WAITFOR`（堆叠式），stacked 与 time 会双重印证；建议报告层去重或标注"互相印证"。 | 见 §7 Q7。 |
| P2-3 | 端到端靶机用例：在 e2e 测试中加入 MySQL（`multiStatements` 开启）/ SQL Server 堆叠靶机，验证 stacked 命中（≥1 例）。 | 提升检测可信度。 |
| P2-4 | 堆叠专用混淆增强：对 `;` 后可尝试注释分割/大小写变体，进一步规避 WAF。 | 复用 `obfuscatePayload` 思路。 |

---

## 6. UI 设计稿（界面变化文字描述）

> 仅描述相对现有 `ScanConfigPanel` 的**变更**，其余配置区（超时/并发/重试/阈值/限速/拖库、代理/认证、WAF 规避）保持原样。

- **新增"检测技术"分区**（位于"扫描配置"主区与"代理/认证"之间，或作为独立 Divider 分组）：
  - 一组多选控件（Checkbox / Chip 多选），选项与中文标签来自 `TECHNIQUES` + `TECHNIQUE_LABEL`：
    - ☑ 联合查询注入（union）
    - ☑ 报错注入（error）
    - ☑ 布尔盲注（boolean）
    - ☑ 时间盲注（time）
    - ☐ **堆叠注入（stacked）** ← 本期新增，**默认未选中**，附一行次要说明文字："堆叠注入可确认目标是否允许执行多条语句，风险高，按需开启"。
  - 选择结果写入 `ScanConfig.techniques`；取消全部选择时按"全选"处理（兼容老配置）。
- **漏洞列表 / 详情（`VulnList` / `VulnDetail`）**：无需新增布局，堆叠漏洞经 `TECHNIQUE_LABEL['stacked']` 自动显示"堆叠注入"，风险 Chip 因 Critical 显示红色（沿用现有 `RISK_COLOR`/`RISK_LABEL`）。
- **报告导出（JSON / HTML）**：漏洞清单"技术"列显示 `stacked` 原始值或"堆叠注入"中文（建议中文），"风险"列显示 `Critical`；汇总 `byTechnique` 含 `stacked` 计数；HTML 关键风险行套用现有 `.critical` 红色样式。
- **向后兼容**：老用户/老历史配置无 `techniques` 字段时，等价于"4 类全选、堆叠不跑"，扫描结果与今日一致。

---

## 7. 对旧架构的影响与风险

### 7.1 接入点（基于现有设计）

| 变更 | 接入旧模块 | 说明 |
|------|------------|------|
| F-19a 枚举/标签 | `src/shared/types.ts`（`TechniqueType`）、`src/shared/constants.ts`（`TECHNIQUES` / `TECHNIQUE_LABEL`） | 纯前端枚举扩展，不破坏既有值；新增 `'stacked'`。 |
| F-19b 检测器 | `server/src/engine/detectors/StackedDetector.js`（新增）+ `Detector.js`（基类，`send`/`obfuscateValue` 复用） | 沿用策略模式：构造 `super('stacked')`，实现 `detect(ctx)`，返回 `DetectionResult`。 |
| F-19c Payload | `server/src/engine/payloads.js`（`PAYLOADS[dbms].stacked`） | 仅增键，不影响既有 union/error/boolean/time 模板；Oracle 以不适用占位。 |
| F-19d 报告定级 | `server/src/services/ReportGenerator.js`（`riskOf` 增加 `stacked→Critical`） | 在既有 if 链中前置 stacked 分支；其余定级逻辑不变。 |
| F-19e 技术选择 | `ScanManager.js`（按 `config.techniques` 过滤 `this.detectors`）、`models.js`/`defaults.js`（合并 `techniques`）、`ScanConfigPanel.tsx`（多选 UI） | **本期最大改动点**：引入过滤后必须保证"未定义=全选"以兼容老配置，否则影响全部既有扫描。 |
| 前端展示 | `VulnList.tsx` / `VulnDetail.tsx` / 导出链路 | 经 `TECHNIQUE_LABEL` 自动显示，无硬编码改动。 |

### 7.2 兼容 / 回归风险

- **高（回归）**：现状 4 检测器无条件全跑，引入 `config.techniques` 过滤后，若默认/空值处理不当，会导致老配置或新用户"漏跑"既有技术。护栏：**`techniques` 为空/未定义一律视为全选**（含 4 既有，不含显式关闭项）；默认 UI 4 项全选。必须有"无 techniques 字段时行为完全不变"的回归用例。
- **中（定级）**：`riskOf` 加入 stacked→Critical，会改变整体 `report.riskLevel`（原 union/error 仅 High）。需回归报告定级单测，确认仅当真的命中 stacked 才升 Critical，且不扰乱既有组合的定级。
- **中（检测稳定性）**：堆叠依赖"第二条语句产生时间延迟"，对 `timeThresholdMs` 与 `SLEEP` 秒数敏感；阈值过低易误报、过高易漏报。建议固定 SLEEP 2–5s、阈值复用 `timeThresholdMs`（默认 1500ms），并在文档注明。
- **中（WAF/编码）**：payload 含 `;`，须确保经 `httpClient` 不被截断/编码破坏；`obfuscateValue` 仅处理字母与空格，`;` 与延迟函数名安全，但需实测确认。
- **低（DBMS 差异）**：Oracle 不支持堆叠，投放无效且可能报错 → 指纹为 Oracle 时不投放 stacked；MySQL 需驱动 `multiStatements` 才生效，靶机需相应配置（见 P2-3）。
- **低（重复报告）**：SQL Server 的 `time` payload 已是 `; WAITFOR`（堆叠式），stacked 与 time 可能同时命中同一注入点 → 需去重或标注（见 Q7）。
- **低（双形态/依赖）**：Web 与 Tauri 共用前端，无新业务逻辑分支；堆叠检测复用 `Detector` 基类与 `HttpClient`，**不引入新 npm 依赖**。

---

## 8. 范围与明确排除（避免范围蔓延）

- **不做自动利用层**：堆叠仅"检测/确认可用"，**不实现**写文件（`SELECT … INTO OUTFILE` / `xp_cmdshell`）、命令执行、批量数据导出（拖库）。利用层留待后续独立需求。
- **不重写既有 4 类检测逻辑**：仅新增第 5 类 + 必要的枚举/过滤/定级衔接；union/error/boolean/time 实现保持不变。
- **不新增网络依赖包**：堆叠检测复用现有 `HttpClient` 与 `Detector` 基类。
- **不做"自适应堆叠利用 / 批量文件写入 / 命令执行编排"**。
- **不加密任何新增配置**（与既有"明文本地存储"安全基调一致）。

---

## 9. 待确认问题（需工程/架构拍板，已给默认决策）

| # | 问题 | 默认决策（建议） | 拍板方 |
|---|------|------------------|--------|
| ① | 技术选择机制是否本期一并引入？现状无 `techniques` 字段、无多选 UI、4 检测器无条件全跑；要"让用户勾选堆叠"必须先把选择机制建起来。 | **一并引入**：新增 `ScanConfig.techniques` + `ScanConfigPanel` 多选 + `ScanManager` 过滤；默认 4 类全选、堆叠默认不选，以维持向后兼容。 | 架构 |
| ② | 堆叠检测主判据用什么？ | **以"时间延迟"为主判据**（`;` 后 `SLEEP/WAITFOR/pg_sleep` 触发延迟且稳定多次）。副作用（建/删临时表、写文件）作为 **P1 可选副判据、默认关闭**（具破坏性）。 | 工程 |
| ③ | 风险等级如何定？现有 union/error=High、boolean/time=Medium，stacked 与之冲突。 | **stacked 定为 Critical**（可直接写文件/命令执行）。修改 `riskOf` 增加 stacked→Critical 分支。 | 架构 |
| ④ | 堆叠是否进入默认扫描集？默认勾选还是 opt-in？ | **默认不勾选（opt-in）**。原因：堆叠可能具破坏性副作用、MySQL 默认不支持、且会改变报告风险定级；作为增强项按需开启更稳妥。 | 产品/架构 |
| ⑤ | Oracle 不支持堆叠查询，是否投放堆叠 payload？ | **不投放，标注"技术不适用"**。指纹为 Oracle 时跳过 stacked 检测，并在 UI/报告中提示。 | 工程 |
| ⑥ | 堆叠延迟秒数与判定阈值是否复用既有参数？ | **复用 `timeThresholdMs` 作判定阈值、`SLEEP` 固定 2–5s**，不新增独立配置项，降低复杂度。 | 工程 |
| ⑦ | SQL Server 的 `time` payload 已是 `; WAITFOR`（堆叠式），stacked 与 time 会双重印证/重复报告，如何处理？ | **报告层去重或标注"互相印证"**：同一注入点若 time 与 stacked 同时命中，报告中注明两者指向同一堆叠能力，避免重复计为两个独立漏洞（或合并为一条 stacked 记录）。 | 架构 |

---

> 本增量 PRD 聚焦"F-19 变更做什么、为什么、验收与风险"，含产品目标 / 用户故事 / P0-P2 需求池 / UI 设计稿 / 待确认问题，不含架构设计与实现细节，可直接交付架构师做增量设计。现状核查发现（无技术选择机制、后端无集中枚举、SQL Server time 已是堆叠式）已在 §1.1 与 §7 如实标注。
