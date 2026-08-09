# SQL 注入检测工具「sqli-scanner」— F-20 增量 PRD（仅变更部分 · WAF 绕过优化 / tamper 流水线暴露 + 指纹推荐）

> 作者：产品经理 许清楚（Xu）
> 版本：F-20 增量（基于已交付完整版 v1.0.0 + P2 增强 + F-19 堆叠 + 既有 tamper 后端体系）
> 语言：简体中文
> 配套架构背景：`docs/system_design.md`、`docs/prd_p2_incremental.md`（F-16 WAF 规避）、`docs/prd_f19_stacked.md`

---

## 1. 增量概述

本期主题为 **WAF 绕过优化（F-20）**：把现有薄弱的 WAF 规避（仅 `随机 UA / 请求抖动 jitter / Payload 简单混淆` 三个独立开关）升级为"可插拔的 tamper 变换流水线"，并尽可能贴近 sqlmap 的 tamper 体系能力；同时新增 WAF 指纹识别与「推荐 tamper 组合」（仅推荐、不自动套用），并在前端把 3 个开关升级为「tamper 多选 + 强度」面板。

**重要前提修正（见 §1.1 现状核查）**：编写前已逐文件核查代码，发现**后端 tamper 可插拔流水线实际上已经存在且相当完整**——`server/src/core/tamper/` 下已有 `TamperRegistry` + 链式 `applyTampers` + 统一钩子 `obfuscateWithConfig`，并内置 **62 个 tamper 插件**（已覆盖 F-20 需求池中几乎全部候选变换），且已接入 `Detector / injection / Extractor / Exploiter / 各 Detector`，`defaults.js` 也已预留 `wafEvasion.tamper` 配置与默认关闭。因此本期**真正的工程重心不是"从零造流水线"，而是"把已有能力在前端暴露 + WAF 指纹识别与推荐 + 类型/默认/报告对齐 + 测试补齐"**。本 PRD 据此调整范围。

---

## 1.1 现状核查（重要，与需求说明前提不符之处，如实标注）

编写前已阅读 `server/src/core/httpClient.js`、`server/src/core/tamper/*`、`server/src/engine/payloads.js`、`server/src/engine/Detector.js`、`server/src/config/defaults.js`、`server/src/engine/ScanManager.js`、前端 `src/shared/{types,constants}.ts`、`src/components/ScanConfigPanel.tsx`、现有单测 `server/tests/tamper.test.js` / `src/tests/scanConfig.f19.test.tsx`。发现以下与"当前仅 3 开关、薄弱"这一前提**不一致**的现状，需工程/架构确认：

1. **后端 tamper 可插拔流水线已存在（且大幅超出需求候选集）。** `server/src/core/tamper/` 包含：
   - `applyTampers.js`：`applyTampers(payload, ctx, pluginNames)` 链式执行 + `obfuscateWithConfig(value, ctx)` 统一钩子（优先级：① `tamper.enabled` → 链式；② `obfuscate`(legacy) → `obfuscatePayload`；③ 均未开 → 原样返回）。
   - `TamperRegistry.js`：注册表，`list()` 返回 `{name, description}`（**天然可作为前端多选清单数据源**），`resolve(names)` 按数组顺序解析有序插件链。
   - `plugins/`（**62 个插件**，已确认数量）：覆盖 F-20 需求池几乎全部候选变换——
     `space2comment`、`space2plus`、`randomcomments`、`randomcase`、`charencode`、`charunicodeencode`、`chardoubleencode`（≈ doubleurlencode）、`appendnullbyte`、`equaltolike`、`between`、`modsecurityversioned`、`modsecurityzeroversioned`、`percentage` 等均在列；另有 `securesphere`(Imperva)、`sp_password`(MSSQL WAF)、`bluecoat`、`versionedkeywords/morekeywords` 等直接面向 WAF 的插件。
   - 已在 `Detector.obfuscateValue → obfuscateWithConfig`、`injection.js`、`Extractor.js`、`Exploiter.js`、`OobDetector`、`SecondOrderDetector`、`TargetParser` 多处改调统一钩子（grep 确认）。
   - `defaults.js` 已含 `wafEvasion.tamper = { enabled: false, plugins: [] }`，默认关闭。
   - `server/tests/tamper.test.js` 已存在（注册全量校验 + 各插件变换 + 链式顺序用例）。
2. **`obfuscatePayload` 与任务描述不符。** `payloads.js`（L265-267）当前的实现**仅**把 `AND/OR` 用 `/*!*/` 包裹、并折叠多余空格；**并非**任务所述"大小写随机化 + `/**/` 内联注释分割 + 保护字符串字面量 `__S__/__E__`"。大小写随机化是独立插件 `randomcase`；代码中**不存在** `__S__/__E__` 标记机制。即 legacy 混淆比前提描述更"薄"，而大小写随机化已在 tamper 体系内。
3. **前端仍是 legacy 3 开关，无 tamper 面板。** `src/components/ScanConfigPanel.tsx`（L232-270）WAF 区仅渲染：`随机 User-Agent`(randomUA Switch)、`Payload 混淆`(obfuscate Switch)、`请求间随机延时`(jitterMs 数字)。**没有 tamper 多选、没有强度控件**——这正是任务要升级的"3 开关"区。
4. **前端类型/默认值与后端 `tamper` 配置不对齐。** `src/shared/types.ts` 的 `WafEvasionConfig`（L63-68）**无 `tamper` 字段**；`src/shared/constants.ts` 的 `DEFAULT_CONFIG.wafEvasion`（L46-50）**也无 `tamper`**。后果：前端不会初始化 `tamper`，且 TS 契约拒绝该字段；用户即便在配置里传 `tamper` 也缺乏类型与初始态支撑。
5. **WAF 指纹识别完全不存在。** grep `server/src` 对 `Cloudflare / ModSecurity / AWS WAF / 阿里云 / 百度云 / wafDetector / 指纹` 等**无任何检测逻辑或规则库**（仅有注释里提及 WAF 的零散字符串）。任务 P1/P2 的"识别 + 推荐"是**真正的新增能力**，后端尚无雏形。
6. **无 API 暴露 tamper 清单给前端。** grep `server/src/api` 对 `tamper / TamperRegistry / list()` **无匹配**——前端要渲染 62 个 tamper 多选，目前**没有数据来源**（要么新增轻量端点，要么前端硬编码，存在前后端漂移风险）。
7. **报告标注缺口。** `ScanManager._run`（L248-257）仅在 `report.summary.wafEvasion` 记录 `randomUA / jitterMs / obfuscate`，**未记录 `tamper`（enabled + plugins）**。若用户开启 tamper，报告不会标注，既违背"开启后报告会标注"承诺，也破坏结果可复现。
8. **F-19 技术多选范式可复用。** `ScanManager.activeDetectors(config)` 已按 `config.techniques` 过滤；`ScanConfigPanel` 已有 `Checkbox`/`FormGroup` 多选 UX（默认不全选 + 说明）。tamper 多选应**沿用同一视觉范式与"默认 opt-in=false"约定**，而非另起炉灶。

> **结论**：F-20 的"tamper 流水线核心"在后端**已交付**。本期真正待做 = ①前端 tamper 多选 + 强度面板（升级 3 开关）；②`WafEvasionConfig` / `DEFAULT_CONFIG` 对齐 `tamper`；③tamper 清单数据源（新增端点或硬编码）；④WAF 指纹识别 + 推荐组合（仅推荐）；⑤报告补齐 tamper 标注；⑥前后端测试。需求池据此编写，P0 的"流水线核心"以"复用并暴露既有体系"落地。

---

## 2. 产品目标

| # | 目标 | 说明（可衡量） |
|---|------|----------------|
| G1 | 能力可用：把已有 tamper 流水线在前端"可选择 + 可编排"地暴露给用户 | 扫描配置页提供 tamper 多选 + 强度 + 顺序控件；勾选并开启后，出站 payload 经所选 tamper 链变换；默认全部关闭。 |
| G2 | WAF 感知：识别常见 WAF 并推荐 tamper 组合（仅推荐，不自动套用） | 至少覆盖 Cloudflare / ModSecurity / AWS WAF / 阿里云 WAF / 百度云加速 5 类；命中后返回推荐 tamper 组合，需用户二次确认才应用。 |
| G3 | 结果可信：开启 tamper 后在报告中标注所用变换，保证可复现 | 报告 `summary.wafEvasion.tamper` 记录 `{enabled, plugins(有序), intensity}`；开/关状态一目了然。 |

三个目标彼此正交：G1 是用户交互与编排、G2 是 WAF 感知与建议、G3 是报告与可复现。

---

## 3. 用户故事

| # | 角色 | 期望 | 价值 |
|---|------|------|------|
| US1 | 安全测试人员 | 作为测试人员，我希望在扫描配置里勾选多个 tamper 并按顺序串联，以便针对特定 WAF 构造能绕过的 payload。 | 不必手改代码即可复用 sqlmap 式绕过能力，定向对抗目标 WAF。 |
| US2 | 安全测试人员 | 作为测试人员，当工具识别出目标前置 WAF 时，我希望看到"推荐 tamper 组合"建议，并一键应用（需我确认）。 | 降低试错成本，快速找到可用绕过组合。 |
| US3 | 安全测试人员 | 作为测试人员，我希望 tamper 默认全部关闭，只有我显式开启才生效。 | 改变请求形态会触发不同行为，默认关闭避免误伤检测稳定性与可复现性。 |
| US4 | 审计/合规人员 | 作为审计人员，我希望报告中明确记录本次扫描是否启用了 tamper 及具体组合。 | 结果可复现、可审计，知道"某次命中是在何种变换下得到的"。 |
| US5 | 安全测试人员 | 作为测试人员，我希望用"强度"一键套用一套合理预设（轻度/中度/激进），也能手动微调。 | 兼顾"开箱即用"与"精细控制"。 |

---

## 4. 变更点清单（按模块）

| 编号 | 变更描述 | 影响模块 | 验收标准（要点） | 风险等级 |
|------|----------|----------|------------------|----------|
| F-20a | 前端类型与默认对齐：新增 `WafEvasionConfig.tamper`（`{ enabled, plugins: string[], intensity }`）；`DEFAULT_CONFIG.wafEvasion` 增加同名默认（enabled=false）。 | 前端 `types.ts` / `constants.ts` | 类型含 tamper；缺省时行为等价于未开启；编译通过。 | 低 |
| F-20b | 前端 tamper 面板：在 WAF 区把 3 开关升级为「tamper 多选组 + 强度三档 + 顺序调整」，沿用 F-19 Checkbox 多选范式；默认不全选。 | 前端 `ScanConfigPanel.tsx` | 可多选/排序/设强度并写入 `config.wafEvasion.tamper`；默认态 tamper.enabled=false、plugins=[]。 | 中 |
| F-20c | tamper 清单数据源：新增 `GET /api/tampers` 返回 `tamperRegistry.list()`（name+description）；前端拉取渲染多选。 | 后端 `api/*` + 前端 `ScanConfigPanel` / `apiClient.ts` | 前端无需硬编码即可渲染全部 tamper 及中文/英文说明；新增端点不影响既有契约。 | 低 |
| F-20d | 报告标注补齐：在 `ScanManager` 的 `report.summary.wafEvasion` 增加 `tamper: { enabled, plugins, intensity }`。 | 后端 `ScanManager.js` | 开启 tamper 后报告含该字段；关闭/缺省时字段为空或省略，向后兼容。 | 低 |
| F-20e | WAF 指纹识别（P1）：内置轻量规则库，按响应头/状态码/特征串识别常见 WAF，输出候选 vendor + 置信度。 | 后端新增 `core/waf/*.js` | 对已知 WAF 靶机/响应能识别并给出 vendor；仅识别、不额外发包（复用指纹阶段响应）。 | 中 |
| F-20f | 指纹→推荐映射（P1）：按 vendor 给出推荐 tamper 组合，前端以"建议"呈现，需用户确认才应用。 | 后端 `core/waf/*` + 前端面板 | 命中 WAF 后在面板展示推荐组合与"一键应用"；应用即写入 `tamper.plugins`，但仍需用户主动确认开启。 | 中 |

---

## 5. 需求池（P0 / P1 / P2 分级）

> 优先级：P0 = 必须（本期交付）；P1 = 应当（高价值，力争本期）；P2 = 可选（后续或增强）。
> 范围边界：本期仅做"变换暴露 + 可选指纹推荐 + UI 暴露 + 报告标注"，**不做自动套用、不做绕过成功率统计**（见 §8）。后端 tamper 流水线核心已存在，P0 以"复用并暴露"落地。

### P0（必须）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P0-1 | 类型与默认对齐：前端 `WafEvasionConfig` 增加 `tamper: { enabled: boolean; plugins: string[]; intensity: 'low'\|'medium'\|'high' }`；`DEFAULT_CONFIG.wafEvasion` 增加 `tamper: { enabled: false, plugins: [], intensity: 'medium' }`。缺省（老配置/无字段）视为未开启。 | `types.ts`, `constants.ts` | 编译通过；`DEFAULT_CONFIG` 与后端 `defaults.wafEvasion.tamper` 结构一致；缺省时 `enabled=false`。 |
| P0-2 | 前端 tamper 多选面板：WAF 区从 3 开关升级为「tamper 多选组 + 强度三档控件（low/medium/high）+ 顺序调整」，沿用 F-19 `Checkbox`/`FormGroup` 范式（默认不全选 + 说明文字）。选择结果写入 `config.wafEvasion.tamper`（enabled 由"是否至少选 1 个或显式开关"决定）。 | `ScanConfigPanel.tsx` | 可多选/设强度/调顺序并写入 tamper；默认态 enabled=false、plugins=[]；UI 与检测技术多选视觉一致。 |
| P0-3 | tamper 清单数据源：新增 `GET /api/tampers` 返回 `tamperRegistry.list()`（`{name, description}` 数组）；前端拉取后渲染多选（避免硬编码漂移）。 | 后端 `api/tampers.js`（或并入现有路由）, 前端 `apiClient.ts` / `ScanConfigPanel.tsx` | 前端渲染的 tamper 列表与后端注册表完全一致；新增端点不破坏既有 `/api/scan/start` 契约。 |
| P0-4 | 默认关闭兼容护栏：确保 `tamper.enabled` 默认 false；`obfuscateWithConfig` 已保证 tamper 关且 obfuscate 关时原样返回（已具备）；补充"无 tamper 字段 / 老配置 / plugins 含未知名"时的回归用例（未知名 `resolve` 跳过并告警，已具备）。 | `defaults.js`（已正确）, `server/tests/`, `src/tests/` | 老配置（无 tamper）扫描行为与今日完全一致；未知插件名被安全跳过。 |
| P0-5 | 报告标注 tamper：在 `ScanManager._run` 的 `report.summary.wafEvasion` 增加 `tamper: { enabled, plugins, intensity }`（与 randomUA/jitterMs/obfuscate 并列）。 | `ScanManager.js` | 开启 tamper 后报告含该字段且 plugins 有序；关闭/缺省时不写或写空，向后兼容旧报告结构。 |
| P0-6 | 契约透传与校验：确认 `config.wafEvasion.tamper` 经 `/api/scan/start` 透传（后端 `Detector/obfuscateWithConfig` 已读取）；前端写入该字段；在配置校验处对 `plugins` 做"须为已知名"的基本校验（未知名告警而非报错）。 | 后端路由/校验, 前端 `ScanConfigPanel.tsx` | tamper 配置端到端生效；非法插件名不阻断扫描、仅告警。 |

### P1（应当）

| ID | 需求 | 受影响模块 | 验收标准 |
|----|------|-----------|----------|
| P1-1 | WAF 指纹识别：内置轻量规则库（响应头/状态码/特征串正则），识别 Cloudflare、ModSecurity、AWS WAF、阿里云 WAF、百度云加速等，输出候选 `vendor + 置信度`；仅复用既有响应（指纹阶段已抓响应），不额外发包。 | 后端新增 `core/waf/WafIdentifier.js`（或并入 `DBFingerprinter`） | 对带特征响应的目标返回候选 vendor；无特征时返回"未识别"；不增加额外请求量。 |
| P1-2 | 命中后推荐 tamper 组合：维护 `vendor → 推荐 plugins[]` 映射（经验库，可初版少量规则），前端以"建议"呈现，提供"一键应用"按钮（写入 `tamper.plugins`，但**仍需用户确认开启**，不自动套用）。 | 后端 `core/waf/*`, 前端面板 | 命中 WAF 后展示推荐组合与一键应用；应用后 tamper 仍为 opt-in，用户须手动开启 enabled。 |
| P1-3 | 强度预设语义：定义 `low/medium/high` 三档对应的 tamper 预设包（如 low: 随机UA+space2comment；medium: +randomcase+charencode；high: +modsecurityversioned+percentage+versionedkeywords 等），面板"应用预设"按钮一键勾选。 | 前端 `constants.ts`/面板, 后端可配套常量 | 三档含义明确、可审计；点选即按预设填充 plugins；用户可在此之上微调。 |
| P1-4 | 组合顺序 UI：多选组支持调整 tamper 串联顺序（有序数组写入 `tamper.plugins`），默认按推荐/注册顺序；提供上移/下移/删除（优先用原生控件，避免引入拖拽库，见待确认 ⑤）。 | 前端 `ScanConfigPanel.tsx` | 顺序变更实时反映到 `tamper.plugins` 数组；最终 payload 按该顺序链式变换。 |
| P1-5 | 测试补齐：①前端 `scanConfig.f19.test.tsx` 范式新增 tamper 多选/强度/默认关闭态测试；②e2e 增加"开启 tamper 后四类检测仍正确"的靶机用例；③后端补充"未知插件名安全跳过""tamper 关时原样"等回归（已有 `tamper.test.js` 可扩）。 | `src/tests/`, `server/tests/`, e2e | 前端/后端均覆盖开启态与默认态；e2e 至少 1 例确认 tamper 不破坏检测。 |

### P2（可选 / 后续增强）

| ID | 需求 | 说明 |
|----|------|------|
| P2-1 | 自动按指纹套用（需用户二次确认的总开关）：在 P1 推荐基础上，提供"确认后自动应用推荐组合"开关；本期仅推荐不套用，留待后续。 | 降低手动操作，但需强护栏防误伤。 |
| P2-2 | 绕过成功率统计 / 对比报告：对比"开/关 tamper"的命中率与差异，给出绕过效果评估。 | 高级分析，超出本期范围（见 §8）。 |
| P2-3 | 用户自定义 tamper 注册入口（UI/配置）：后端 `TamperRegistry.register` 已支持，前端暴露"粘贴/选择自定义 transform"为后续增强。 | 能力开放，但有安全风险需审批。 |
| P2-4 | 多 WAF 串联识别 + 组合推荐：一个目标前置多层 WAF 时，识别组合并给叠加推荐。 | 复杂度高，初版仅单 WAF。 |
| P2-5 | tamper 与堆叠/拖库/二阶协同回归：确认 tamper 链不破坏 `;` / 延迟函数名（P0-4 思路延续），补充针对性 e2e。 | 复用 `obfuscateValue` 统一通道，重点验证字符编码类 tamper 对堆叠 payload 的影响。 |

---

## 6. UI 设计稿（界面变化文字描述）

> 仅描述相对现有 `ScanConfigPanel` 的**变更**，位于"检测技术"多选组之后的 **WAF 规避** 区（其余配置区保持不变）。

- **WAF 规避区重构**（替换现有 3 开关）：
  - **tamper 多选组**（沿用 F-19 技术多选视觉：`FormGroup` + `Checkbox`，每项显示插件名 + 简短中文说明，说明来自 `GET /api/tampers` 的 `description`）：
    - ☐ space2comment（空格→`/**/`）
    - ☐ randomcase（关键字大小写随机）
    - ☐ charencode（URL 编码）
    - ☐ modsecurityversioned（MySQL 版本化注释包裹）
    - ……（共 62 项，按字母/分类分组，可滚动/折叠）
    - **默认全部未选**（opt-in=false），下方说明文字："tamper 会改变请求形态，可能触发目标不同行为，请按需开启；开启后报告会标注所用组合。"
  - **强度三档控件**（Radio / Segmented：`轻度 / 中度 / 激进`）：选择即按 P1-3 预设包填充上方多选（用户可再微调）；默认 `中度`。
  - **顺序调整**：已选项以有序列表/ chips 呈现，每项带"上移/下移/删除"；顺序即 `tamper.plugins` 串联顺序（默认按添加/推荐顺序）。
  - **总开关（enabled）**：面板顶部一个显式"启用 tamper 变换"Switch；**默认关**。勾选 tamper 但未开总开关时，给出提示"启用后才会对 payload 生效"。
  - **WAF 指纹建议区（P1，命中后出现）**：扫描开始/指纹阶段识别到 WAF 后，面板（或扫描页提示条）显示"检测到 Cloudflare，推荐组合：space2comment + randomcase + …"，附"一键应用"按钮（写入 plugins，但 enabled 仍须用户确认开启）。
  - **保留的 legacy 开关**：`随机 User-Agent`、`请求间随机延时 (ms)` 保留（与 tamper 正交，UA/jitter 在 httpClient 层施加）；原 `Payload 混淆`(obfuscate) 开关保留但标注"已被 tamper 体系取代，开启 tamper 后优先走 tamper"（`obfuscateWithConfig` 已保证优先级）。
- **报告页**：`VulnList` / `ReportPage` 摘要区新增"WAF 规避"一行，显示 tamper 是否启用 + 所选组合（来自 `summary.wafEvasion.tamper`）；关闭时与今日一致不显示。
- **向后兼容**：老配置/历史记录无 `tamper` 字段时，等价于 `enabled=false, plugins=[]`，扫描与报告行为与今日一致；`DEFAULT_CONFIG` 升级后初始态即为全关。

---

## 7. 对旧架构的影响与风险

### 7.1 接入点（基于现有设计）

| 变更 | 接入旧模块 | 说明 |
|------|------------|------|
| F-20a 类型/默认 | `src/shared/types.ts`（`WafEvasionConfig`）、`src/shared/constants.ts`（`DEFAULT_CONFIG`） | 纯前端扩展字段，不影响既有值；新增 `tamper` 子对象。 |
| F-20b 面板 | `src/components/ScanConfigPanel.tsx`（WAF 区替换） | 沿用 F-19 `Checkbox`/`FormGroup` 范式；新增强度/顺序/总开关，写 `config.wafEvasion.tamper`。 |
| F-20c 清单端点 | 后端新增 `GET /api/tampers`（包装 `tamperRegistry.list()`）；前端 `apiClient.ts` 拉取 | 单一事实源，避免前端硬编码 62 项漂移；新增端点不影响 `/api/scan/start` 既有契约。 |
| F-20d 报告标注 | `server/src/engine/ScanManager.js`（扩展 `summary.wafEvasion`） | 仅增字段，不改动既有 randomUA/jitterMs/obfuscate 记录；旧报告结构仍可解析。 |
| F-20e/f 指纹 | 后端新增 `core/waf/*`（识别 + 推荐映射），可挂到 `DBFingerprinter` 或扫描启动时；前端建议区 | 仅识别与建议，不自动改请求；复用指纹阶段已有响应，零额外发包（默认）。 |
| 后端流水线（已存在） | `Detector.obfuscateValue → obfuscateWithConfig → applyTampers`（`server/src/core/tamper/*`） | 本期**不改动**链式引擎；仅前端写入 `config.wafEvasion.tamper` 即可被既有通道消费。 |

### 7.2 兼容 / 回归风险

- **低（默认关闭护栏）**：`obfuscateWithConfig` 已保证 `tamper.enabled=false` 且 `obfuscate=false` 时原样返回（与现状一致）。护栏是本期稳定性的关键：老配置/无 tamper 字段必须零回归。需补"无 tamper 字段时行为不变"的回归用例（P0-4）。
- **低（契约兼容）**：新增 `GET /api/tampers` 为只读端点，不改写 `/api/scan/start`；前端写入 `tamper` 字段由后端既有 `obfuscateWithConfig` 消费，无需改 REST 结构（字段已存在于后端 schema）。
- **中（前端多选正确性）**：62 个 tamper 多选 + 顺序 + 强度，交互态多；需保证"默认不全选、enabled 默认关、plugins 顺序即串联顺序"与后端 `resolve()` 语义严格一致，否则 UI 勾选与最终 payload 不符。
- **中（检测稳定性）**：开启 tamper（尤其 `chardoubleencode`/`charunicodeencode`/`modsecurityversioned` 等）会改变 payload 形态，理论上影响布尔/时间盲注判定与时序。因此**默认关闭 + 报告标注**是必要护栏；e2e 须验证开启后检测仍正确（P1-5）。
- **低（报告结构）**：`summary.wafEvasion` 增 `tamper` 字段向后兼容；旧报告解析器忽略未知字段即可。
- **低（双形态一致性）**：Web 与 Tauri 共用前端，无新业务逻辑分支；新增端点前后端一致。
- **低（依赖）**：本期不引入新 npm 依赖（tamper 体系、registry 均已存在；顺序调整用原生控件，避免拖拽库，见待确认 ⑤）。

---

## 8. 范围与明确排除（避免范围蔓延）

- **不做自动套用**：指纹命中后**仅推荐** tamper 组合，需用户二次确认开启；不自动套用（自动套用留 P2-1）。
- **不做绕过成功率统计 / 对比报告**：不实现"开/关 tamper 命中率对比""绕过效果评分"等高级分析（留 P2-2）。
- **不重写检测算法 / Payload 库 / 四类检测逻辑**：tamper 仅在出站 payload 上做变换，不动核心检测与指纹主体。
- **不重写 62 插件体系**：本期只"暴露"既有 tamper，不新增/修改插件（除非发现某候选插件缺失，见待确认 ①）。
- **不加密新增配置**：与既有"明文本地存储"安全基调一致。
- **指纹识别默认零额外发包**：仅复用指纹阶段已有响应；不主动对目标做额外探测（除非后续明确需求）。

---

## 9. 待确认问题（需工程/架构拍板，已给默认决策）

| # | 问题 | 默认决策（建议） | 拍板方 |
|---|------|------------------|--------|
| ① | F-20 候选 tamper 是否都已在 62 插件中？若个别缺失（如 `doubleurlencode` 实为 `chardoubleencode`，命名待对齐），是否需要补插件？ | **核对后基本齐全**；`doubleurlencode` 以 `chardoubleencode` 覆盖，命名差异在 UI 说明中澄清即可；不新增插件（除非发现真正缺口）。架构确认清单。 | 工程 |
| ② | tamper 清单如何在前端获取？新增 `GET /api/tampers` 还是前端硬编码常量？ | **新增轻量端点 `GET /api/tampers`**（返回 `tamperRegistry.list()`），单一事实源，避免前后端 62 项漂移；若求快可前端常量但需与 registry 同步纪律。 | 架构 |
| ③ | "强度"（low/medium/high）语义如何定义？是预设包还是数值滑块？ | **三档预设包**（low/medium/high 各映射一组 tamper，见 P1-3 示例），含义明确、可审计、贴合 sqlmap 经验；不采用无语义的数值滑块。 | 产品/架构 |
| ④ | tamper 在哪一环注入最合理？现状是统一 `obfuscateValue → obfuscateWithConfig → applyTampers`（请求前对 payload 值统一变换）；是否沿用，还是各 Detector 内联？ | **沿用现状统一入口**（Detector/injection/Extractor 三处已改调），不改各 Detector 内联；保证 `;`、延迟函数名在变换中受控。不建议分散。 | 架构 |
| ⑤ | 组合顺序 UI 如何表达？拖拽排序 vs 上移/下移 vs 固定推荐顺序？ | **点击添加进有序列表 + 上移/下移/删除**（原生控件，零拖拽库依赖）；不引入 dnd 依赖，控制包体积与稳定性。 | 前端/产品 |
| ⑥ | WAF 指纹识别的数据来源与优先级？基于响应头/状态码/body 特征串的内置规则库，还是借 sqlmap 经验库？ | **内置轻量规则库**（Cloudflare `cf-ray`/`Server`、ModSecurity 特有头/body 串、AWS WAF 头、阿里云/百度云特征），按置信度排序；数据来自指纹阶段已有响应，默认零额外发包。 | 工程 |
| ⑦ | 指纹命中后"推荐"是否要自动写入 plugins？ | **仅推荐、不自动套用**：推荐组合以"一键应用"呈现，点击才写入 `tamper.plugins`；`enabled` 仍须用户显式开启（双重确认，防误伤）。 | 产品/架构 |
| ⑧ | 老配置/历史记录无 `tamper` 字段、前端旧 `WafEvasionConfig` 升级兼容性如何处理？ | **缺省视为 `{enabled:false, plugins:[], intensity:'medium'}`**，零回归；`DEFAULT_CONFIG` 补 tamper 默认；后端 `obfuscateWithConfig` 对缺省安全降级为原样。 | 架构 |

---

> 本增量 PRD 聚焦"F-20 变更做什么、为什么、验收与风险"，含产品目标 / 用户故事 / P0-P2 需求池 / UI 设计稿 / 待确认问题，不含架构设计与实现细节，可直接交付架构师做增量设计。现状核查（§1.1）已如实标注：后端 tamper 可插拔流水线（62 插件 + 注册表 + 链式 + 统一钩子 + 配置 + 单测）**已经存在**，F-20 工程重心实为「前端暴露 + WAF 指纹识别与推荐 + 类型/默认/报告对齐 + 测试」，而非从零造流水线；同时 `obfuscatePayload` 实际仅做 AND/OR 包裹（与前提描述不符），前端 WAF 区仍是 legacy 3 开关，`WafEvasionConfig`/`DEFAULT_CONFIG` 缺 `tamper` 字段，且尚无 WAF 指纹识别与 tamper 清单 API。
