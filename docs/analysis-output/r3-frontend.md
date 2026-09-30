# 前端安全与质量深度审计报告（`src/` + `src-tauri/`）

- 审计对象：`D:\projects\sqli-scanner` 前端（React + TS + Vite + MUI v6 + zustand + Tauri v2），约 17k 行
- 审计方式：**只读**，未修改任何源码；证据来自 `search_files` / `read_file`
- 证据等级：每条结论标注 文件:行号 或命令输出；无行级证据者标注「未证实线索」
- 定性口径：「已确认缺陷」/「设计取舍（附理由）」/「未检到」
- 审计日期：2026-09-29

---

## ① 结论摘要

### 缺陷与风险表（按严重度排序）

| 严重度 | 标题 | 位置 | 影响 | 修复方向 |
|---|---|---|---|---|
| 中 | 令牌解析逻辑重复且两处不同源 | `src/shared/apiClient.ts:35-55` 对比 `src/hooks/useEvents.ts:60-64` | SSE 通道（`useEvents`）只读 env + `localStorage`，**不读运行时注入令牌**；Tauri 形态下两条通道凭据来源不一致，表现为事件流鉴权失败/静默降级到构建期 env 值 | 抽出唯一 `resolveApiToken()`，`apiClient` / `useEvents` / `useScan` 共用；删除内联副本 |
| 中 | 安全清洗模块零调用点，且实现为纯正则、不解析 DOM | `src/shared/htmlSanitize.ts:2-8`、`src/tests/htmlSanitize.test.ts:3-4` | 当前无实害（全项目无危险 HTML 汇聚点，见 2.1）；真实风险是"有闸未接线 + 测试全绿"造成的虚假安全感：任何后续把报告 HTML 经 `dangerouslySetInnerHTML` 挂进 DOM 的改动，会绕开唯一保护 | 改接 DOMPurify 等 parser 型清洗；或明确禁止 HTML 注入并在 lint 层封禁危险 API |
| 中 | Tauri capability 面过宽 | `src-tauri/capabilities/default.json`（`permissions: ["core:default","shell:allow-spawn","dialog:default","fs:default"]`，window `main`） | 前端若被注入或依赖链被污染，可直接 spawn 子进程 + 使用 fs 默认 scope，突破"扫描器自身只读"边界 | `shell:allow-spawn` 绑定具体 sidecar 命令与参数白名单；`fs:default` 收窄到仅导出目录所需 scope |
| 低-中 | CSP 缺显式加固指令 | `src-tauri/tauri.conf.json:22-24` | 缺 `base-uri 'self'`（该指令**不回落** `default-src`，可被 `<base>` 劫持相对 URL）、`object-src 'none'`、`frame-ancestors 'none'` | 追加 `base-uri 'self'; object-src 'none'; frame-ancestors 'none'` |
| 低 | API 令牌落盘于 `localStorage['scanApiToken']` | `src/shared/apiClient.ts:35-55` | 同源脚本/本机进程可读；桌面形态下持久化到磁盘，非进程内存隔离 | 优先仅内存态 + 会话期有效；确需持久化则走 Tauri keyring/加密存储 |
| 低 | 401 重取令牌用 `window.prompt` 明文输入 | `src/shared/apiClient.ts:85-106`（含 test-mode 守卫） | 令牌经弹窗明文输入与回显，存在被误存/误贴/误记录风险；**不构成注入面** | 改为设置页 `type=password` 表单，禁止回显与日志 |
| 信息 | 测试断言存在自我证明成分 | `src/tests/useScan.export.test.tsx:58`；`src/tests/htmlSanitize.test.ts`（整体） | 断言 mock 被调用 / 断言零调用点模块的行为契约，均不能证明生产路径安全 | 见 2.5：删除冗余断言，为真实汇聚点补端到端断言 |

### 通过项速览

1. `src/` 生产代码中**零**危险 HTML 汇聚点（`dangerouslySetInnerHTML` / `innerHTML` / `document.write` / `srcDoc` / `eval` / `new Function` / `insertAdjacentHTML` / `outerHTML` 均未命中，仅注释提及）。
2. 令牌**只走请求头 `x-api-token`，不进 URL query**。
3. 历史记录持久化前做凭据剥离（记录级确认，见 ④.4）。
4. 引擎侧 `ReportGenerator.generateHtml` 对所有插值做实体转义（`src/shared/htmlSanitize.ts:3-4` 记录，服务端测试 `reportGenerator.escape.test.js` 护栏）。
5. CSV 公式注入设有专项测试（`src/tests/csvFormulaParity.test.ts`）。

---

## ② 逐条详述

### 2.1 XSS 汇聚点（检查项 1）——「未检到」

**全局搜索**（范围 `src/`）：

```
pattern: dangerouslySetInnerHTML|innerHTML|document\.write|srcDoc|eval\(|new Function|outerHTML|insertAdjacentHTML
```

命中结果全部为**注释或测试说明**，无生产渲染路径：

- `src/shared/htmlSanitize.ts:2-8`：文件头注释自述本模块是"前端消费侧的第二道闸"，并要求"任何将来把报告 HTML（report.html / AI 报告片段等）经 `dangerouslySetInnerHTML` 挂进 DOM 的地方，都必须先过一遍本函数"。
- `src/tests/htmlSanitize.test.ts:3-4`：注释明确写"当前前端全项目没有一处使用 `dangerouslySetInnerHTML`（已 grep 确认，仅本文件注释里提及）"。
- `src/tests/qa_theme.test.tsx:56`：提到 `head.innerHTML`，属主题测试的实现说明（MUI v6 emotion 在 jsdom 下 `style` 标签内容为空，改用 `getComputedStyle` 断言），非数据渲染汇聚点。

**结论**：当前不存在"目标站点返回内容（响应体 / 报错信息 / 提取数据 / WAF 拦截页片段）进入 HTML 汇聚点"的攻击链。该项判定为「未检到」，非「通过」——通过需要以真实渲染路径为前提，此处是路径不存在。

**`htmlSanitize.ts` 自身能力评估**（检查项 1 第二问）：

- 策略见 `src/shared/htmlSanitize.ts:8`：块级用正则、属性级在标签内部逐 token 处理，**不解析 DOM**。
- 对 `<img onerror>`、`<svg/onload>`、`javascript:`、`data:text/html`、属性内引号逃逸的**具体绕过样例未取得行级证据**（见 ④.2）。
- 仅给形态判断：正则 + 非 DOM 解析的清洗实现，对 HTML5 宽松解析特性（斜杠分隔属性如 `<img/src=x onerror=…>`、引号相邻属性、未闭合标签）通常不完备。该判断为**未证实线索**，不作为缺陷定级依据。真实定级依据是「零调用点 + 测试绿灯」（见 2.5）。
- 调用点覆盖评估：因调用点数为 **0**，"覆盖不全"这一缺陷形态不成立；PayloadViewer / VulnDetail / ScanResult / ProgressView / ReportPage / BlindTraceTimeline **均不经过清洗函数，也无渲染目标数据到 HTML 的必要**（依据全局 sink 搜索为空）。

### 2.2 凭据 / 令牌处理（检查项 2）

**令牌解析与落盘**：`src/shared/apiClient.ts:35-55`
- 解析优先级：环境变量 `VITE_SCAN_API_TOKEN` → 运行时注入令牌（Tauri sidecar 一次性令牌）→ `localStorage['scanApiToken']`；并执行持久化写入。

**传输路径**：`src/shared/apiClient.ts:65-73`
- 请求拦截器统一注入 `x-api-token` 请求头。令牌**不出现在 URL query**。

**401 交互流程**：`src/shared/apiClient.ts:85-106`
- 使用 `window.prompt` 重新索要令牌；存在 test 模式守卫。风险为明文输入/回显，属低危可用性问题。

**唯一裸 `fetch`**：`src/hooks/useScan.ts:265-275`
- 令牌置于请求头，query 仅携带 `format` 等非敏感参数。核对通过。

**已确认缺陷：令牌解析双实现不同源**
- `src/hooks/useEvents.ts:60-64`：内联重写了一份令牌解析，仅读环境变量 + `localStorage`，**未接入运行时注入令牌**。
- 与 `apiClient.ts:35-55` 的三级优先级不一致。同一应用内 SSE 事件通道与常规 API 通道的凭据来源不同，Tauri 形态下会产生行为分歧（事件流鉴权失败或静默使用构建期 env 值）。

**日志泄漏**：本次采集未发现令牌被 `console.*` 输出或写入导出文件的证据（`apiClient.ts` 内 `console.` 无令牌相关命中）。标注为「未检到（本范围内）」。

**持久化敏感字段**（`useServerHistory` / zustand）：
- 历史记录写入 `localStorage['sqli_scan_history_v1']`，条数上限 `HISTORY_LIMIT = 100`；持久化前做凭据剥离（记录级确认，行号见 ④.4）。
- `localStorage` 键**全量枚举未完成**，见 ④.5。

### 2.3 CSV / 导出注入（检查项 3）——部分确认

- 存在专项测试：`src/tests/csvFormulaParity.test.ts`（公式转义一致性）、`src/tests/dumpExport.behavior.test.ts`（导出行为契约）。表明导出路径已按公式注入设护栏。
- 已知相关事实：CSV 输出带 `\uFEFF` BOM。BOM 会改变 Excel 对首列的解析行为，可削弱部分公式触发场景，但**不构成转义替代**，不能据此认定安全。
- **未完成**：`src/shared/dumpExport.ts`、`src/components/DbTree.tsx`、`src/components/ReportExport.tsx` 中"`=` / `+` / `-` / `@` / TAB / CR 前缀是否全部转义"以及"导出 HTML / SARIF 是否对目标数据做转义"的**实现级证据未取得**（见 ④.3）。该项**不下缺陷结论**，也不判通过。

### 2.4 Tauri 侧（检查项 4）

**CSP**：`src-tauri/tauri.conf.json:22-24`

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self' http://127.0.0.1:*
```

- `script-src 'self'`：未放行 `unsafe-inline` / `unsafe-eval`，主防护到位。
- `connect-src` 限定 loopback，匹配"与本地引擎通信"的架构，合理。
- 缺口：无 `base-uri`（该指令不回落到 `default-src`）、无 `object-src 'none'`、无 `frame-ancestors 'none'`；`img-src` 放行 `data:`（data: 不能执行脚本，风险可接受）。

**capabilities / 权限**：`src-tauri/capabilities/default.json`

```
permissions: ["core:default", "shell:allow-spawn", "dialog:default", "fs:default"]  // window: main
```

- `shell:allow-spawn` 未与具体 sidecar 命令/参数白名单绑定；`fs:default` 为默认（较宽）scope。二者叠加使前端具备"启动任意子进程 + 默认范围文件访问"的能力面，**超出扫描器业务所需**。判定为已确认的加固缺陷（中）。

**sidecar 启动与令牌传递**：

- 外部二进制声明：`src-tauri/tauri.conf.json:36-38` `bundle.externalBin: ["binaries/sqli-engine"]`。
- 端口选择：`src-tauri/src/lib.rs:31-39` —— 优先尝试 `127.0.0.1:4567`，失败则 `TcpListener::bind("127.0.0.1:0")` 由系统分配临时端口。
- 令牌下发：Rust 读取子进程 stdout 中的 `ENGINE_TOKEN=` 一次性令牌，再下发给前端（作为 `runtimeToken`）。
- **未证实线索**：sidecar 启动参数的拼接/转义实现细节与令牌传递代码的精确行号未逐行核对（见 ④.6）。基于"参数数组直传、不经 shell 字符串拼接"的实现形态判断命令注入风险为低，但**未取得行级证据**，不作出"无注入风险"的断言。

### 2.5 前端测试盲区（检查项 5）

**盲区 A（最严重，已确认）：被测模块与生产路径无连接**

- `src/tests/htmlSanitize.test.ts` 整体测试的是**生产环境零调用点**的模块，依据同文件 `:3-4` 自述（"当前前端全项目没有一处使用 `dangerouslySetInnerHTML`"）。
- 后果：测试全绿仅证明"一个未被使用的函数"的行为契约，**不能证明应用 XSS 防护有效**。这是"自我证明"的最强形态——断言对象与真实风险面之间没有边。

**盲区 B（已确认，冗余断言）：断言 mock 被调用**

- `src/tests/useScan.export.test.tsx:58`：`expect(vi.mocked(getApiToken)).toHaveBeenCalled();`
- 同一测试 `:57` 已对请求头做真实断言（更强）。`:58` 断言的是"mock 被调用过"，属自我证明式冗余。**不判缺陷**（因 `:57` 已构成有效护栏），但其存在会掩盖"实现被替换"类回归。

**盲区 C（分层测试取向，可接受但不构成安全证据）**

- `src/tests/tauriBridge.test.ts` / `src/tests/tauriBridge.tauri.test.ts`：通过构造 `__TAURI_INTERNALS__` 桩验证 bridge 分支。
- `src/tests/apiClient.runtime.test.ts:83-121`、`src/tests/apiClient.errors.test.ts:84-100`、`src/tests/apiClient.test.ts:53-59`、`src/tests/useEvents.test.tsx:87`：断言令牌注入 / 401 分支在 mock 层的表现。
- 这些测试证明"分支被走到"，**不证明**真实引擎的鉴权语义，也不覆盖 2.2 中的双实现不同源缺陷（无测试比较两条通道的解析结果）。

**组合副作用**：2.1 的"零汇聚点"与 2.5 的"零接线测试"叠加，使仓库处于"有闸未接线 + 全绿"状态。任何后续把报告 HTML 接入 DOM 的改动，都会在无真实防护、无有效回归的前提下上线。

---

## ③ 通过项与设计取舍

### 通过项

1. **无危险 HTML 汇聚点**：`dangerouslySetInnerHTML` / `innerHTML` / `document.write` / `srcDoc` / `eval` / `new Function` / `outerHTML` / `insertAdjacentHTML` 在 `src/` 生产代码中零使用（命中仅存在于注释与测试说明）。
2. **令牌不进 URL**：`src/hooks/useScan.ts:265-275` 令牌走请求头，query 仅含 `format` 等非敏感参数；`apiClient.ts:65-73` 拦截器统一注入 `x-api-token`。
3. **历史持久化前剥离凭据**：`useServerHistory` 写入 `sqli_scan_history_v1` 前剥离凭据（记录级确认）。
4. **引擎侧报告转义**：`src/shared/htmlSanitize.ts:3-4` 记录 `ReportGenerator.generateHtml` 对所有插值做实体转义，并由服务端测试 `reportGenerator.escape.test.js` 护栏。
5. **CSP 主防护到位**：`tauri.conf.json:22-24` 的 `script-src 'self'` 未放行 `unsafe-inline` / `unsafe-eval`；`connect-src` 限定 loopback。
6. **导出公式注入有专项测试**：`src/tests/csvFormulaParity.test.ts`。

### 设计取舍（附理由）

| 取舍项 | 位置 | 理由 | 评价 |
|---|---|---|---|
| `style-src 'self' 'unsafe-inline'` | `tauri.conf.json:22-24` | MUI v6 emotion 运行时注入样式所必需，移除会破坏主题 | 可接受 |
| `img-src 'self' data:` | `tauri.conf.json:22-24` | 支持内联图标/占位图；data: 不执行脚本 | 可接受 |
| `htmlSanitize` 用正则而非引入 DOMPurify | `src/shared/htmlSanitize.ts:8` | 避免为"预埋防御"增加 DOM 依赖与包体 | **偏弱**：在零调用点前提下无实害，但作为安全闸不可靠；应二选一（接 parser 或明确禁用） |
| 端口优先固定 `4567` 再回落临时端口 | `src-tauri/src/lib.rs:31-39` | 便于本地调试与文档化端口 | 可接受：固定端口可被同机进程预占，由 stdout 一次性令牌缓解 |
| 令牌持久化到 `localStorage` | `apiClient.ts:35-55` | 便于刷新后不重复索要令牌 | 可接受但有更好方案（见 ①） |
| 401 用 `window.prompt` 索要令牌 | `apiClient.ts:85-106` | 实现最简，无需新增设置页 | 可用性问题，非安全边界问题 |
| SSE 通道内联解析令牌 | `useEvents.ts:60-64` | 避免 `useEvents` 依赖 `apiClient` 模块初始化 | **不成立**：应解耦为共享工具函数，现实现导致行为分歧（见 2.2） |

---

## ④ 未覆盖与不确定项

1. **`<img onerror>` / `<svg/onload>` / `javascript:` / `data:text/html` / 属性引号逃逸的绕过样例未取得行级证据**：`htmlSanitize.ts` 仅确认了策略形态（`:8`），未逐条复现绕过。相关判断为**未证实线索**。
2. **检查项 3 未完成实现级确认**：`src/shared/dumpExport.ts`、`src/components/DbTree.tsx`、`src/components/ReportExport.tsx` 的公式转义与 HTML/SARIF 转义实现行号未保留。仅确认"存在专项测试"。该项既未判通过也未判缺陷。
3. **`useServerHistory` 凭据剥离逻辑行号未保留**：P1-U8 为记录级确认，非行级证据。
4. **`localStorage` 键全量枚举未完成**：已确认 `sqli_scan_history_v1`、`scanApiToken` 两个键，无法排除其他持久化敏感字段（cookie / auth / proxy 凭据）。
5. **`src-tauri/src/lib.rs` sidecar 参数拼接与令牌传递段落未逐行核对**（仅确认 `:31-39` 端口逻辑）。命令注入风险**未证实**，不作断言。
6. **未逐一读取的组件**：`src/components/PayloadViewer.tsx`、`src/components/VulnDetail.tsx`、`src/components/ScanResult.tsx`、`src/components/ProgressView.tsx`、`src/pages/ReportPage.tsx`、`src/components/BlindTraceTimeline.tsx`。因子组 sink 全局搜索为空，风险推导成立，但**非逐文件确认**。特别地，`ReportPage` 是否通过 markdown 渲染库输出 AI 报告片段（可能引入间接 HTML 路径）**未确认**——这是最值得优先复核的一点。
7. **`src/tests/` 其余安全相关测试断言未全部展开**：已展开 `htmlSanitize.test.ts`、`useScan.export.test.tsx`、`apiClient.*.test.ts`、`tauriBridge*.test.ts`、`useEvents.test.tsx` 的关键行；`dumpExport.behavior.test.ts`、`csvFormulaParity.test.ts`、`dbTree.export.test.tsx`、`vulnDetail.poc.test.tsx` 的具体断言强度未评估。
8. **无网络访问**（`external_side_effect: false`、`network: false`）：未核对任何 npm 依赖的已知漏洞（如 axios / MUI / react-router-dom 的 CVE）。依赖层面的供应链风险**完全未覆盖**。

### 优先修复顺序建议

1. 修复 2.2 的**令牌解析双实现不同源**（真实功能缺陷，影响 Tauri 形态鉴权）。
2. 收窄 `src-tauri/capabilities/default.json` 的 `shell:allow-spawn` 与 `fs:default`（真实攻击面）。
3. 补齐 CSP 的 `base-uri` / `object-src` / `frame-ancestors`（低成本高收益）。
4. 对 `htmlSanitize` 做**二选一决策**：接线并换 parser 型实现，或删除模块并在 lint 层封禁 `dangerouslySetInnerHTML`；同时清理"零调用点模块的全绿测试"带来的误导。
5. 复核 `ReportPage` 是否引入间接 HTML 渲染路径（④.6）。
