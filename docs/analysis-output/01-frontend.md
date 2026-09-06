# sqli-scanner 前端深度审查报告（01-frontend）

> 审查日期：2026-08-25 · 分支 master @ a3ef37b · 审查人：前端架构/性能审查（ox-alpha）
>
> 已确认基线：`typecheck` / `lint` / `build` 全部通过；24 个测试文件约 108 用例通过；页面级 React.lazy 拆包已完成（router.tsx:14-18）。
>
> 本次在基线上补齐六项深度审查：① 组件级重渲染风险逐个排查（15 组件 + 5 页面）；② useEvents SSE 边界与 reconcile 竞态；③ events 截断 300 条策略的长期扫描影响；④ i18n zh/en key 完整性与硬编码漏翻抽查；⑤ vite manualChunks 与实际产物体积（已实际运行 `npm run build` 验证）；⑥ shared/types.ts 与后端响应结构的对齐缺口。
>
> 条目格式：`[文件:行号 严重级别]`。严重级别：高（正确性/明显性能劣化）、中（可感知性能损失/维护风险）、低（代码质量/一致性）。

---

## 一、重渲染风险逐项排查（src/pages 5 页 + src/components 15 组件）

### 1.1 页面级

- [src/pages/ScanPage.tsx:58 高] ScanPage 通过 `useScanStore((s) => s.events)` 直接订阅 events 数组。每个 SSE 事件到达都会使 **整个 ScanPage**（含 ScanWizard、TargetForm、ScanConfigPanel、SqlmapOptions、两个 Dialog）整树重渲染。useEvents.ts 头注释（P1-4）声称“避免 ScanPage 随每个 SSE 事件整树重渲染”，但该优化只覆盖了 action 订阅，事件数据订阅仍在本页。扫描高峰期 `http_request` / `sqlmap_log` 事件可达每秒数条，表单输入会与之叠加造成卡顿。
- [src/pages/ScanPage.tsx:74 中] `computeProgress(events)` 在渲染体内直接调用且无 useMemo（ProgressView.tsx:179 对同一函数做了 useMemo，此处是重复实现 + 未缓存），每次 SSE 事件全量遍历最多 300 条事件两遍（ScanPage 与 ProgressView 各一遍）。
- [src/pages/ScanPage.tsx:140-150 中] 传给 ScanWizard 的 11 个回调全部为内联箭头函数，每次渲染重建引用；配合上条导致 ScanWizard 子树永远无法靠浅比较跳过（ScanWizard 本身也未 React.memo）。
- [src/pages/ReportPage.tsx:452-490 中] 内置引擎漏洞列表一次性渲染全部 `report.vulns` 卡片（无分页/虚拟化）。大报告（数百漏洞 × 每卡 4-6 个 MUI Chip/Typography）时点击任意卡片展开 `selectedVuln` 会触发整个列表重渲染。建议列表卡片抽为 React.memo 子组件并限制首屏数量（如先渲染 50 条 + “加载更多”）。
- [src/pages/ReportPage.tsx:128 低] 加载报告的 useEffect 依赖含 `t`：切换语言会使 t 引用变化 → 重新触发 getReport。虽然 useScan.getReport 内有 store 缓存短路（useScan.ts:172），实际不发请求，但 effect 重跑仍会造成一次多余的 loading 抖动路径；建议依赖只留 `[id, getReport]`，错误文案兜底改用 ref 或 i18n.t 即时取用。
- [src/pages/HomePage.tsx:69-83 低] 统计值（totalVulns/highRiskScans/targetCount）每次渲染对 history 全量 reduce/filter/map，未 memo。history 上限 100 条，代价可控，属低优先级。
- [src/pages/HistoryPage.tsx:104-184 低] 100 张历史卡片全量渲染、行内 handler 每次 render 重建；无虚拟化但量级受 HISTORY_LIMIT=100 约束，可接受。
- [src/pages/ExploitPage.tsx:33-35 低] capabilities 拉取一次、无订阅 store，重渲染面小；无明显问题。

### 1.2 组件级

- [src/components/ProgressView.tsx:209-211 中] `vulnFound/wafDetected/pointsTested` 三个 `events.filter(...)` 在渲染体中直接执行且未 useMemo（同文件的 computeProgress/computeBadges/stageTimings/recentEvents 都做了 memo，唯独这三个漏掉），每条 SSE 事件多三次全量遍历。
- [src/components/ProgressView.tsx:426-448 中] 事件时间线 `<ListItem key={i}>` 以数组下标为 key 且列表是倒序（最新在前）：每来一条新事件，全部 50 行的下标整体位移，React 需要重建全部 ListItem 内容而不是增量更新；且 50 行 × MUI ListItemText 无虚拟化。建议以 `e.ts+type+序号` 组合 key 并考虑 react-window 类方案（当前依赖里没有，可用简单分页替代）。
- [src/components/ProgressView.tsx:191-206 低] reqRate 定时刷新用 eslint-disable 注释豁免 exhaustive-deps（rateTick 只作信号）。逻辑正确但属脆弱写法，若后续有人在 memo 内再读其它 state 易踩坑；建议改为 `useState<Date>` 心跳或 useRef 计数。
- [src/App.tsx:87-191 中] AppThemeProvider 在函数体中直接 `createTheme(...)`：mode/systemDark/engineDown 任一 state 变化都完整重建 theme（含 components 覆盖对象）。已知基线结论成立，深化补充：**不止 createTheme 可 useMemo**——第 194 行 ThemeModeContext.Provider 的 value 是字面量对象 `{ mode, effectiveMode, setMode }`，每次 provider 重渲染都是新引用，TopBar（useThemeMode 消费者）会被连带重渲染（例如 Tauri 下 engineDown 翻转时）。theme 与 context value 都应 useMemo。
- [src/App.tsx:198-204 低] Tauri Snackbar 的 Alert 文案「重启引擎」「检测引擎已停止运行」硬编码中文（见 §四 i18n 汇总）。

---

## 二、useEvents SSE 处理边界（重连丢失窗口 / reconcile 竞态）

对照后端 server/src/core/eventBus.js 实现逐条核对后的结论：

- [src/hooks/useEvents.ts:59-97 + server/src/core/eventBus.js:45-127 高] **重连期间事件永久丢失窗口**。后端 toSSE 是纯“订阅未来事件”模式：不缓存历史事件、不支持 Last-Event-ID 回放（eventBus.js 只有 em.on('event', listener)，无 backlog）。前端 onerror 后按 1s/2s/4s/8s/8s 退避重连（useEvents.ts:196），断线到重连成功之间的所有事件（http_request/point_testing/detection_found/sqlmap_log…）**不可恢复地丢失**。onopen 里的 reconcile 只补「终态」（报告拉取），中间事件缺失的直接后果是：computeProgress 的 processed 集合缺项 → 进度百分比回退/停滞；ProgressView 时间线出现空洞；徽章计数偏小。这是当前架构下最大的正确性缺口，建议后端为每个 scanId 保留环形缓冲（如最近 N 条）并在 SSE 握手时按 Last-Event-ID 或 fromTs 回放。
- [src/hooks/useEvents.ts:180-195 中] **重试耗尽/命名空间回收后的误判**：连续失败 5 次后置 status=error 并追加 scan_error 事件。但若此时扫描实际已完成、只是后端在 RECORD_TTL_MS 后 dispose 了命名空间（sqlmapBridge.js:358-361 dispose），EventSource 连接一个不存在的命名空间会收到后端推来的 `scan_error('扫描不存在或已结束')`（eventBus.js:71-83），前端 onmessage 将 status 置为 'error'（useEvents.ts:167-169）——**已完成的扫描被显示为错误态**。reconcile 无法拯救这条路径，因为它只在“非首次 open 成功”时跑，而这里连接是成功建立的（收到的是业务错误事件而非网络错误）。建议前端对 message 为「扫描不存在或已结束」的 scan_error 先尝试拉一次报告再定状态。
- [src/hooks/useEvents.ts:62-97 中] **reconcile 并发无互斥**。reconcile 在每次非首次 onopen 都会触发；若网络抖动造成快速连断连（1s 退避内两次成功 open），会有两个 reconcile 同时 in-flight。await 返回后的 `cur.scanId !== scanId` 守卫（65/75/87 行）是到位的，不会跨会话污染，但可能对同一 scanId 双写 setReport/saveScanToHistory/setStatus——history 有 scanId 去重（scanStore.ts:119），实害有限，属竞态卫生问题。可加 `let reconciling = false` 闸门。
- [src/hooks/useEvents.ts:103-110 低] retryCount 归零逻辑（onopen 里 retryCount=0）与 firstOpen 标志配合正确：首个连接从未成功时不会误触发对账，重连成功后计数归零允许后续再次退避。确认无缺陷，记录结论。
- [src/hooks/useEvents.ts:112-171 低] onmessage 对终态事件 `es?.close()` 同步执行，能抢在后端 terminalListener res.end() 引发的前端 onerror 之前关闭连接，避免了“终态后又触发一次重连”的经典竞态——此路径实现正确。
- [src/hooks/useEvents.ts:45-51 低] token 经 URL query 透传给 SSE（EventSource 不能带 header）：token 会进入浏览器历史/代理日志。本地单机工具威胁模型下可接受，但若 HOST 放开（server/index.js 支持 0.0.0.0）风险升级，建议注释中标注该前提。

---

## 三、store/events 截断 300 条策略对长时间扫描的影响

`scanStore.addEvent`（src/store/scanStore.ts:102）采用 `[...st.events, e].slice(-300)` 滑动窗口。对长扫描（事件总数 > 300，sqlmap 日志模式尤其容易：每行输出一条 sqlmap_log）产生以下**正确性**影响：

- [src/store/scanStore.ts:102 + src/components/ProgressView.tsx:84-100 高] **进度总分母丢失**。computeProgress 的 `total` 取自最后一条 point_discovered 事件的 payload.points.length。该事件通常出现在扫描早期；一旦其后累积超过 300 条后续事件（长爬取 + 大日志量场景），point_discovered 被滑出窗口 → total 归 0 → pct 变 null → 进度条从 determinate 退回 indeterminate，「已处理 x/y」消失。同理 ScanPage.tsx:31-44 的重复实现受同一影响。
- [src/store/scanStore.ts:102 + src/components/ProgressView.tsx:109-134 中] **阶段耗时统计失真**。computeStageTimings 用「窗口内首条 point_testing → 末条 detection_found」计算检测耗时、用 events[0].ts → events[last].ts 计算总耗时：截断发生后这些值只反映最近 300 条的时间跨度，而非真实扫描阶段时长，「总耗时」会突然变小。
- [src/store/scanStore.ts:102 + src/components/ProgressView.tsx:197-206 中] **请求速率虚高**。reqRate = events.length / (now - events[0].ts)：窗口滑动后 events[0].ts 不再是扫描开始时间，分母被压缩到窗口跨度，速率显示为“窗口内速率”且随每次滑动跳变。
- [src/components/ProgressView.tsx:143-152 中] **徽章计数语义漂移**。computeBadges 的 countOf 是窗口内计数：运行越久，“发现点/已测试/命中”徽章与真实累计值的偏差越大，用户看到数字回退。
- [src/pages/HomePage.tsx:71 低] 对比项：history 侧的漏洞统计来自完整报告快照不受影响——即进度页与报告页对同一次扫描可能给出不一致的计数。

修复建议（按成本递增）：① 把 total/processed 等聚合值改为 store 内增量维护（addEvent 时同步更新 counters 字段，窗口只服务时间线展示）；② 或将 point_discovered/终态类关键事件标记为不可滑出（单独保留数组）；③ ProgressView 各 useMemo 已就位，只要数据源正确即可全部自愈。

---

## 四、i18n zh/en key 完整性抽查

**key 层面**：脚本比对 `src/i18n/zh.json` 与 `en.json` 的全量扁平化 key——两侧各 **403 个 key，零缺失、零多余**，结构完全对齐；fallbackLng='zh'（i18n/index.ts:16）下不存在回退黑洞。**结论：key 完整性通过。**

**但存在硬编码中文/中文标点漏翻**（用户切到 EN 后仍显示中文）：

- [src/App.tsx:200-202 中] Snackbar：「重启引擎」「检测引擎已停止运行」。
- [src/router.tsx:42 中] 无障碍跳转链接「跳到主内容」。
- [src/components/ProgressView.tsx:218-224 中] currentPhase 兜底文案 5 处：「正在提取数据…」「正在检测注入点（已测试 N 次）…」「正在初始化扫描…」「正在启动扫描…」「正在扫描…」——这是扫描页最显眼的实时状态文本。
- [src/hooks/useEvents.ts:185-192 中] 重连耗尽追加的 scan_error 事件消息「实时进度连接中断（连续重试 N 次失败）…」（会渲染进时间线与日志导出）。
- [src/components/PayloadViewer.tsx:6,11 低] 「无 Payload」「Payload（只读）」。
- [src/components/ErrorBoundary.tsx:52,60 低] 「页面渲染异常」「刷新页面」（降级 UI，触发时无法依赖 hook，可用 i18n.t 直接调用）。
- [src/pages/ScanPage.tsx:85 低] startScan 抛出的业务错误「已有扫描正在运行，请先停止当前扫描」（经 Alert 展示给用户）。
- [src/shared/apiClient.ts:42,48 低] 「请求失败」「网络错误」（错误提示兜底文案）；[src/hooks/useScan.ts:212]「导出失败（HTTP xxx）」。
- [src/components/ScanWizard.tsx:232-236 低] WAF 建议 Alert 在 t() 输出之间拼接中文标点 `{'，'}{'（'}{'）。'}`：EN 语言下句子呈英文单词 + 中文标点混排。
- [src/pages/ReportPage.tsx:536-537 / src/pages/HomePage.tsx:55 / src/pages/HistoryPage.tsx:30 低] `toLocaleString('zh-CN')` 三处硬编码 locale，EN 用户看到 dd/mm hh:mm 中文习惯格式；应按 i18n.language 选择 locale。

建议：以上统一补入 zh/en.json（约新增 15 个 key），并加一条 ESLint 规则或 CI 脚本（如 `eslint-plugin-i18next` 或自写正则扫描 JSX 文本节点中的 CJK 字符）防止回归。

---

## 五、vite manualChunks 与实际产物体积（实测 `npm run build`）

实测产物（vite 7.3.6，esbuild minify，2026-08-25）：

| chunk | 体积 | gzip | 说明 |
|---|---|---|---|
| mui-vendor | **494.16 kB** | **153.46 kB** | @mui/material + icons-material + emotion 全量合并 |
| react-vendor | 89.24 kB | 30.20 kB | react/react-dom/react-router-dom |
| i18n-vendor | 49.17 kB | 16.33 kB | i18next + react-i18next（含 zh/en 资源？否，资源在入口） |
| index (主包) | 48.91 kB | 19.17 kB | TopBar/router/i18n 资源/壳 |
| apiClient | 47.18 kB | 18.23 kB | axios 所在共享块 |
| ScanPage | 49.84 kB | 14.14 kB | 含 ProgressView/ScanWizard 等页面树 |
| ReportPage | 31.68 kB | 9.02 kB | |
| HomePage / ExploitPage / HistoryPage | 7.37 / 5.23 / 4.56 kB | ~2-3 kB | 懒加载生效 |
| CSS | 12.33 kB | 3.45 kB | |

结论与条目：

- [vite.config.ts:22-30 中] 页面级 lazy 拆分已生效（四个页面独立 chunk、首屏不含业务页面代码）。剩余大头是 **mui-vendor 494KB，恰好压在 Vite 500kB 警告线之下所以 build 无警告——这是“沉默的肥 chunk”**。首屏关键路径 = index + react-vendor + mui-vendor + i18n-vendor ≈ **681KB / 207KB gzip**。建议：① 把 @mui/icons-material 单拆 `icons-vendor`（图标按需 import 已做，但与 material 合并后无法单独缓存）；② 或设置 `chunkSizeWarningLimit` 显式暴露体积变化；③ 中期可评估 MUI baidu/macro 按需或迁移 v6 的 granular imports。
- [vite.config.ts:26-29 低] manualChunks 未含 axios：axios(47KB) 落在按需的 apiClient 共享块里，首屏不加载，行为正确；若希望预缓存可显式加入 vendor，但当前状态反而更优，保持即可。
- [src/index.css:1-8 中] 构建期实际出现 PostCSS 警告：`@import must precede all other statements` —— Google Fonts 的 @import 写在 `@tailwind` 指令之后（index.css 第 5 行）。该 @import 可能被浏览器忽略或乱序，导致 Inter/JetBrains Mono 字体不生效或闪烁。修复：把字体 @import 移到文件最顶部，或改到 index.html `<link rel=preload/preconnect>`（还能省一次渲染阻塞请求）。
- [vite.config.ts:36-38 低] `sourcemap:false` + esbuild minify 对桌面发布合理；无 build.reportCompressedSize 开销问题。无行动项。

---

## 六、类型安全：shared/types.ts 与后端响应结构对齐缺口

逐端点比对前端类型与 server 实现（scanRoutes.js / sqlmapBridge.js / models.js / eventBus.js）：

- [src/shared/types.ts:331 高] `ScanEvent.payload: any` 是全链路类型安全的最大豁免口：EventType 注释（93-105 行）里描述的 payload 形状（{phase,message}/{method,url,status,ms}/{pointId,technique}…）没有落到类型上，下游全部靠 as 断言（ProgressView.tsx:52,60,69,73,89-96；ScanPage.tsx:36,39；useEvents.ts:72 等 10+ 处）。建议改为判别联合：`type ScanEvent = { type:'http_request'; payload: HttpRequestPayload } | ...`，断言即可删除，事件消费处拼写错误能在编译期暴露。
- [src/hooks/useScan.ts:66 中] wrapSqlmapReport 返回值用 `as ReportModel` 强转：构造的对象 target.config 用 `{...DEFAULT_CONFIG}` 填充属合法，但 `as` 绕过了字段核对（如 sqlmap.status 为任意 string 而非受限枚举）。风险点在 SqlmapReportData.status: string（types.ts:321）与后端 r.state 实际取值 'running'|'completed'|'stopped'|'error'|'killed'（sqlmapBridge.js:331-348）之间无编译期约束；建议收窄为字面量联合类型。
- [src/shared/types.ts:320-324 中] SqlmapReportData 缺少后端实际返回的 `engine: 'sqlmap'` 字段（sqlmapBridge.getReport 返回 `{engine,status,logs,vulns}`，sqlmapBridge.js:381）。前端以 Partial<SqlmapReportData> 接收时该字段被静默丢弃——当前逻辑恰好不需要它，但契约文档（types.ts 头注“镜像后端 schema”）已失真；一旦未来依赖会踩坑。
- [src/shared/types.ts:289-303 低] builtin 报告：models.js createReport 返回 {scanId,target,startedAt,finishedAt,dbms,points,vulns,data,riskLevel,summary} 与 ReportModel 必选字段完全对齐（engine/sqlmap 为可选）✓；summary.wafEvasion/wafDetected 与 ReportGenerator 输出一致 ✓。此对齐良好，记录为通过项。
- [src/shared/types.ts:129-136 中] HistoryRecord.riskLevel: RiskLevel 必填，但 scanStore.saveScanToHistory 写入的是 report.riskLevel（恒有值）✓；不过 loadHistory 直接 `parsed as HistoryRecord[]`（scanStore.ts:17）对 localStorage 旧结构/损坏数据零校验——HomePage.tsx:70-76 已经在用 `h.report?.vulns?.length ?? 0` 防御性访问，说明运行时确实出现过缺字段记录。建议 loadHistory 加最小 shape 校验（schemaVersion 存在 + scanId string）。
- [src/shared/apiClient.ts:55-58 中] `apiClient.get<T>` 返回 `res.data.data as T`：后端错误时返回 `{code:非0,data:null,message}` 由拦截器抛错 ✓，但 **code===0 而 data 结构不符** 时无任何校验直接 as T。配合上一条 ScanEvent.payload:any，整条「SSE → store → 渲染」链路没有任何一层做运行时验证（zod/valibot 均未引入）。至少应对报告拉取（getReport 的 ReportModel）做关键字段存在性检查。
- [src/pages/ExploitPage.tsx:43 中] exploit base 对象 method 硬编码 'GET' 且 bodyParams/cookieParams/headerParams 恒空对象——与 types.ts ExploitTarget 类型兼容但语义上限制了 POST 型利用；属功能缺口而非类型错误，提请产品确认。

---

## 七、汇总（按严重级别）

### 高（3 项）—— 正确性 / 明显性能劣化，建议本迭代处理

| # | 条目 | 一句话 |
|---|---|---|
| H1 | useEvents.ts:59-97 + eventBus.js:45-127 | SSE 重连窗口内事件永久丢失（后端无回放），进度/时间线/徽章失真；需后端环形缓冲 + Last-Event-ID 回放 |
| H2 | scanStore.ts:102 + ProgressView.tsx:84-100 | 300 条滑动窗口把 point_discovered 滑出后 total 归零，长扫描进度条退化；聚合值应改为 store 增量维护 |
| H3 | ScanPage.tsx:58 | 页面级订阅 events 数组，每个 SSE 事件整树重渲染（含向导表单树）；应将 events 消费下沉至 ProgressView |

### 中（14 项）—— 可感知性能损失 / 契约与健壮性风险

M1 ReportPage.tsx:452-490 漏洞列表无虚拟化/分片；M2 ScanPage.tsx:140-150 全内联回调 + 子组件未 memo；
M3 ProgressView.tsx:209-211 三处 filter 未 memo；M4 ProgressView.tsx:426-448 时间线 index key + 无虚拟化；
M5 TargetForm.tsx:72 每渲染 JSON.parse 未 memo；M6 WafTamperPanel.tsx:65 useEffect 依赖 [t] 切语言重拉接口；
M7 App.tsx:87-191 createTheme + context value 未 useMemo；M8 BlindTraceTimeline.tsx:74-160 采样列表无上限；
M9 useEvents.ts:180-195 命名空间回收后已完成扫描被误标 error；M10 useEvents.ts:62-97 reconcile 并发无互斥；
M11 vite.config.ts:22-30 mui-vendor 494KB 沉默肥 chunk，首屏 ~681KB/207KB gzip；M12 src/index.css:5 字体 @import 位置违规（构建有 PostCSS 警告）；
M13 types.ts:331 ScanEvent.payload:any 全链路无运行时校验 + apiClient as T 直转；M14 useScan.ts:66 / types.ts:321 sqlmap status 无字面量约束 & SqlmapReportData 缺 engine 字段。

### 低（13 项）—— 代码质量 / 一致性

L1 ReportPage.tsx:128 effect 依赖 t 切语言触发冗余加载路径；L2 HomePage.tsx:69-83 统计未 memo；
L3 HistoryPage.tsx:104-184 100 卡无虚拟化（量级受控）；L4 ExploitPage.tsx:33-35 预检重复请求类问题同 ScanWizard.tsx:65-72；
L5 ScanConfigPanel marks/handler 每渲染重建；L6 VulnDetail.tsx:76 粗粒度 store 订阅；L7 ReportExport models 数组重建；
L8 i18n 硬编码中文 8 处（App/router/ProgressView/useEvents/PayloadViewer/ErrorBoundary/ScanPage/apiClient+useScan）+ ScanWizard 中文标点混排 + 3 处 toLocaleString('zh-CN')（详见 §四）；
L9 useEvents.ts:45-51 token 走 query 的日志暴露前提注释；L10 ProgressView.tsx:206 eslint-disable 心跳写法；
L11 scanStore.ts:17 loadHistory 零 shape 校验；L12 builtin 报告契约对齐 ✓（通过项记录）；L13 ExploitPage.tsx:43 利用请求 method 硬编码 GET（功能确认项）。

### 建议处理顺序

1. **H2 + M3/M4**（纯前端小改动，直接消除长扫描进度失真与时间线抖动）；
2. **H3 + M2 + M5**（ScanPage 渲染面收敛：events 下沉 + useCallback/memo 一轮）；
3. **H1 + M9**（需后端配合的 SSE 回放；前端先做「扫描不存在」误判兜底）;
4. **M11/M12**（拆 icons chunk + 修字体 @import，半小时内可完成）；
5. **L8**（i18n 补 key + CJK lint 防回归）、**M13**（ScanEvent 判别联合改造，可分 PR 渐进）。





