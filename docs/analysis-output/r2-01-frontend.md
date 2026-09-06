# 第二轮前端审查报告（r2-01）

> 范围：`src/**`（含与 server 事件契约的交叉验证）
> 方法：亲读源码 + `npm run build` 实测产物 + manualChunks 对照实验 + zh/en key 清点脚本
> 本轮不重复第一轮已修复项结论，聚焦验证落地质量与新问题。

---

## 一、已修项验证

### 1.1 ScanPage 移除 events 订阅 + 回调稳定化 + ScanWizard memo（commit 7811bb4）✓ 有残留缺陷

- [src/pages/ScanPage.tsx:42-46 通过] 页面级 `events` 订阅已彻底移除，仅订阅 store 增量聚合值 `progressTotal` / `processedPointIds`（点级事件才触发更新），SSE 高峰期 `http_request`/`sqlmap_log` 不再引发整页（含表单树）重渲染。目标达成。
- [src/components/ScanWizard.tsx:245 通过] `memo(ScanWizardInner)` 已落地。
- **[src/pages/ScanPage.tsx:137-138 中｜新发现]** `onConfigChange={(patch) => setConfig(...)}` 与 `onSqlmapConfigChange={(patch) => setSqlmapConfig(...)}` 仍是内联箭头函数，每次 ScanPage 渲染（status/report/wafSuggestion 变化均会触发）都产生新引用 → `React.memo` 浅比较必然失败，**memo 形同虚设**。注释（:98 "配合 ScanWizard 的 React.memo"）声称的收益实际只在「这两处也稳定化之后」才成立。修法：`useCallback((patch) => setConfig((c) => ({ ...c, ...patch })), [])`，setter 函数式更新本身无需依赖。
- [src/pages/ScanPage.tsx:62 低｜新发现] `Object.keys(processedPointIds).length` 每渲染 O(n)，`src/components/ProgressView.tsx:166` 同款。万级注入点扫描时进度文本区每帧线性扫全集合。建议在 store 增量维护 `processedCount: number`，或在两处 `useMemo`。

### 1.2 ProgressView 统计 filter useMemo ✓ 但口径分裂

- [src/components/ProgressView.tsx:171/175/196-198/200-212/240 通过] stageTimings、badges、vulnFound、wafDetected、pointsTested、currentPhase、recentEvents 均已 `useMemo` 且 deps 正确。
- **[src/store/scanStore.ts:126 + src/components/ProgressView.tsx:198 中｜新发现] 统计口径不一致**：进度条的 `processed` 取自增量聚合集合（不受 300 条滑窗影响），而 ProgressView 的「已测试」徽章 `pointsTested = events.filter(point_testing).length` 仍基于滑窗——长扫描（事件 >300，sqlmap 日志模式必现）中两个数字会明显背离（进度 87% 但「已测试 12 次」）。且 `point_testing` 对同一点会发两次（tamperRetry，server/src/engine/scanRunner.js:229/303），窗口内计数还会虚高。建议 tested/vulnFound 也走 store 增量聚合（vulnFound 可复用 detection_found 进入 processedPointIds 的时机计数）。

### 1.3 progressTotal / processedPointIds 增量维护（本轮重点追问）

- **增长上限**：确认 `processedPointIds` 在单次扫描会话内**单调无上限增长**（每 pointId 一个键）。每条命中事件执行 `{ ...processedPointIds, [pid]: true }` 全量浅拷贝 → 会话生命周期内累计 O(n²) 复制成本。10k 注入点量级约 50M 键复制，现代机器毫秒级抖动但 GC 压力可观；典型扫描（<1k 点）无感。**评级：低～中**。可选优化：超过阈值（如 5000）切换 `Set` + 版本号，或直接接受现状并在注释标注上界假设。
- **clearEvents 是否重置**：✓ 已正确处理。`clearEvents` 同时清空 `progressTotal` 与 `processedPointIds`（src/store/scanStore.ts:128）；`reset()` 同样清空（:161）；`useEvents` 在每个新 scanId 生效时先调 `clearEvents`（src/hooks/useEvents.ts:37）。三处闭环，无跨会话泄漏。
- **progressTotal 覆盖语义的隐藏前提**：addEvent 对 `point_discovered` 采用「覆盖」而非累加（scanStore.ts:115-117）。当前安全——后端仅在发现阶段一次性 emit 全量 points（server/src/engine/scanRunner.js:53）。但 crawlDepth（F 系功能）未来若改为分批 discover，total 将只统计最后一批，进度条封顶 <100%。建议在 store 注释显式记录该契约前提，或改为累加去重。

---

## 二、ReportPage 漏洞列表虚拟化/分片方案落地评估

现状：组件 579 行 / 构建产物 31.71 kB（gzip 9.03 kB），漏洞列表仍为全量渲染。

- [src/pages/ReportPage.tsx:451-494 中] 内置引擎 `vulns.map` 一次性渲染全部卡片；卡片是内联 JSX（非独立 memo 组件），点击任一卡片展开 `selectedVuln` → 整个列表重渲染。数百漏洞 × 每卡 4-6 个 MUI 节点时展开交互可感知卡顿。
- [src/pages/ReportPage.tsx:39-79 中] `SqlmapVulnCard` 已抽成函数组件但未 `memo`，同样随父级全量重渲染。
- [src/pages/ReportPage.tsx:90-101 通过] TabPanel 条件渲染（value===index 才挂载）意味着非当前 Tab 无成本——这是已有的天然"分片"。
- [src/pages/ReportPage.tsx:445 低] `sqlmapVulns.map key={i}` 索引 key，与 vulns 列表用 `vuln.id` 的做法不一致。

**方案评估**（package.json 未含 react-window/react-virtual）：
- **方案 A（推荐）：memo 卡片 + 增量分片**。① 抽出 `VulnCard = memo(function VulnCard({vuln, expanded, onToggle}))`，onToggle 用稳定回调 + 按 id 比较；② 首屏渲染 50 条，尾部「加载更多」每次 +100。零新依赖、约 60 行改动、保留 Card 布局与展开态。
- **方案 B：react-window**。Card 展开高度不定 → 需 VariableSizeList + 高度缓存，展开/收起要手动重算，可达性（role=button/aria-expanded）需重做。收益仅在大报告首帧，成本高于 A。
- 结论：**落地方案 A**；实测 500+ 漏洞首帧 >300ms 再升级 B。

---

## 三、i18n 硬编码中文清单复核 + 补 key 方案

zh.json 与 en.json key 完全平齐（脚本清点：403 = 403，双向零缺失）✓。但以下位置**绕过 i18n 直接输出中文**（英文用户可见中文）：

| 位置 | 内容 | 级别 |
|---|---|---|
| src/components/ProgressView.tsx:205-208,211,271 | 阶段提示「正在提取数据…/正在检测注入点（已测试 N 次）…/正在初始化扫描…/正在启动扫描…/正在准备检测…」全部硬编码 | 中 |
| src/hooks/useEvents.ts:218 | 重连超限提示「实时进度连接中断…」硬编码写入事件流并展示于时间线 | 中 |
| src/App.tsx:200,202 | 「重启引擎」「检测引擎已停止运行」 | 中 |
| src/components/ErrorBoundary.tsx:52,60 | 「页面渲染异常」「刷新页面」 | 中 |
| src/hooks/useScan.ts:85,212 | 「已有扫描正在运行…」「导出失败（HTTP …）」异常消息直出 UI | 中 |
| src/shared/constants.ts:8-17 | RISK_LABELS / TECHNIQUE_LABELS 中文映射表被组件直接消费 | 中 |
| src/components/PayloadViewer.tsx:6,11 | 「无 Payload」「Payload（只读）」 | 低 |
| src/shared/apiClient.ts:42,48 | 兜底错误「请求失败」「网络错误」 | 低 |
| src/router.tsx:42 | skip-link「跳到主内容」 | 低 |
| src/components/ScanWizard.tsx:233-238 | t() 输出间以中文标点「、，」。」硬拼接，en 语言下仍显示中文标点 | 低 |
| src/pages/ReportPage.tsx:536-537 | `toLocaleString('zh-CN')` 固定区域格式，应随 i18n.language | 低 |

补 key 方案：
1. 新增命名空间：`phase.extracting / phase.initializing / phase.detecting / phase.starting / phase.scanning`；`error.engineStopped / restartEngine / renderCrash / refreshPage / scanInProgress / exportFailed / requestFailed / networkError / noPayload / payloadReadonly / skipToContent / sseDisconnected`。
2. 非 Hook 层（apiClient / useScan / useEvents / ErrorBoundary 类组件）直接 `import i18n from '../i18n'` 后用 `i18n.t(...)`——实例同步初始化（src/i18n/index.ts:10-20）保证可用。
3. constants 的 label 映射改为返回 i18n key（`RISK_LABEL_KEY`），由展示层翻译，删除双份文案漂移风险。
4. useEvents 的提示事件把 message 拆为结构化载荷 `{ code:'sse_disconnected', retries:N }`，展示层再翻译（事件流存稳定 code 更利于日志归档）。

---

## 四、ScanEvent payload:any → 判别联合类型改造可行性方案

现状：`src/shared/types.ts:327-334` `payload: any`；消费端遍布 `as` 断言（scanStore.ts:116,121；ProgressView renderSecondary 50-77；useEvents reconcile :78 等，约 20 处）。**类型漂移已现实发生**：
- 后端 emit 了 `scan_stopped_finalized`（server/src/engine/scanRunner.js:359），前端 `EventType` 联合未声明 → 该事件在时间线里走默认样式、类型系统完全不可见；
- 前端 `EVENT_STYLE` 含 `detection_not_found`（ProgressView.tsx:31），`EventType` 与后端均无此类型——三处契约各自为政。

**改造方案（可行性：高，约 1 天含测试修复）**：
1. 以 server emit 点为准定义载荷映射（scanRunner.js:34-482 + sqlmapBridge 日志/命中行）：
```ts
interface ScanEventBase { scanId: string; ts: string; seq?: number }
// 每类一个 interface（字段起步全部可选，避免破坏旧数据/旧测试）
export type ScanEvent = ScanEventBase & (
  | { type: 'scan_started';      payload: ScanStartedPayload }
  | { type: 'point_discovered';  payload: { points: InjectionPoint[] } }
  | { type: 'point_testing';     payload: { pointId: string; technique: TechniqueType; tamperRetry?: boolean } }
  | { type: 'point_skipped';     payload: { pointId: string; reason: 'static' | 'resume-done' } }
  | { type: 'detection_found';   payload: DetectionResult & { riskLevel: RiskLevel } }
  | { type: 'http_request';      payload: { method: string; url: string; status?: number; ms?: number } }
  | { type: 'scan_phase';        payload: { phase: string; message: string } }
  | { type: 'extraction_progress'; payload: { /* tables/rows 计数 */ } }
  | { type: 'waf_detected';      payload: WafDetectedPayload }
  | { type: 'sqlmap_log';        payload: SqlmapLogEntry }
  | { type: 'sqlmap_vuln';       payload: SqlmapVulnEntry }
  | { type: 'scan_completed';    payload: ReportModel }
  | { type: 'scan_stopped';      payload?: undefined }
  | { type: 'scan_error';        payload: { message: string } }
);
```
2. 边界收窄策略：`JSON.parse` 处（useEvents.ts:128）保持 `unknown` + 一个轻量守卫 `isScanEvent(x): x is ScanEvent`（只校验 type 在集合内 + payload 非空对象即可，不必引 zod）；store `addEvent` 参数同步换型；测试构造点（scanStore.test.ts:54-56 用了 `as never`）逐一补齐必填字段或提供 `makeEvent()` 测试工厂。
3. 收益：消除 ~20 处 as 断言；switch/addEvent 分支可做 exhaustive check，新增事件类型漏改前端时编译报错（本轮发现的 `scan_stopped_finalized` 即会被捕获）；顺带把 EventType 单一事实源化。
4. 风险：后端 payload 为动态 JSON，字段可选化后仍可能运行时缺字段——判别联合解决「编译期」问题，运行期靠守卫兜底；不建议一步到位全 required。

---

## 五、mui-vendor chunk 现状实测（commit 5cfaef1 icons 拆包之后）

`npm run build` 实测（当前配置，对象形式 manualChunks）：

| chunk | raw | gzip |
|---|---|---|
| mui-vendor | **492.23 kB** | **152.38 kB** |
| mui-icons | 1.96 kB | 1.00 kB |
| react-vendor | 89.24 kB | 30.20 kB |
| i18n-vendor / apiClient / index / ScanPage / ReportPage | 49.17 / 47.18 / 48.95 / 49.86 / 31.71 kB | — |

结论：
1. **icons 拆包"生效但已是空壳"**：应用按图标具名导入（如 `@mui/icons-material/CheckCircle`），tree-shaking 后 mui-icons 仅 2KB——icons 根本不是体积问题，5cfaef1 的动机（独立缓存）成立但收益趋零。
2. [vite.config.ts:27-38 中｜新发现] **真正的重量来源是对象形式 manualChunks**：把 `'@mui/material'` 写进列表会让 Rollup 把该包**入口 barrel 整体**纳入 mui-vendor，绕过按引用 tree-shaking——应用只用子集却背了全部组件。对照实验（函数形式 manualChunks，按路径正则分桶）：mui-vendor **347.27 kB / gzip 105.83 kB（-145 kB raw，-46.5 kB gzip，-30%）**，mui-icons 11.27 kB / gzip 3.84 kB；react-vendor 因依赖再分配 89→233 kB（scheduler、@remix-run/router 等并入 react 桶，缓存语义反而更正确）。
3. 建议：manualChunks 改函数形式（保留五个桶名不变，缓存文件名稳定性不受影响）；落地后复测 LCP。若 MUI 升级 v6/v7（Granite tree-shaking 改进）可再评估。

---

## 六、useEvents SSE 回放对接后的前端健壮性（seq 游标 / 乱序 / 重复）

**seq 游标 ✓ 基本正确**
- [src/hooks/useEvents.ts:133-134 通过] `lastSeq = Math.max(lastSeq, seq)` 单调推进；重开连接带 `lastEventId`（:113）；手动重连路径与 EventSource 原生 Last-Event-ID 头语义对齐。
- [server/src/core/eventBus.js:147 通过] 服务端回放 `filter(e => e.seq > lastSeq)`，与前端游标语义匹配（严格大于，无边界重复）。
- [server/src/core/eventBus.js:39 通过] seq 为**全扫描共享的全局计数器**——游标间存在空洞属正常；前端仅作 max 比较无连续性假设，正确。但注意：若未来有人想用「本地计数 vs seq 差值」检测丢事件，会因全局计数误报。

**乱序防御：缺失 [低]**
- 回放写入在 listener 注册之后同步完成（eventBus.js:137-149 先挂 listener 再写回放），Node 单线程下实时事件不会插入回放中间，当前顺序有保证。但前端 onmessage 对 `seq <= 已见序号` 的事件照单全收（useEvents.ts:125-136 直接 addEvent）——一旦服务端将来并发写流或代理层重放，时间线即乱序。建议加三行守卫：会话内记录 lastAppliedSeq，`seq != null && seq <= lastAppliedSeq` 时丢弃（仍推进 max 游标）。

**重复事件去重：缺失，且后端存在真实双发路径 [高｜跨栈]**
- **[server/src/core/eventBus.js:118-138 高]** 正常完成时终态事件被写两次：`listener` 对**所有**事件（含 scan_completed/stopped/error）各 write 一次（:128-136），`terminalListener` 又对终态事件再 write 一次并 end（:118-127）→ **每次扫描结束前端必然收到重复终态事件**。后果：ProgressView 时间线出现两条完成条目；useEvents.ts:143-148 的 setReport/saveScanToHistory 双触发（历史库靠 scanId 去重兜底未产生脏数据，但属于巧合性安全）。修法：terminalListener 只负责 end 不再 write，或在 listener 内识别终态跳过。
- 前端无任何 (seq) 去重：上述「seq <= lastAppliedSeq 则 drop」守卫可同时兜住后端双发、重连瞬间新旧连接短暂并存、以及未来代理重放三类场景。建议作为独立小改动先行落地（不依赖后端修复）。
- [低] 重连成功后的 reconcile 有并发闸门（useEvents.ts:65-68 reconciling 标志）与会话切换守卫（:71,81,93,171），验证通过。
- [低] lastSeq 仅存内存，页面刷新后从头订阅；服务端回放缓冲上限 500 条（eventBus.js:33-36），刷新后长扫描前段不可恢复——设计取舍可接受，如需彻底解决应把报告拉取作为初始对账（进入页面时 reconcile 一次）。

---

## 七、汇总

### 高（1）
1. [server/src/core/eventBus.js:118-138] 终态事件 listener + terminalListener 双写 → 前端必收重复 scan_completed/stopped/error；前端无 seq 去重兜底，时间线重复、收尾回调双触发。（跨栈问题，前端可用 seq 去重先兜住）

### 中（6）
1. [src/pages/ScanPage.tsx:137-138] onConfigChange/onSqlmapConfigChange 内联箭头使 ScanWizard memo 失效，commit 7811bb4 的优化收益实际未兑现。
2. [src/store/scanStore.ts:126 + src/components/ProgressView.tsx:198] 进度口径分裂：processed 走增量聚合、pointsTested 走 300 条滑窗且 point_testing 双发虚高，长扫描两数背离。
3. [vite.config.ts:27-38] 对象形式 manualChunks 整包拉入 @mui/material barrel，mui-vendor 492 kB（gzip 152 kB）；函数形式实测 -30%（347 kB / gzip 106 kB）。
4. [src/pages/ReportPage.tsx:39-79,451-494] 漏洞列表全量渲染 + 卡片未 memo，展开交互全列表重渲染；建议方案 A（memo + 50/批分片）。
5. [i18n] ~12 处硬编码中文绕过 i18n（ProgressView 阶段提示、useEvents 断线提示、App/ErrorBoundary/useScan/constants 等），en 语言下中文漏出。
6. [src/shared/types.ts:333] payload:any 已造成真实契约漂移（scan_stopped_finalized 未声明、detection_not_found 幽灵类型），判别联合改造可行且必要（约 1 天）。

### 低（6）
1. [src/store/scanStore.ts:111-127] processedPointIds 会话内单调增长 + 全量浅拷贝 O(n²)；clearEvents/reset/useEvents 三处已正确重置，无跨会话泄漏；progressTotal 覆盖语义依赖「point_discovered 仅发一次」的隐含契约（crawl 分批化时会破）。
2. [src/hooks/useEvents.ts:125-136] 无乱序防御（seq<=已见序号不丢弃），建议随高项一并加守卫。
3. [src/pages/ScanPage.tsx:62 / ProgressView.tsx:166] Object.keys(...).length 每渲染 O(n)，宜增量维护计数。
4. [src/pages/ReportPage.tsx:445] sqlmapVulns 索引 key。
5. [src/pages/ReportPage.tsx:536-537] toLocaleString('zh-CN') 未随语言；ScanWizard 中文标点硬拼接（同列 i18n 低项）。
6. [src/hooks/useEvents.ts] 刷新页面后 lastSeq 丢失，>500 条回放缓冲外的早期事件不可恢复（设计取舍，可加进场对账缓解）。