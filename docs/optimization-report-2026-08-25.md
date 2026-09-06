# sqli-scanner 全面优化分析报告（2026-08-25）

> 分析方式：6 个专项子代理并行审查（前端 / 检测引擎 / API 安全 / 工程化交付 / 测试文档 / 数据资产层），
> 其中 4 个完成深度分析；后因子代理模型当日免费额度耗尽（429），剩余两个维度由主代理直接补齐核查。
> 所有结论均基于实际读取的代码与 `git ls-files` / `git status` 输出，基线 commit `a3ef37b`。

---

## 一、高危问题（建议立即处理）

### 1. [CRITICAL·安全] 真实 LLM API Key 提交进了 Git 仓库
- **证据**：`git ls-files` 包含 `server/.env.ai`，内容为 3 个真实 key：
  `AI_REPORT_KEY_1=sk-exca19pN9sK...`、`AI_REPORT_KEY_2=sk-28ngUkeq...`、`AI_REPORT_KEY_3=sk-yqboKHTf...`；
  根目录 `.env.ai` 同样被跟踪。引入提交：`af372ee`、`63710f8`（`git log -- server/.env.ai` 可见）。
- **影响**：任何能拉取该仓库的人都能盗用这 3 个 key 产生费用；若仓库将来开源则直接泄露。
- **修复**：
  1. **立即在服务商侧吊销/轮换这 3 个 key**（这是第一优先级，清理历史不能代替轮换）；
  2. `git rm --cached .env.ai server/.env.ai`；
  3. `.gitignore` 增加 `.env.ai`、`.env.*` 白名单式管理（保留 `.env.example`）；
  4. 如仓库已推送远端，用 `git filter-repo` 清理历史后强推。

### 2. [HIGH·DevOps] `.dockerignore` 未排除 `.env.ai`，密钥会被打进 Docker 镜像
- **证据**：`.dockerignore` 仅排除 `.env`、`.env.local`、`.env.*.local`；而 Dockerfile 构建阶段 `COPY . .`
  且运行时阶段 `COPY --from=builder /app/server ./server` —— `server/.env.ai` 会进入运行镜像层。
- **修复**：`.dockerignore` 增加 `.env*` 与 `!.env.example`（或精确排除 `**/.env.ai`）。

### 3. [HIGH·仓库卫生] 日志产物文件被 Git 跟踪
- **证据**：`preview-server.err`、`server.err` 出现在 `git ls-files`；`.gitignore` 只有 `*.log` 与
  `server/*.err`，未覆盖根目录 `*.err`；工作区还散落 `server.log`、`preview-server.log`、`sqli-labs.err/.log`、
  `nul` 等未跟踪杂物（`git status` 当前就有一条 `sqli-labs.err` untracked）。
- **修复**：`git rm --cached preview-server.err server.err`；`.gitignore` 增加 `*.err`；
  物理删除工作区残留日志与 `nul` 文件。

---

## 二、中优先级问题

### 4. [测试/CI] 覆盖率门槛实际未在 CI 强制执行
- **证据**：`vitest.config.ts` 设有 thresholds(60/55/45/60)，但 CI 的 test-frontend job 只跑
  `npx vitest run`（无 `--coverage`），门槛形同虚设；`npm run test:coverage` 仅本地可用。
  服务端侧 `test:coverage` 只圈定 3 个文件（httpClient/Detector/ScanManager），Extractor/Exploiter/
  各 detector/tamper 链均无覆盖率约束。
- **修复**：CI 增加 coverage 步骤（`npx vitest run --coverage` 即可触发阈值失败）；
  server 覆盖率逐步扩大 `--test-coverage-include` 范围。

### 5. [文档同步] README 测试数字过期 + 空报告文件
- **证据**：README 写「前端 92 个 / 服务端 733 个」，实测约 **108 个前端用例 / 约 1010 个服务端用例**
  （110 个 test 文件）；`docs/optimization-report-2026-08-20.md` 是**空文件**；
  `docs/archive/api-audit.md` 日期写着「2026-01-xx」占位符。
- **修复**：更新 README 数字（或改为「以 CI 最新结果为准」）；删除空报告文件；补占位日期。

### 6. [引擎] ReportAI 缓存 Map 无淘汰机制
- **证据**：`services/ReportAI.js` 的 `reportCache`（Map）只在命中时检查 TTL，从不删除过期键；
  `keyHealth` 同理只增不减。长驻进程（Docker 常驻）下缓慢内存增长。
- **修复**：写入时顺手清理过期键，或改用简单 LRU（上限如 100 条）。

### 7. [API] 错误处理可观测性不足
- **证据**：`index.js` 兜底错误处理仅 `logger.error(err.message)`，不打堆栈，线上排障困难；
  CORS 拒绝通过 `cb(new Error(...))` 抛出，最终表现为 500 而非 403 语义。
- **修复**：兜底处理打印 `err.stack`（生产可脱敏）；CORS 拒绝返回 403 JSON。

### 8. [前端] 大组件可继续拆分
- **证据**：`pages/ReportPage.tsx` 25.6KB、`components/ProgressView.tsx` 20.3KB 为最大两块；
  `AppThemeProvider` 每次 mode 切换整体重建 `createTheme`（可 `useMemo`，影响小）。
  其余基础良好：页面级 lazy 拆包、zustand selector 订阅、SSE 手动退避重连、报告竞态守卫、
  localStorage 落盘前凭据脱敏均已到位。

### 9. [数据层] 注释与实现漂移
- **证据**：`core/waf/wafRules.js` 头注释仍写「覆盖 7 类常见 WAF」，实际规则已达 **62 条**
  （与 README 一致）；`payloadRegistry.js` 71 条声明与 README 相符 ✓；203 个 tamper 插件
  启动期全量注册（当前规模可接受，暂无需按需加载）。
- **修复**：更新 wafRules 头注释；为 tamper/payload 数量建立单一事实源（如启动时断言计数，
  防止 README/注释再次漂移）。

---

## 三、低优先级 / 打磨项

10. **docker-compose.yml**：顶层 `version: '3.8'` 已被 Compose v2 废弃（会产生 warning），可直接删除。
11. **package.json scripts 跨平台**：`waf-lab-v2` 使用 Unix 风格前缀 `WAF_PROFILE=all_in_one node ...`，
    Windows PowerShell 无法直接运行；可用 `cross-env` 或拆成 node 内部读参。
12. **e2e 结果产物入库噪音**：`e2e/*/results/*.md|json` 被跟踪，每次跑批都产生 diff（当前 git status
    就挂着一条 modified）。建议统一 gitignore + 改为 CI artifact，仅在里程碑手动刷新快照。
13. **CI tamper-waf-matrix**：`continue-on-error: true` 使该 job 永远不会红，仅作参考信号；
    且同时声明 `needs` 与 `schedule`，语义上建议拆成独立 workflow 更清晰。
14. **vitest 单线程串行**（fileParallelism:false + singleThread）是为规避本机偶发挂起的权宜之计，
    牺牲了速度；CI 环境可尝试恢复并行（用环境变量区分本地/CI 配置）。
15. **eslint 范围**：flat config 已覆盖 `server/**/*.js`（好），但 `src-tauri/**` 整体忽略——
    Rust 侧代码无 lint 门禁，可考虑接入 `clippy`（若有 CI 构建 Tauri 的计划）。

---

## 四、值得肯定的现状（无需改动）

- **SSRF 防护成体系**：元数据/链路本地段无条件拒绝 + `SSRF_STRICT` 分层 + DNS 钉死防 rebinding +
  逐跳重定向校验 + 响应体上限。
- **利用能力红线清晰**：`EXPLOIT_ENABLED` 默认关 + `authorized:true` 审计字段 + exploit 端点独立限速桶 +
  头名黑名单双向过滤（scanRoutes 与 httpClient 保持一致）。
- **认证**：SCAN_API_TOKEN SHA-256 归一后恒时比较；SSE 经 query token 兜底并有精确路径白名单。
- **前端工程质量高**：竞态守卫、原子 startSession、事件流截断 300 条、历史记录脱敏持久化。
- **CI 结构完整**：lint/typecheck/前后端测试/win+mac 矩阵/recall-lab 18 场景/Docker 构建冒烟。
- **声明式 payloadRegistry** 对标 sqlmap `<test>` 元素（id/dbms/technique/level/risk/clause/boundary/where），
  设计规范，71 条与文档一致。

## 五、建议处理顺序

1. 今天：吊销并轮换 3 个 AI key → `git rm --cached` 密钥与 err 文件 → 补 `.gitignore`/`.dockerignore`。
2. 本周：CI 接入覆盖率强制 → README 数字修正 → 删空报告文件。
3. 迭代中：ReportAI 缓存淘汰 → 错误堆栈日志 → ReportPage/ProgressView 拆分 → 杂项打磨。

---

> 本报告为第一轮汇总。六个维度的深度审查报告（含 [文件:行号] 级定位与修复建议）已落盘于
> `docs/analysis-output/01-frontend.md ~ 06-data-layer.md`，下文摘录其关键增量发现。

## 六、子代理深度审查补充发现（第二轮，全部经实码核实）

### 6.1 检测引擎正确性（详见 02-engine.md）

| # | 位置 | 问题 |
|---|---|---|
| E-H1 | StackedDetector.js:79-86 | 堆叠判定用固定 thresholdMs 无基线补偿 → 正常慢站任意点误报 Critical（并强制特权定级） |
| E-H2 | InlineQueryDetector.js:44-49 | 缺反射门控（UnionDetector 有 `_gateInjection` 此处没有）→ 回显页面必然误报 |
| E-H3 | Extractor.js:421 / UnionDetector.js:108 | `_colGuessCache` key 只用 point.id 不含 host → 不同目标同路径同名参数时列数缓存串数据 |
| E-H4 | ScanManager.js + httpClient | stop 取消传播只有协作式检查点：stop 后点内循环与在途请求不中断（分钟级残留流量） |
| E-M | Exploiter.js:442/59-73 等 | PG UDF 用 MySQL 类型词（RETURNS STRING）必语法错误；MSSQL 分页 SQL 缺 ORDER BY 恒失败——同一方言逻辑多份拷贝漂移的实证 |

### 6.2 后端 API 安全（详见 03-api-security.md）

- **A-H1 [高危]** `oobReceiver.js:176` 对 URL 路径 token 直接 `decodeURIComponent` 无 try/catch：
  一个无认证请求 `GET /oob/%E0%A4%A` 即抛 URIError → uncaughtException → **整个引擎进程崩溃**（DoS）。
  修复：token 白名单 `/^[A-Za-z0-9_-]{1,64}$/` + 全 handler 包 try/catch。
- **A-M1** DNS OOB 通道不校验 qname 是否属于配置的 dnsDomain → 本机任意进程可伪造命中（误报 Critical）
  或预灌 token 掩盖真实判定；UDP 源地址可伪造绕过 per-ip 令牌桶。
- **A-M2** AI 报告链路存在「目标站响应 → evidence 全文入 prompt → LLM 输出回灌下一级 → 操作者报告」的
  二次注入链；evidence 未截断、host 明文外送第三方 LLM、analyst JSON 输出未做校验。

### 6.3 前端正确性（详见 01-frontend.md）

- **F-H1** SSE 重连窗口内事件永久丢失：后端 eventBus 无历史缓冲、不支持 Last-Event-ID 回放 →
  断线期间进度百分比回退/时间线空洞/徽章偏小。需后端环形缓冲 + 重连回放。
- **F-H2** events 截断 300 条滑动窗口把 `point_discovered` 滑出后 total 归零 → 长扫描进度条退化；
  聚合值应改为 store 增量维护而非每次从事件数组重算。
- **F-H3** ScanPage 页面级订阅 events 数组 → 每个 SSE 事件整树重渲染（含向导表单树）。
- 另有 MUI vendor chunk 494KB 肥包、8 处 i18n 硬编码中文、全链路无运行时校验等 14 中 / 13 低项。

### 6.4 工程化交付（详见 04-devops.md）

- **D-H1 [高]** ci.yml 存在非法 job 级键 `schedule:`/`workflow_dispatch:` —— 这两个键只能出现在
  workflow 顶层（on:），当前写法有整个 workflow 解析失败的风险，需立即核实 Actions 实际运行状态。
- Docker runtime 层幸运地不含密钥（multi-stage），但 builder 各层随 buildx/registry 缓存持久化可还原；
  Tauri updater/signing 配置缺失；husky hooks 未 install 时门禁旁路。

### 6.5 测试与数据资产（详见 05-quality-docs.md / 06-data-layer.md)

- ScanManager stop/cancel 服务级生命周期完全无测试；ReportAI/tamperRoutes/healthRoutes 无路由测试；
  203 个 tamper 插件仅 5~6 个被链路测试触及。抽查确认无「mock 掏空」型测试，质量整体良好。
- **gzip 插件语义错误**：产出 gzip 容器格式却包装成 MySQL `UNCOMPRESS()`（期望 zlib 格式）→ 真实环境无法解压。
- payloadRegistry（71 条）唯一生产消费者是 TimeBlindDetector 且默认开关关闭 ≈ 半休眠数据，
  且模板与 PAYLOADS 手工双抄无同步断言。
- wafRecommend 62 条推荐中约 50 条是完全相同的通用组合，与 203 个 tamper 插件能力严重不成比例。

## 七、修订后的处理顺序

1. **今天**：吊销轮换 3 个 AI key → `git rm --cached` 密钥/err 文件 → 补 `.gitignore`(加 `.env*`) 与 `.dockerignore`
   → 核实 ci.yml 的 `schedule:`/`workflow_dispatch:` 非法键是否已导致 workflow 失效。
2. **本周（正确性热点）**：oobReceiver decodeURIComponent 崩溃修复（几行代码）→ StackedDetector/InlineQueryDetector
   误报防护 → `_colGuessCache` key 掺入 host → CI 接入 coverage 强制。
3. **迭代中**：SSE 回放缓冲（前后端联动）→ stop 取消传播强化 → 方言 SQL 构造器收敛单一实现 →
   gzip 插件修正与 registry 双轨收敛 → 前端渲染面收敛（events 下沉 + memo 一轮）。
4. **持续打磨**：README 数字同步、i18n 补齐、wafRecommend 差异化、大组件拆分、203 插件参数化快照测试。
