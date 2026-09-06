# sqli-scanner 对标 sqlmap 全面优化 —— 执行总结

> 执行时间：2026-08-14　｜　方式：4 个并行子代理 + 主代理收尾　｜　基线：440 引擎测试全绿 → **486 全绿** + 前端 63 例全绿

## 一、执行概览

| 子代理 | 维度 | 落地内容 | 新增测试 |
|---|---|---|---|
| A | 检测召回 | DB 指纹报错分库+时间向量、响应锚点/分块相似度、WAF 自动 tamper 重跑（节流）、URI 路径注入点 | 21 |
| B | 网络性能 | 显式 HTTP Agent + keep-alive、盲注值缓存（predictOutput）、提取点间并行、时间盲注 sleep 标定 | 12 |
| C | 架构安全 | 日志 redact 脱敏、报告 token 护栏、createApp/start + 优雅关闭、遗留物清理 | 13 |
| D | 体验文档 | VulnDetail 证据展示、注入点 `*` 精确指定、API/用户文档重写 | 前端 63 例 |

## 二、对标 sqlmap 的关键能力补齐

| sqlmap 能力 | 本次落地 | 说明 |
|---|---|---|
| `--fingerprint` | 报错签名按 dbms 拆分 + 时间向量定库 | dbms 未知按高频顺序命中即停，不再死回退 MySQL |
| `--string` / `--not-string` | `matchString` / `notString` 锚点 + 分块相似度 | 动态内容块排除，降误报 |
| `--tamper` 自动组合 | `wafEvasion.autoRetry` | 高置信 WAF + 未命中点自动套推荐链重跑一轮（节流） |
| `--predict-output` | `predictOutput` 盲注值缓存 | version()/库名/用户等常见值跨点复用 |
| keep-alive 长连接 | 显式 `http.Agent`（`disableKeepAlive` 开关） | 连接复用，Node 版本无关 |
| `-p` 注入点指定 | 参数值尾部 `*` 标记（URL/Body/Cookie/Header） | 前端解析 + 后端 TargetParser 消费 |
| `--flush-session` / 会话管理 | `sessionDefault` 落盘 + resume | 复扫近乎 0 请求 |
| 报告脱敏/访问控制 | `redact()` + `SCAN_API_TOKEN` 护栏 | URL 凭据/认证头/Cookie 打码，报告端点 401 |
| 优雅关闭 | `createApp()` / `start()` + SIGINT/SIGTERM | 等在途扫描收尾后退出 |

## 三、测试结果

- 引擎：**486 tests / 486 pass / 0 fail**（`node --test --test-concurrency=1`）
- 前端：**15 文件 63 例全绿**，`tsc --noEmit` 通过
- 既有 440 个测试零回归

## 四、遗留事项

1. `nul`（根目录）：Windows 保留设备名，普通删除返回 ACCESS_DENIED，Git Bash 显示的 358 字节是 MSYS 层误读（`os.stat` size=0）。无代码引用、无实际占位，建议用户用专用工具（如 7-Zip/Everything）手动处理。
2. `ReportGenerator.build`：src 无调用，但被 4 处测试当 fixture 使用，删除需同步改测试，判定为"测试辅助函数"保留。
3. 优化方案全量清单见 `00-optimization-plan.md`（Phase 1~3 共 58 项），本次覆盖 Phase 2 剩余 + Phase 3 大部分；Phase 3 仍有少量锦上添花项（如 14 个缺失 tamper、会话续跑 --resume 交互）可按需继续。

---

## 五、二轮增强（2026-08-14，派 3 子代理并行）

| 子代理 | 方向 | 落地 | 新增测试 |
|---|---|---|---|
| A | 二阶注入 OOB 触发 | `oobTrigger` 从预留开关落地：MySQL `LOAD_FILE` / MSSQL `xp_dirtree` / Oracle `UTL_HTTP` / PG `COPY PROGRAM` 带外回调，触发页无回显也能判定 | 14 |
| B | 非 SQL 检测深化 | MongoDB 6 操作符矩阵（$gt→$where→$regex→$in/$nin→$exists→$type 命中即停）、SSTI 8 引擎（Jinja2/FreeMarker/Velocity/ERB/Thymeleaf）、GraphQL 批处理/别名、内容差异+二次确认降误报 | 8 |
| C | 盲注响应匹配多指标 | `matchText`/`matchCode`/`matchRegexp`/`matchTitle` + `autoDynamicBlock`（动态块自动排除），对标 sqlmap `--text-only`/`--code`/`--regexp`/`--titles` | 19 |

- 最终回归：**533 tests / 533 pass / 0 fail**（较一轮 486 净增 47，零回归）
- 三个能力均为 opt-in 增强，默认关闭，不影响既有判定路径与默认行为

---

## 六、三轮增强（2026-08-16，3 子代理 + 主代理收尾）

| 执行方 | 方向 | 落地 | 新增测试 |
|---|---|---|---|
| 子代理 A | 检测深度 | payload 466→**839**（主库扩容 702 + 新增 `CLAUSE_PAYLOADS` 137 条）；ORDER BY/GROUP BY/HAVING/LIMIT 子句位置模板（level≥2 门控，level=1 请求零变化）；布尔判定 Content-Length 短路；顺带去重存量模板 4 条 | 16 |
| 子代理 B | 性能效率 | skip-static 参数预筛选（对标 --skip-static，opt-in，同值去重+哨兵探测）；布尔提取字符集收窄（数字 8→5 请求/字符，等值验证自愈）；Agent maxSockets 推导对齐；sanitizeStart 白名单补漏（matchString/notString、oob.dns*） | 29 |
| 子代理 C | 文档与前端 | docs/faq.md（11 节含错误码表/SSRF 防护专节）、docs/deploy.md（环境变量全集/安全基线）；user-guide/api.md 增量同步；DbTree 单表 CSV/JSON 导出；VulnList DBMS 标识（G14） | 前端 9 |
| 主代理 | 收尾+靶场 | REST 白名单补齐 matchText/matchCode/matchRegexp/trueRegexp/falseRegexp/matchTitle；时间盲注通道数字字符集收窄（纯数字探测 32→18，修复收窄区间下界值误判为 0 的二分约定 bug）；**e2e/recall-lab 检测召回靶场**（微型注入 SQL 求值器 + 7 场景回归 runner，修复靶场 ORDER BY 黑名单误伤基线的 bug） | 8 + e2e 7 场景 |

### 检测召回基线（e2e/recall-lab，`npm run recall-e2e`）

| 场景 | 上下文 | 检出 | 请求数 |
|---|---|---|---|
| /num | 数值型 | union+error+boolean | 44 |
| /str | 单引号字符串 | error+boolean | 30 |
| /paren | 括号包裹 | error+boolean | 35 |
| /orderby | ORDER BY 位置（level=2） | boolean（子句 payload） | 41 |
| /bool | 仅布尔差异 | boolean | 31 |
| /time | 仅时间 | time | 19 |
| /stacked | 堆叠 | stacked | 14 |

- 最终回归：**server 701/701**（0 fail）+ **前端 92/92**（tsc 零错误）+ **recall-e2e 7/7 场景全绿**
- 全程未 git commit，改动留在工作区

### 遗留观察项（后续可选）

1. ~~`oob.dnsOob` 开关全链路无消费者~~ → **已修复**：OOB DNS payload 已生成，接收端已闭环
2. ~~`TimeBlindDetector._robustDetect` 采样数读 `defaults.timeBlindSamples` 而非 `ctx.config`~~ → **已修复**：采样数改为读 `ctx.config.timeBlindSamples`（L103，clamp [1,10]）
3. extractTime 小写字母区间无净收益未做；HTTP/2 未支持；DBMS 18 种 vs sqlmap 40+（边缘库仍是最小适配）

---

## 追加：四轮审计修复记录（83 commit）

### 第一轮（安全审计）
- P0 API key 硬编码 → 环境变量读取
- P0 SSRF DNS 解析 bug → records.map(r => r.address)
- P0 resume 稳定 key → SHA256(location+param+actionUrl)
- P0 AI 报告脱敏 → URL 脱敏 + 不发敏感字段
- P1 SSE 全局上限 → SSE_GLOBAL_MAX=100
- P1 bodyParams 校验 → clampParams()
- P1 Exploiter 拼 boundary → ${prefix}${boundary}

### 第二轮（前端审计）
- P1 TopBar aria-label 语义 → 英文正确描述
- P1 ExploitPage 响应式 → flexWrap
- P2 3 个未使用导出 → 清理
- P2 6 处 any 类型 → 具体类型

### 第三轮（后端审计）
- P2 directConnector timer 泄漏 → clearTimeout
- P2 excludeSysdbs 不一致 → 统一 defaults 读取
- P2 SYS_QUERIES 列名转义 → escCols() 按方言
- P2 Extractor._send 静默 → logger.debug
- P2 resolveDbms 语义统一 → regex 匹配

### 第四轮（外部审计复核）
- P0-1 stop 护栏 → requireReport
- P0-2 TokenBucket clamp → 上限 10000
- P0-3 DNS 钉死 → buildPinnedLookup + 重定向跳 + net.isIP
- P0-4 重定向清 body → data: GET ? undefined : opts.data
- P0-5 CLI 超时 → while(true) + deadline>0
- P1-1 WAF baseline → sharedBaseline
- P1-2 批量全局限速 → perScanRate = ceil(rate/concurrency)
- P1-3 CLI 补齐 15 参数 → 字段名对齐引擎消费
- P1-5 CI matrix 去重 → ubuntu 去除
- P2 头注释清理 / getReport structuredClone / coverage 标志 / ScanManager 拆分（1397→672 行）

### 最终状态
- **server 1010/1010 + 前端 108/108 = 1118 测试全绿**
- **recall-lab 18 场景全 PASS（含 SQLite+PG+MySQL 真实 DBMS）**
- **tsc 0 / eslint 0/0 / npm audit 0**
