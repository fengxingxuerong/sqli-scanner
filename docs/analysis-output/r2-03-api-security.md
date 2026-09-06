# 后端 API 与安全第二轮审查报告（r2-03-api-security）

> 审查日期：2026-08-25 · 审查者：后端 API 与安全工程师（ox-alpha）
> 对象：`server/`，第二轮重点：SSE 回放机制新攻击面、AI 路由改动回归、第一轮未修项复查。
> 方法：全量源码阅读（eventBus.js / scanRoutes.js / index.js / reportAiRoutes.js / ReportAI.js / oobReceiver.js / sqlmapBridge.js / requestFileParser.js / logger.js / ScanManager.js / scanRunner.js）+ git 取证（7ca2add / 5372d6e / 57715d1 / ba9dad2 等近期提交）。

---

## 零、已修项验证（本轮不重复立项）

| 近期修复 | 验证结果 |
|---|---|
| oobReceiver decodeURIComponent try/catch + token 白名单 | ✅ 已落地 [oobReceiver.js:176-192]：try/catch 返回 400；白名单 `/^[A-Za-z0-9_-]{1,64}$/` 同时封死超长 token 内存面。H2 关闭 |
| SSE 回放环形缓冲 + Last-Event-ID | ✅ 已实现 [eventBus.js:31-73,140-163]，但引入新攻击面 → 见第一节 |
| ReportAI 缓存淘汰 + 容量上限 | ✅ 已落地 [ReportAI.js:224,311-322]：CACHE_MAX=100 + 写入时清过期键。L4 关闭 |
| reportAiRoutes 404 映射 | ✅ [reportAiRoutes.js:63-64] `SCAN_NOT_FOUND → 404`。链路复查见第二节 |
| 密钥文件出库 | ✅ `git ls-files` 仅剩 `.env.example`（提交 7ca2add）。注意：git 历史中的 key 仍需服务商侧轮换，第一轮 H1 处置第 1 条不可豁免 |

---

## 一、SSE 回放机制新攻击面（本轮重点）

### 1.1 环形缓冲内存上界实测评估

- 结构：每 scanId 一个 `em._replayBuffer = []` [eventBus.js:45]，emit 时 push，超限 `splice(0, len - SSE_REPLAY_MAX)` [eventBus.js:56-60]。`SSE_REPLAY_MAX` 默认 500，env 可调但硬顶 5000 [eventBus.js:33-36] ✅。
- 单事件体积实测（遍历全部 eventBus.emit 调用点）：
  - `http_request`：节流 250ms，payload 仅 method/url(去 query)/status/ms 四字段 [scanRunner.js:26-43]，~250B；
  - `sqlmap_log`：单行文本 + level/ts [sqlmapBridge.js:284-293]，~200B；
  - `scan_started/phase/completed` 等控制事件：<300B；
  - **例外 `point_discovered`**：payload 为完整 points 数组 [scanRunner.js:53]，爬虫+表单发现的大量注入点单事件可达数十 KB 且无长度截断——缓冲内唯一"大对象"来源。
- 上界结论：
  - 典型场景（注释假设 ~300B/条）：500 条 ≈ 150KB/命名空间，100 并存扫描 ≈ 15MB —— 注释量级成立；
  - 最坏场景（point_discovered 数十 KB + SSE_REPLAY_MAX=5000）：单命名空间可达百 MB 级。但受三层既有治理约束：MAX_SCAN_API_CONCURRENT=8 并发上限、ScanManager.maxScans 超限淘汰、终态后 retireTtl 到期 `_disposeScan → eventBus.dispose` [ScanManager.js:260-282]、sqlmap 桥 60s TTL dispose [sqlmapBridge.js:356-361] —— 缓冲随命名空间整体释放，**无永久泄漏路径**。
- 定级：**低危 L-R2-3**（内存面可控）。建议 emit 入缓冲前加序列化尺寸上限（如 JSON.stringify(evt).length > 32KB 时替换 payload 为 `{truncated:true}`）。

### 1.2 dispose 后缓冲是否释放

✅ 释放路径完备：
- 内置引擎：completed/stopped/error 三条路径均走 `_retire → _disposeScan → eventBus.dispose(scanId)` [ScanManager.js:141,155,266-276]；dispose 做 `emitters.delete + removeAllListeners` [eventBus.js:194-201]，em（含 _replayBuffer）失去 Map 引用后可 GC；
- sqlmap 桥：_finish 的 setTimeout 内 `scans.delete + eventBus.dispose` [sqlmapBridge.js:358-361]；
- 回归测试覆盖：scanManager.retire.test.js 断言淘汰扫描的 eventBus 命名空间已释放；performance.phase1.test.js 断言 dispose 后 create 重建新发射器；
- 残留窗口：retireTtl（内置引擎）/60s（sqlmap）内缓冲仍驻留——属设计内"给前端拉取最终状态留时间"，可接受。

### 1.3 lastEventId 参数注入面

- 解析实现 [eventBus.js:66-73]：优先 `Last-Event-ID` 头，回退 query `lastEventId`；`Number.parseInt(raw, 10)` 后要求 `Number.isFinite && n >= 0`，否则归 null（=不回放）。
- 逐项核查：
  - **超长值**：header 与 query 同受 Node 默认请求头/请求行长度上限约束 → 无法借此放大内存；解析为 number 后仅参与数值比较 ✅；
  - **非法值**（`%zz`/`abc`/负数）：parseInt 宽容解析或归 null，值绝不回显进 SSE 流（流内只输出缓冲事件自身 seq）→ 无反射注入、无 SSE 响应分割面 ✅；
  - **`"12abc"` 类脏值**：parseInt 截断为 12，语义宽容但无害；
  - **原型污染**：输入恒为 string 经 Number 强转，无对象语义 ✅；
  - **游标穿越**：`e.seq > lastSeq` 为严格数值比较；伪造超大 lastSeq 仅使回放为空（自伤），无法触达其他 scanId 的缓冲（按 scanId 隔离 + 入口守卫）✅。
- 残留缺口（低危 L-R2-2）：**进程重启后 seq 归零** [eventBus.js:39 模块级计数器]。客户端重连带旧大 lastSeq（重启前已收 seq=8000），服务端新 seq 从 1 起 → `e.seq > lastSeq` 恒假 → 重连后事件被静默丢弃直到终态。属正确性边界而非安全洞；建议 seq 高位拼启动时间戳，或检测 lastSeq ≥ 当前计数器时降级为全量回放。

### 1.4 回放是否向未授权客户端泄露事件

✅ 守卫覆盖确认：
- SSE 入口唯一：`GET /scan/:id/events` 挂 requireReport [scanRoutes.js:504-506]；回放逻辑在 toSSE 内部执行 [eventBus.js:142-163] —— **回放与实时推送共用同一鉴权入口，不存在绕过实时守卫的独立回放端点**；
- 双层防护：设置 SCAN_API_TOKEN 时 index.js 全局中间件先拦（[index.js:90-102]，SSE 可走 query token 备选通道），requireReport 二层兜底；
- 缓冲隔离：per-scanId 命名空间，scanId 为 nanoid(12) 不可枚举；
- 未授权失败模式：401 JSON（未写 SSE 头），除"需要 Token"外不泄露任何信息；对不存在扫描返回 scan_error 事件——信息量与 GET /scan/:id 的 SCAN_NOT_FOUND 一致，可接受；
- 已知边界（沿用第一轮 M1 结论）：SCAN_API_TOKEN 未设置（本地单租户默认）时无任何鉴权，CORS 白名单内页面可订阅任意已知 scanId 的事件流。

### 1.5 新发现问题

#### M-R2-1.【中危】toSSE 清理钩子非幂等 → 连接计数多次递减，SSE 上限被软化

- 定位：[eventBus.js:174-183]
```js
const cleanup = () => { clearInterval(ping); em.off(...); _dec(scanId); };
req.on('close', cleanup);
res.on('close', cleanup);   // 同一次断开可先后触发 close + finish
res.on('finish', cleanup);
```
- 路径：连接结束（终态 res.end() 或客户端断开）时 `res 'close'` 与 `res 'finish'` 通常**先后都触发**（客户端断开时 req 'close' 亦触发）→ cleanup 执行 2-3 次 → `_dec` 对 globalConnectionCount / activeConnections 多扣。global 侧有 Math.max(0,…) 防负 [eventBus.js:190]，per-scanId 侧 n<=1 即 delete [eventBus.js:188-189]——不崩溃，但**计数系统性偏低**：实际活跃连接可在达到上限后继续接入，FD/内存防线被逐步侵蚀；前端 1-8s 退避自动重连持续放大漂移。
- 修复（一行级）：cleanup 内加 `if (cleaned) return; cleaned = true;` 幂等闸。

#### L-R2-1.【低危】回放命中终态的早退路径遗留监听器

- 定位：[eventBus.js:137-138 先注册 listener/terminalListener → 154-161 回放含终态时 res.end()+_dec+return]。该 return 不经过 cleanup（此时尚未注册 req/res 监听），两个监听器残留至 dispose(scanId) 才随 removeAllListeners 移除（内置引擎最长 retireTtl、sqlmap 最长 60s）。窗口期内每个新事件都会对已 end 的 res 执行 write（try/catch 吞掉）。影响仅为短时对象滞留 + 无效回调；修 M-R2-1 时在早退前补 em.off 两监听器即可。

---

## 二、reportAiRoutes 改动后鉴权链路完整性复查

| 检查项 | 结论 |
|---|---|
| 全局 Token 拦截 | ✅ 双挂载 [index.js:126-127] `/api/scan` + `/scan`；两路径均不在 PUBLIC_READONLY 精确集合 [index.js:54-65] → 设置 SCAN_API_TOKEN 时 AI 两端点均被全局中间件拦截（x-api-token / Bearer / query token 三通道 + SHA-256 归一恒时比较） |
| 404 映射修复回归 | ✅ [reportAiRoutes.js:62-67]：RATE_LIMITED→429、SCAN_NOT_FOUND→404、"AI 报告功能未配置"→503、LLM 错误/超时→502、其余 next(e) 进兜底 500——不再误报 404 且不泄堆栈 |
| key/model 覆盖面 | ✅ 维持服务端 env 控制，请求方不可指定 [reportAiRoutes.js:52-54] |
| 限速 | ⚠️ checkAiRate 按 req.ip 内存 Map [reportAiRoutes.js:16-32]：① index.js 未设 trust proxy → 反代下 req.ip 恒为代理地址，全用户共享 3 次/分钟配额（可用性方向）；② aiRateMap 键仍只增不删（第一轮 L3 未修），建议补上限淘汰 |
| 第二层守卫 | ⚠️ 仍未挂 requireReport：全局层认 x-api-token/Bearer/query token，requireReport 额外认 x-scan-token——两层头集合不一致（第一轮 L7/M1）**未收敛**。实际风险低（全局层已拦），但按 x-scan-token 发凭据的部署会在 AI 端点全部 401。建议导出 createReportGuard 复用统一 |
| 缓存淘汰回归 | ✅ CACHE_MAX=100 + 写入时清扫 [ReportAI.js:311-322]，L4 关闭；evidence 全文进 prompt 的外送面维持原状 |

---

## 三、第一轮未修项复查

### 3.1 sqlmapBridge 子进程参数注入——维持"无注入"，残留两项

- ✅ spawn(py, [script, ...args], {stdio, env}) [sqlmapBridge.js:252-267]：数组形式、无 shell:true → 无命令注入；env 白名单仅透传 sqlmap 相关变量。
- ✅ 参数治理复核：数值类全部区间校验；techniques 白名单 `/^[ABEUSTQ]$/i`；unionFrom 标识符白名单；headers 显式拒绝 CR/LF [sqlmapBridge.js:37,80]；长度 clamp 齐备。
- ⚠️ 未修 1（原 L8）：破坏性参数（--dump/--os-shell/--file-read）仍仅逐项 opt-in，无 SQLMAP_DESTRUCTIVE_ENABLED 总开关 [sqlmapBridge.js:174-184]。
- ⚠️ 未修 2（原 M5）：超时与 stop 仍单级 SIGTERM 无 SIGKILL 升级 [sqlmapBridge.js:271-281,364-376]；POSIX 下 sqlmap 忽略信号即永久占用并发槽（默认 2）；Windows 上 SIGTERM≈强杀故影响有限。另 --method 值仍只 toUpperCase 未做 `^[A-Z]+$` 白名单（optparse 作值消费，风险低，防御性收紧即可）。

### 3.2 requestFileParser 边界——第一轮 M4 三缺口全部未修

[requestFileParser.js] 与第一轮一致无改动：
1. **无输入大小上限**：整段文本 split/遍历，消费点 bin/cli.js 直读 -r 文件，GB 级文件全量入内存逐行处理；
2. **Host 头拼接注入仍在** [requestFileParser.js:54-62]：`url = http://${hostVal}${path}` 无合法性校验——`Host: user:pass@evil.com` 构造 userinfo URL、`Host: evil.com/?x#` 篡改 path/query；CLI 直通路径无 assertSafeHttpTarget 兜底（路由层有）；
3. **decode 粒度过粗** [requestFileParser.js:66-82]：try/catch 包住整个 params 循环，任一 query 对含坏百分号序列即抛出 → 丢弃全部参数提取结果而非跳过该对。
- 建议：hostVal 强制 `/^[A-Za-z0-9.\-\[\]]+(:\d+)?$/`；decode 改 per-pair try/catch；入口加长度上限。

### 3.3 logger 脱敏覆盖度——第一轮 M6 缺口确认仍存在

- 文本形态覆盖良好 ✅：URL 凭据/Authorization/Cookie/password= 类键值均有正则 [logger.js:13-19]，且在 printf 层对 console+file 双 transport 统一生效 [logger.js:126-132]。
- ⚠️ 缺口 1（JSON 形态）：SENSITIVE_KEY_RE 要求敏感词后紧跟 `\s*[=:]`，而 `"password": "x"` 中间有引号 → 不命中，JSON 序列化的凭据落日志不打码；
- ⚠️ 缺口 2（socks 代理）：URL_CRED_RE 仅匹配 `https?://`，`socks5://user:pass@host` 凭据漏脱敏；
- ⚠️ 缺口 3（承接原 L9）：file transport 仍未设 mode 0600。
- 建议：正则改 `(password|...)"?\s*[:=]\s*"?[^\s&;,"]+`；URL_CRED_RE 扩为 `((?:https?|socks[45]h?):\/\/)`。

---

## 四、CORS 抛错变 500 问题现状

- **未修，行为不变**。[index.js:75-79] origin 校验失败 `cb(new Error('CORS: 源不被允许'))` → 错误链直达兜底处理器 [index.js:153-156] → 返回 **500 code:9001 "服务器内部错误"**。
- 影响：① 语义错误——源非法是 403 场景却报服务端故障，监控/网关按 500 计入错误率可致误熔断；② 日志噪音——每次跨域探测打 error 级日志，掩盖真实异常信号。
- 修复建议：origin 回调改记 `cb(null, false)`（不发 CORS 头由浏览器侧拒绝），或前置自写中间件对非法 origin 直接 403 JSON。维持低危定级。


---

## 五、本轮发现与未修项汇总

### 5.1 本轮新增发现（R2）

| 编号 | 级别 | 位置 | 问题 | 状态 |
|---|---|---|---|---|
| M-R2-1 | **中危** | [eventBus.js:174-183] | toSSE 清理钩子非幂等，close+finish 多次触发 `_dec` → 连接计数系统性偏低，SSE 并发上限被软化，FD/内存防线被前端自动重连逐步侵蚀 | 待修（一行级幂等闸） |
| L-R2-1 | 低危 | [eventBus.js:137-161] | 回放命中终态早退路径不经过 cleanup，两监听器残留至 dispose 才移除，窗口期内对已 end 的 res 无效 write | 待修（随 M-R2-1 一并处理） |
| L-R2-2 | 低危 | [eventBus.js:39,66-73] | 进程重启后 seq 归零，客户端重连带旧大 lastSeq → `e.seq > lastSeq` 恒假，重连后事件被静默丢弃至终态（正确性边界，非安全洞） | 待修（seq 高位拼启动时间戳或降级全量回放） |
| L-R2-3 | 低危 | [scanRunner.js:53] + [eventBus.js:45-60] | `point_discovered` 单事件可达数十 KB 且无截断，最坏场景（×5000 上限）单命名空间缓冲达百 MB 级；受并发上限/dispose 治理约束无永久泄漏路径 | 待修（入缓冲前加序列化尺寸上限截断） |

**本轮新增高危：无。**

### 5.2 第一轮未修项回归状态（R2 复查）

| 原编号 | 级别 | 位置 | 问题 | R2 状态 |
|---|---|---|---|---|
| M4 | 中危 | [requestFileParser.js] | 三缺口全部未修：无输入大小上限、Host 头拼接注入、decode 整循环 try/catch 过粗 | ⚠️ 维持中危 |
| M5 | 中危 | [sqlmapBridge.js:271-281,364-376] | 超时/stop 仅单级 SIGTERM 无 SIGKILL 升级；POSIX 下可永久占用并发槽（Windows 影响有限） | ⚠️ 维持 |
| M6 | 中危 | [logger.js:13-19] | JSON 形态凭据不打码（引号致正则不命中）、socks 代理凭据漏脱敏、file transport 未设 0600 | ⚠️ 维持 |
| M1/L7 | 中危/低危 | [index.js] + [reportAiRoutes.js] | 双层守卫头集合不一致（x-api-token/Bearer/query vs x-scan-token）；AI 两端点仍未挂 requireReport——实际风险低但未收敛 | ⚠️ 维持 |
| L3 | 低危 | [reportAiRoutes.js:16-32] | aiRateMap 键只增不删；且未设 trust proxy → 反代下 req.ip 恒为代理地址，全用户共享 3 次/分钟配额 | ⚠️ 维持 |
| L8 | 低危 | [sqlmapBridge.js:174-184] | --dump/--os-shell/--file-read 仅逐项 opt-in，无 SQLMAP_DESTRUCTIVE_ENABLED 总开关 | ⚠️ 维持 |
| L9 | 低危 | [logger.js] | file transport 未设 mode 0600（并入 M6 缺口 3 跟踪） | ⚠️ 维持 |

### 5.3 已关闭项（本轮验证通过，不再跟踪）

- H2（oobReceiver decode 异常 + token 白名单）：已修；
- SSE 回放环形缓冲 + Last-Event-ID 主体机制：已落地，残余面拆为 M-R2-1 / L-R2-1~3；
- L4（ReportAI 缓存无界）：CACHE_MAX=100 + 写入时清扫，已关；
- reportAiRoutes 404 误映射：SCAN_NOT_FOUND → 404，已关；
- H1 密钥出库：文件已删，**git 历史 key 服务商侧轮换仍不可豁免**。

### 5.4 总体结论

第二轮重点审计的 SSE 回放机制**设计方向正确**：per-scanId 缓冲隔离、鉴权入口唯一、dispose 全路径释放均有保障；新引入问题集中在连接计数幂等性（M-R2-1，建议优先修）与大事件体积上界（L-R2-3）。第一轮中危项 M4/M5/M6 全部零进展，建议下一迭代按 M-R2-1 → M4 → M6 → M5 顺序处置。

