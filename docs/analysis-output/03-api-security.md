# 后端 API 与安全深度审查报告（03-api-security）

> 审查日期：2026-08-25 · 审查者：后端 API 与安全工程师（ox-alpha）
> 对象：`server/`（Express 引擎 + CLI + 核心库），基线为主代理已确认项，本报告在其之上补齐 7 个深度项并给出 [文件:行号] 定位。
> 方法：全量源码阅读（index.js / api/* / core/* / engines/* / services/* / bin/cli.js）+ git 取证（git ls-files / git log / git show）。

---

## 一、基线确认与深化（复核结论）

| 基线项 | 复核结论 |
|---|---|
| server/.env.ai 3 个真实 sk- key 入库 | **确认且扩大**：`git ls-files` 显示 `.env.ai`、`server/.env.ai`、`server/.env.test` 均被跟踪；工作区两个 .env.ai 合计命中 3 处 `sk-`。引入提交 af372ee（2026-08-22，commit message 自称"不入源码，不泄露"但文件本身被 add）与 63710f8（2026-08-19）。`.gitignore` 仅忽略 `.env`/`.env.local`，**不覆盖 `.env.ai`**，后续改动仍会继续入库 → 见 H1 |
| exploitRoutes：EXPLOIT_ENABLED 默认关 | 确认 [exploitRoutes.js:28,120-134]：默认 403、authorized:true 已降级为纯审计字段、独立令牌桶默认 5 req/s（L31-45）、sanitizeTarget 过 assertSafeHttpTarget SSRF 校验（L63）、FORBIDDEN_HEADER_NAMES 头黑名单（L20-23） |
| index.js：SHA-256 归一恒时比较 | 确认 [index.js:44-50] safeEqual 双方先 SHA-256 再 timingSafeEqual；PUBLIC_READONLY 精确路径白名单 [index.js:54-65]；兜底错误不打堆栈 [index.js:153-156]；CORS 拒绝抛 Error 变 500 而非 403 [index.js:75-79]（见 L1） |
| ReportAI.js：keyHealth 冷却降级 | 确认 [ReportAI.js:28-46]：429 冷却 60s、其余 10s，getRoleConfig 跨角色遍历降级（L49-68）；reportCache 无淘汰见 L4；prompt 拼接扫描结果见 M2 |

---

## 二、高危

### H1.【CRITICAL】真实 LLM API Key 入库，且 .gitignore 不拦截后续复发

- 定位：
  - [server/.env.ai]（git tracked，含真实 `sk-` key）
  - [.gitignore:1-2] 仅 `.env` / `.env.local`
  - 消费点 [server/src/services/ReportAI.js:12-18] `AI_REPORT_KEY_1..3` 经 dotenv 读入
  - 引入历史：af372ee、63710f8（`git log --all -- server/.env.ai` 仅此一条，key 自该提交起永久暴露于历史）
- 影响：任何能 clone 仓库（含 fork/CI 缓存/GitHub 历史）的人可直接烧 LLM 配额、以项目身份调用 sensenova/deepseek/glm 接口。
- 加剧因素：根目录 `.env.ai` 也被跟踪（模板与真实文件同名混用，极易再次误填真实 key 提交）。
- 处置（按顺序）：
  1. 服务商侧**吊销并轮换**全部 3 个 key（清史不能替代轮换）；
  2. `.gitignore` 增加 `.env*.ai`、`server/.env.*`，真实配置迁移到环境变量或密钥管理；
  3. `git filter-repo` 清除历史中的 key；通知所有 fork 协作者重克隆。

### H2. OOB HTTP 接收端畸形 token 触发未捕获 URIError → 整进程崩溃（DoS）

- 定位：[server/src/core/oobReceiver.js:162-180] `_handleHttp`
```js
const token = decodeURIComponent(m[1]);   // L176：无 try/catch
this.receive(token);
```
- 路径：`GET /oob/%E0%A4%A`（任何非法百分号序列）→ `decodeURIComponent` 同步抛 `URIError` → http request listener 异常未被捕获 → uncaughtException → Node 默认退出。**一个无认证请求即可打崩整个扫描引擎**（OOB 监听端口独立于 Express，不经 SCAN_API_TOKEN 中间件）。
- 可达前提：攻击者需可达 `LISTEN_HOST`（[oobReceiver.js:16] 默认 127.0.0.1 → 本机恶意进程、或经浏览器 SSRF/CSRF 打 http://127.0.0.1:<port>/oob/%xx；`OOB_LISTEN_HOST` 显式放开后为远程直达）。因后果是整进程崩溃且 payload 极简，定高危；loopback 默认值为缓解条件。
- 修复：
  1. token 白名单 `/^[A-Za-z0-9_-]{1,64}$/`（同时解决 L10 的超长 token 内存面）；
  2. `_handleHttp` 全体包 try/catch，异常返回 400；
  3. 进程级兜底 `process.on('uncaughtException')` 记录而非退出（可选纵深）。

## 三、中危

### M1. AI 报告端点：鉴权归属、scanId 校验与数据外送面（深度项 1）

**鉴权归属**
- 挂载 [server/index.js:126-127] `/api/scan` 与 `/` 双挂载；端点 `POST /scan/:id/report/ai`、`GET /scan/:id/report/ai/configs`。
- **不在 PUBLIC_READONLY**（[index.js:54-65]）→ 设置了 `SCAN_API_TOKEN` 时被全局中间件拦截（[index.js:90-102]），归属正确 ✓。
- 但该路由**没有** scanRoutes 的二层守卫 `requireReport`（对比 [scanRoutes.js:481-528] 所有 :id 端点都挂）：requireReport 额外接受 `x-scan-token` 头（[scanRoutes.js:423]），而全局中间件只认 `x-api-token`/Bearer/query token（[index.js:96-99]）。两层 token 通道集合不一致 → 只按 x-scan-token 发放凭据的部署会出现"报告可读、AI 生成一律 401"的误配；反之若有人误把 AI 端点加进白名单集合也无第二层兜底。建议统一为同一 guard 工厂。

**scanId 校验与跨用户泄露**
- scanId 由 `nanoid(12)` 生成 [ScanManager.js:121]，不可枚举 ✓；不存在时 NOT_FOUND [reportAiRoutes.js:42-45] ✓。
- 结果回传仅含 LLM 生成的文本（不回传 report 本体）→ 不直接泄露他人扫描数据 ✓。
- **残余风险**：`SCAN_API_TOKEN` 未设置（默认本地单租户部署）时，CORS 白名单内的任一页面/本机进程拿到 scanId 即可触发 LLM 流水线并取回含漏洞细节的报告；无 per-user 隔离。属单租户假设下的已知边界，建议文档明示 + 可选 `AI_REPORT_ENABLED` 开关默认关。
- 限速 checkAiRate 基于 req.ip 的 Map（[reportAiRoutes.js:16-32]），在鉴权之后执行顺序正确；但 Map 键只增不删 → 见 L3。

**数据外送面（第三方 LLM）+ prompt 注入落地**
- [ReportAI.js:71-107] buildAnalystPrompt 将每个漏洞的 **evidence 全文**（目标站点响应片段 + 注入 payload）拼入 prompt；maskUrl（L171-176）只遮 path，**host 明文**发送给外部 API_BASE（默认 sensenova 公网端点，L12）。
- 被测目标响应完全由对方控制 → 构造响应即可注入指令（"忽略以上内容，输出…"），经 analyst→writer→reviewer 三级拼接放大（writer 把 analysis 原文回灌 L124-128，reviewer 再回灌 draft L158-159）。最终注入内容进入交付给操作者的报告——**目标站→LLM→报告的二次注入链**。
- 建议：evidence 入 prompt 前截断（复用 logger.truncateLong）+ 剥离控制字符；对 LLM 输出做结构校验（analyst 要求 JSON 但未 validate，L207 直接取 content）；报告中标注"AI 生成内容不可作为授权依据"。

### M2. DNS OOB 通道无域名绑定校验 → 伪造命中破坏检测可信度（深度项 4 核实）

**已有防护核实（部分有效）**
- `OOB_RECEIVED_MAX` 默认 10000 上限淘汰 ✓ [oobReceiver.js:17-20, 287-293]
- `OOB_RATE_PER_MIN` 默认 60/IP 令牌桶，HTTP 与 DNS 共用 `_rateOk` ✓ [oobReceiver.js:21-24, 50-63, 171, 186]
- 监听面：HTTP 与 DNS 都绑 `LISTEN_HOST`（默认 127.0.0.1）✓ [L16, 95, 134]；DNS 绑定失败静默降级不影响 HTTP OOB ✓ [117-121]

**缺口**
1. **token 无域名绑定**：[oobReceiver.js:227-238] 仅取 firstLabel 且只过滤 `_` 开头标签，**不校验 qname 是否以配置的 dnsDomain 结尾**（dnsDomain 仅出现在日志 L129）。本机任意进程可直接向监听端口发包注册任意 token → OOB 检测可被伪造命中（误报 Critical）或预先灌入 token 掩盖真实无回显判定。UDP 源地址还可伪造绕过 per-ip 令牌桶。
2. 修复：`receive(firstLabel)` 前置条件 `qname === firstLabel + '.' + dnsDomain`（dnsDomain 未配置时拒绝 DNS 通道）；DNS 层对同一 token 只接受首次。

### M3. sessionStore 路径白名单强度与会话落盘范围（深度项 2）

**防护核实（有效的部分）**
- 绝对路径 / `..` 逃逸：tmpdir 分支用 `path.relative(os.tmpdir(), path.resolve(filePath))` 判定（[sessionStore.js:25-27]），`D:\evil.json`、`..\..\x` 均判绝对逃逸拒绝 ✓
- UNC：`\\srv\share\f.json` resolve 后仍为 UNC，relative 返回绝对路径 → 拒绝 ✓
- 裸文件名分支拒 `..`、点开头隐藏文件（.env）✓ [L16-23]
- 写盘前二次校验 `_flush` L122 + load 前 L134 校验 ✓

**缺口**
1. **CWD 任意非隐藏文件可被覆盖**：裸文件名分支 `SESSION_NAME_RE = /^[A-Za-z0-9._-]+$/` 允许 `package.json`、`eslint.config.js` 等合法项目文件名。API 层 [scanRoutes.js:307-315] 仅调 isSafeSessionPath，不限制扩展名/目录 → `config.sessionFile=package.json` 可让会话 JSON（含目标 URL、注入点、漏洞证据）覆盖工作目录同名文件，且会话数据本身写到非预期位置。建议强制 `sqli-session-*` 前缀或 `.json` 扩展 + 固定到专用子目录。
2. **Windows 大小写误拒（可用性 bug）**：os.tmpdir() 在 Windows 返回大写盘符路径（如 `C:\Users\…`），path.resolve 保持输入大小写；`path.relative` 对盘符大小写不一致判为跨卷绝对逃逸 → 合法的 tmpdir 内路径被误拒。建议比较前统一 toLowerCase 盘符。
3. **不做 realpath**：tmpdir 内若存在指向外部的符号链接/junction 可穿越（需本地建链权限，概率低）。建议 `fs.realpath` 后再校验。
4. **NTFS ADS**：tmpdir 分支接受 `f.json:stream` 形式（resolve 后仍在 tmpdir 内）→ 备用数据流写入面（低概率、低影响）。
5. **敏感落盘范围与权限**：
   - sanitizeConfigForDisk [L31-35] 整体剥 `auth`/`proxy` ✓（含 auth.headers 中的 Authorization/Cookie）；
   - 但 `url` 明文、`points[].originalValue`、perPoint found 证据照落盘；`fs.writeFile` 未设 mode（[L127] 默认 0644）→ Unix 多用户主机上其他本地用户可读 tmp 下会话文件。建议 mode 0o600 并文档声明残留内容。

### M4. requestFileParser 解析边界（深度项 3）

- 定位：[server/src/core/requestFileParser.js] 全文 + 消费点 [bin/cli.js:253-284]
1. **无大小上限**：parseRequestFile 不限量，cli.js:259 `readFileSync` 全量读入 → 超大 -r 文件直接 OOM（CLI 本地场景，降级因素；若未来暴露为 API 需先加 2MB 上限对齐 express.json limit）。
2. **Host 头拼接注入**：[requestFileParser.js:54-62] `url = http://${hostVal}${path}`，hostVal 未做任何合法性校验：`Host: user:pass@evil.com` 构造出带 userinfo 的 URL；`Host: evil.com/?x#` 篡改 path/query；含空格/引号同样透传。内置引擎路由层有 assertSafeHttpTarget 兜底，但 CLI 直通无校验 → 目标可被请求文件内容重写。建议 hostVal 强制 `/^[A-Za-z0-9.\-\[\]:]+(:\d+)?$/`。
3. **孤立 CR 残留**：split(/\r?\n/) 不处理行内孤立 `\r`，header value 可携带 `\r` 透传给引擎/sqlmap（sqlmapBridge 有 hasCrlf 显式拒绝 ✓ [sqlmapBridge.js:37,80]，内置引擎依赖 Node 头值校验兜底）。建议解析时 strip \r。
4. **decodeURIComponent 循环级 catch**：[L66-82] try 包住整个参数循环，单个坏编码导致**整段 query 参数丢弃** → 注入点漏发现（功能性缺陷，间接漏报）。
5. 畸形头行（无冒号）静默跳过、重复头后者覆盖——行为可接受，但建议至少 debug 记录。

### M5. sqlmapBridge：强杀单级 SIGTERM → 并发槽永久泄漏（深度项 5 核实）

**已核实的安全面**
- spawn 数组参数、未用 shell → 无 shell 命令注入 ✓ [sqlmapBridge.js:252-267]
- buildArgs 白名单/clamp 全面：url 必须 ^https?://（防 file:// 等，L69）、CR/LF 拒绝（L80）、level/risk/threads/timeSec/ignoreCode/verbose 数值域校验、unionFrom 标识符正则、prefix/suffix ≤200 ✓
- 子进程 env 白名单最小化 ✓ [L255-266]；status() 不返回绝对路径 ✓ [L201-212]
- 并发上限 maxConcurrent 默认 2 ✓ [L197, 222-224]

**缺口**
1. **超时仅 SIGTERM 无升级 SIGKILL**：[L270-282] runtimeTimer 到点 kill('SIGTERM')；Unix 上 python 忽略 SIGTERM 时 close 事件永不触发 → `_running` 永久占位（默认上限 2），后续所有 sqlmap 启动报"并发已达上限"→ 引擎级拒绝服务。stop() 同样单级 SIGTERM [L369]。修复：SIGTERM 后 5s 未退出升级 SIGKILL（Windows 上 terminate 本身即强杀，可平台分支）。
2. **破坏性参数不受总开关治理**：[L174-184] `--dump/--os-shell/--file-read` 只需 config.sqlmap 传参即可触发，与 exploitRoutes 的 EXPLOIT_ENABLED 默认关治理不对齐 → 见 L8 建议。

### M6. logger.js 脱敏覆盖度缺口（深度项 7）

**已覆盖（核实有效）**
- URL 内嵌 `user:pass@`（http/https）[logger.js:15,41] ✓
- Authorization/Proxy-Authorization 头值（含 Bearer/Basic/Digest scheme）[L17,43] ✓
- Cookie/Set-Cookie 头值 [L19,45] ✓；`token=xxx` query 形态被 SENSITIVE_KEY_RE 命中（值到 `&` 截断）✓
- 对象形态头：redactHeaders 敏感头整体打码，含 x-api-token/x-scan-token [L22-29,60-67] ✓
- 统一出口：winston printf 在输出前 redact + 4000 字符截断，覆盖控制台与文件 transport ✓ [L124-132]

**缺口**
1. **JSON 形态凭据漏打码**：SENSITIVE_KEY_RE 要求键名后紧跟 `\s*[=:]`（L13），而日志中 JSON 序列化形态 `"password":"x"` 键名后是引号 → 正则不匹配 → **password/token/api_key 以 JSON 形态出现在 warn 日志时明文落盘**。文件 transport 恰是 warn 以上级别（L115），加重暴露。建议正则改为 `(key)["']?\s*[:=]\s*["']?` 容忍引号。
2. **socks5 代理凭据泄露**：URL_CRED_RE 仅匹配 `https?://`（L15），`socks5://user:pass@proxy:1080` 不打码 → CLI `--proxy socks5://…` 的凭据经日志外泄。建议扩为 `(https?|socks[45h]?|ftp)://`。
3. 文件 transport 仅 warn+（L115）：info 级敏感消息不上文件（好），但控制台全量输出且无 TTY 检测——CI/管道采集场景敏感信息随 stdout 归档。

### M7. bin/cli.js 配置注入面与敏感信息输出（深度项 6）

1. **配置注入评估**：parseArgs 未知 flag 静默忽略（fail-safe 方向正确）；level/risk clamp、technique 白名单过滤、tamper 插件过滤后进 config ✓ [bin/cli.js:305-318]。CLI 与服务端共享同一 sanitize 边界之下的引擎层，无独立注入面 → 无高危项。
2. **敏感信息输出**：
   - 批量进度打印原始 URL 未过 redact：[cli.js:576] `console.error(...${url}...)` —— URL 含 `user:pass@host` 或长 query token 时明文上终端/CI 日志；
   - `-d` 直连连接串（含数据库密码）经 process.argv 暴露于 shell history / ps；
   - 报告 stdout 直出完整 report（含拖库 data 内容，[cli.js:612-622]）——属工具预期功能，但建议文档标注"报告即敏感数据"；
   - CLI 顶层错误只打印 e.message（[cli.js:639-643]）✓ 不带堆栈。
   - 建议：进度输出统一过 `redact()`；直连串支持 env 传参（SQLI_DIRECT_DSN）。
3. **--out 写盘**：批量模式 safeName 替换非法字符并截断 100 字符 ✓ [cli.js:591]；单模式 args.out 为本地用户指定路径，属预期信任边界。

---

## 四、低危

### L1. CORS 拒绝返回 500 而非 403（基线确认）
[index.js:75-79] origin 回调 `cb(new Error(...))` 落入兜底错误处理 → HTTP 500/code 9001。无信息泄露，但审计语义失真、可能污染上游 5xx 告警。修复：cb(null, false) 或专用 403 中间件。

### L2. query string 传递 API token（SSE 权衡）
[index.js:99] `req.query['token']` 作为 EventSource 备选通道 → token 可能进入反代访问日志、浏览器历史。建议改用短期签名 URL 或一次性 ticket。

### L3. aiRateMap 条目永不回收
[reportAiRoutes.js:16-32] resetAt 过期时复用 entry 但 Map 键只增不删；海量源 IP（经反代）下慢速内存增长。对比 oobReceiver._ipBuckets 有 1024 上限、sqlmapBridge 有 TTL——此处遗漏。建议同款上限淘汰。

### L4. reportCache 过期条目永不删除（基线确认，量化）
[ReportAI.js:222-237, 310-311] TTL 仅在读取命中时判断（L237），过期条目无人清理；每条缓存含三级 LLM 全文（数十 KB 级），长驻进程缓慢泄漏。建议定时清扫或 LRU 上限。

### L5. 上游 LLM 错误体透传客户端
[ReportAI.js:202-204] `errText.slice(0,200)` 进入异常 message，[reportAiRoutes.js:61-69] 原样回传 → 第三方端点内部细节（网关签名、路径等）可泄露给调用方。建议固定文案 + 服务端日志留详情。

### L6. exploitRoutes 错误统一 HTTP 200
[exploitRoutes.js:139-149] wrap 把 AppError（含限速/未授权）都 res.json 200 → 状态码监控、网关熔断失效。基线三项治理（默认关/审计字段/独立令牌桶）复核无误，仅状态码语义问题。

### L7. 双层守卫 token 头集合不一致
[index.js:96-99] 接受 x-api-token/Bearer/query token；[scanRoutes.js:422-425] 额外接受 x-scan-token。运维按任一文档发凭据都可能遇到半数端点 401。建议收敛到同一实现（createApp 导出 guard 供路由复用）。

### L8. sqlmap 破坏性参数缺总开关（对应 M5 缺口 2）
[sqlmapBridge.js:174-184] 建议 `SQLMAP_DESTRUCTIVE_ENABLED !== '1'` 时剔除 --dump/--os-shell/--file-read，与 exploitRoutes 治理对齐。另：`t.method` 仅 toUpperCase 未做 `^[A-Z]+$` 白名单（optparse 将其作为值消费，实际风险低，防御性收紧即可）；PYTHON_PATH/SQLMAP_PATH 属运维控制面，可控即等同任意代码执行——预期信任边界，建议在部署文档显式声明。

### L9. engine.log 默认权限过宽
[logger.js:91-118] 固定 `<cwd>/logs/engine.log` 或 tmp 回退，未设 mode（0644）；warn 级以上内容虽经 redact，仍含目标 host、payload 摘要。建议 File transport 加 `options: { mode: 0o600 }`（Unix 生效）。

### L10. oobReceiver 内存治理细节
[oobReceiver.js:58-61] _ipBuckets 超 1024 删"插入序最旧"而非最久未活跃，可能误删活跃桶/保留死桶；[oobReceiver.js:176] HTTP token 未限长，_received 单条上限受 Node 默认最大头约束（~16KB×10000 ≈ 上界百 MB）。配合 H2 修复的 token 白名单一并解决。

---

## 五、汇总

### 5.1 按严重度统计

| 级别 | 编号 | 一句话摘要 | 关键定位 |
|---|---|---|---|
| 高危 | H1 | 3 个真实 sk- key 入库且 .gitignore 不拦截，需吊销轮换+清史 | server/.env.ai; .gitignore:1-2 |
| 高危 | H2 | OOB HTTP 畸形 token 未捕获 URIError → 单请求打崩进程 | oobReceiver.js:162-180 |
| 中危 | M1 | AI 报告端点双层守卫不一致 + evidence 全文外送 LLM + prompt 注入链 | reportAiRoutes.js:35-74; ReportAI.js:71-128 |
| 中危 | M2 | DNS OOB token 无域名绑定 → 可伪造命中破坏检测可信度 | oobReceiver.js:227-238 |
| 中危 | M3 | sessionFile 白名单允许覆盖 CWD 非隐藏文件；Windows 大小写误拒；0644 落盘 | sessionStore.js:16-28,127 |
| 中危 | M4 | -r 解析无大小上限、Host 头拼接注入、坏编码丢整段参数 | requestFileParser.js:54-82; cli.js:259 |
| 中危 | M5 | sqlmap 超时/停止仅 SIGTERM 无升级强杀 → 并发槽永久泄漏 DoS | sqlmapBridge.js:270-282,369 |
| 中危 | M6 | logger 对 JSON 形态凭据与 socks5 代理凭据漏脱敏 | logger.js:13-19 |
| 中危 | M7 | CLI 进度输出未脱敏 URL 凭据；直连串经 argv 暴露 | cli.js:576,495 |
| 低危 | L1-L10 | CORS→500、query token、aiRateMap/reportCache 无回收、LLM 错误透传、exploit 统一 200、token 头集合不一致、sqlmap 破坏性参数无总开关、engine.log 权限、OOB 内存细节 | 见各条 |

### 5.2 深度项覆盖对照（任务要求 7 项）

1. reportAiRoutes 鉴权/scanId/数据回传 → **M1**（鉴权归属正确但双层守卫不一致；scanId nanoid(12) 不可枚举；回传不泄露本体，外送面在 prompt）
2. sessionStore / isSafeSessionPath → **M3**（穿越防护对绝对/UNC/../ 有效；CWD 文件覆盖面、Windows 盘符大小写、symlink/ADS 为缺口）
3. requestFileParser → **M4**（上限缺失、Host 注入、孤立 CR、decode 粒度）
4. oobReceiver 伪造命中与监听面 → **H2 + M2 + L10**（限速/上限实现核实有效；HTTP 崩溃 + DNS 无域名绑定是缺口；默认 loopback 缓解）
5. sqlmapBridge → **M5 + L8**（spawn 数组无注入 ✓；并发上限 ✓；SIGTERM 单级强杀为缺口；SQLMAP_PATH 信任边界声明）
6. bin/cli.js → **M7**（无独立配置注入高危面；敏感输出未过 redact）
7. logger.js → **M6**（文本形态覆盖良好；JSON 形态与 socks5 是实际缺口）

### 5.3 处置优先级建议

1. **立即（当天）**：H1 吊销轮换 3 个 key + 补 .gitignore；H2 给 _handleHttp 加 try/catch 与 token 白名单。
2. **本周**：M2 DNS 域名绑定校验；M5 SIGKILL 升级；M6 正则补丁；M1 evidence 截断/结构校验。
3. **下个迭代**：M3 白名单收紧 + mode 0600；M4 Host 校验与 decode 粒度；L3/L4 内存回收；L1/L6/L7 状态码与守卫统一。

> 审查局限：静态审读为主，未做动态利用验证（如 H2 的崩溃复现、M2 的 UDP 伪造）；ScanManager 报告脱敏（publicTarget/publicReport）与 httpClient SSRF 策略属其他报告范围，本报告仅引用其结论。




