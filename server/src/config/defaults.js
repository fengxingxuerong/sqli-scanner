// 引擎默认参数（集中维护，前后端/双形态需同步修改）
export const defaults = {
  // 网络
  port: 4567, // 引擎监听端口
  // [P0-FIX 对标 sqlmap 默认值] 单请求超时 10s→30s、重试 2→3：
  // 慢目标上短超时会让正常响应被当作失败（叠加 retry 后仍易抖动），且时间盲注
  // 判定窗口被压缩产生误判。对齐 sqlmap 默认（30s / 3 retries）作为保守基线；
  // 追求速度的场景由前端/CLI 显式调低（ratePerSec/concurrency 保持现值不变，
  // 它们经 per-scan 限速桶约束，安全性与并发解耦）。
  timeoutMs: 30000, // 单请求超时（sqlmap 默认 30）
  retry: 3, // 失败重试次数（sqlmap 默认 3）
  // 显式 HTTP keep-alive Agent 开关（false=默认启用长连接复用；true=回退 Node 默认 agent 行为）。
  // 对标 sqlmap --keep-alive 的反向开关：默认开，禁用后不再挂自定义 keep-alive Agent。
  // [P0-FIX 2026-09-09] 本键与 http2 此前只存在于 defaults，未进 scanRoutes 的 KNOWN_CFG_KEYS →
  // REST/CLI 传 `config.disableKeepAlive` 被 sanitizeStart 静默丢弃：用户以为换了传输形态，实际
  // 仍是默认 Agent（会话/连接复用行为与预期不符，且 WAF 侧看到的指纹也不同）。已补白名单+透传。
  disableKeepAlive: false,
  // HTTP/2 支持（对标 sqlmap --http2）：开启后爬虫/页面取页路径走 undici（ALPN 协商 h2 优先，
  // 不支持则自动降级 HTTP/1.1）。默认关闭——盲注提取等主请求路径仍走 axios HTTP/1.1（零风险）。
  http2: false,
  // 令牌桶限速（请求/秒）。历史演进：3（锁死并发收益）→ 50（对标 sqlmap --delay=0 无限速）
  // → 10（[P0-FIX 2026-09-12 保守化]）。为什么从 50 降到 10：sqlmap 敢默认不限速的前提是
  // 用户是会显式调参的老手；本项目的核心用户是「一键扫描」人群，50 req/s 对脆弱目标
  // （老式 CMS、小水管接口、无防抖的前后端）接近压测，授权范围内也可能把目标打挂。
  // 10 req/s 保住 4 并发的基本吞吐（本地靶场全量 e2e 时间预算不变），同时把「开箱即打挂目标」
  // 的风险压到可接受水位。追求速度的场景仍由前端/CLI 显式调高（前端限速设置经 ScanManager
  // 按 scanId 注入 HttpClient 独立桶，真正生效）。
  ratePerSec: 10,

  // 调度
  concurrency: 4, // 并发检测线程数
  // 会话默认落盘（P2-P4）：true 时扫描自动用固定文件名 sqli-session-latest.json 落盘，
  // 下次对同一目标 URL 扫描自动 resume（跳过已完成点，复扫近乎 0 请求）。
  // 默认 false 保持现状（显式传 sessionFile 才落盘），避免静默副作用。
  sessionDefault: false,

  // 检测
  // level/risk 分级（对标 sqlmap --level / --risk）：
  //   level 1-5：payload 复杂度 / 边界探测强度（1 默认，5 最深）
  //   risk  1-3：是否尝试可能影响数据完整性的高破坏性 payload
  //   risk 1：仅 union/error/boolean（安全，无写请求/无长时间等待；time/stacked/oob 被 _selectedTechs 摘掉）
  //   risk 2：含 time/stacked/oob + OR 变体（默认，与旧行为一致）
  //   risk 3：以上全部 + 注册表 risk=3 条目。注释与旧文案「额外 OR 变体布尔测试」不符（[P0-FIX 2026-09-09] 更正）：
  //     声明式注册表里 risk=3 的条目实为 payloads/destructive.js 隔离池的同源模板 —— INTO OUTFILE 写文件、
  //     LOAD_FILE/pg_read_file 任意文件读、xp_cmdshell / COPY TO PROGRAM / load_extension 命令执行、
  //     sp_configure 永久改服务器配置、GET_LOCK/BENCHMARK/RANDOMBLOB DoS、OPENROWSET/UTL_HTTP 外连。
  //     这批条目同时声明 level:5，故只在 level=5 + risk=3 才会被投放；因此「risk 开关」的真实语义是
  //     risk>=3 **且** level>=5，单改 risk 不提 level 在注册表路径下也不会放出高危池（此前注释让人以为改 risk 就够）。
  //     扇平路径（useRegistry=false）此前根本没有 risk>=3 的调用点 → 高危池永不投放，risk 有名无实；
  //     现由 ScanManager 按 productionMode/confirmDestructive 硬门接上 enableDestructivePayloads 调用点。
  level: 1,
  risk: 2,
  // ── [P0-FIX 2026-09-09] 生产护栏总闸 + 不可逆动作显式确认 ────────────────────────
  // 实战后果：扫描器打的是客户**生产**系统。此前 risk=3 一旦打开，注册表就把「写文件 / RCE /
  // 永久改配置 / DoS」模板直接发出去，没有任何二次确认；而扇平路径又完全不发（同一个开关两种后果）。
  // 现统一为：默认把目标当生产环境（productionMode=true），高危池必须 confirmDestructive===true 才投放；
  // 未确认则**跳过这些模板并在 report.summary.constraints 记一条**（被抑制的能力必须在报告里可见，
  // 否则「测了没测」用户只能靠猜）。productionMode=false 是显式脱离护栏（打靶场/自建演练环境），
  // 保持旧语义：注册表 risk>=3 即投放，并在日志打 warn 说明已脱离生产护栏。
  productionMode: true,
  // 高危（destructive）payload 池投放确认位：默认 false = 不投放。true 表示操作者已确认获得书面授权、
  // 且目标可承受写文件/命令执行/资源耗尽类探测。对应 CLI `--confirm-destructive`、REST config 同名键。
  confirmDestructive: false,
  // testFilter / testSkip（对标 sqlmap --test-filter / --test-skip）：逗号分隔的 id 子串列表，
  // 大小写不敏感。testFilter=白名单（仅保留 id 含任一子串的条目），testSkip=黑名单（排除 id 含任一子串的条目）。
  // 空串=不过滤（全部运行 / 不跳过）。
  testFilter: '',
  testSkip: '',
  // useRegistry（对标 sqlmap 声明式 payload 体系）：false=检测器直接用 payloads/*.js 扁平数组（默认，零回归）；
  // true=检测器改用 PAYLOAD_REGISTRY 声明式注册表 + selectPayloadsForCtx 筛选（受 level/risk/testFilter/testSkip 控制）。
  useRegistry: false,
  // payload 前缀/后缀（对标 sqlmap --prefix / --suffix）：在注入点的原参数值前拼接 prefix、
  // 在 payload 后拼接 suffix，用于闭合引号/括号再注释掉尾部等注入场景。
  // 默认空串 = 不拼接，行为与历史一致；仅影响「被注入的参数值」，不影响基线请求。
  prefix: '',
  suffix: '',
  // 布尔盲注二级判据：组间稳定差异（[P0-FIX 2026-09-10] 布尔通道系统性漏报根治）。
  // 默认开启。根因：现代页面真假差异常仅占全文 5~15%，假值页被 _similar 判成「≈基线」→
  // 原判据「假≠基线」恒假 → 布尔通道失效。稳定差异判据不依赖「假≠基线」，而是要求真组/假组
  // 内部各自稳定、且真假差异片段可复现（所有真样本一致、所有假样本一致）。随机 nonce/时间戳因组内
  // 不自相似被排除 → 误报率保持 0；差异片段本身是 8+ 位数字（时间戳/计数器）按 numericNormalized 判无效。
  // 仅当原判据失效且真/假确有差异时进入，不改原判定逻辑，零回归。设为 false 关闭（回落历史行为）。
  boolStableDiff: true,
  // 组间稳定差异采样次数（真/假各 N 个）：N=2~3 足矣（组内一致性 2 即可证伪随机 nonce；
  // 3 更稳）。legacy 路径（blindRobust 关闭）会补足到该样本数（额外 ~2 请求/对），robust 路径复用已采样数组零额外请求。
  boolStableDiffSamples: 3,
  timeThresholdMs: 1500, // 时间盲注判定阈值（ms）
  timeBlindSamples: 5, // 时间盲注判定所需稳定采样次数（3→5：提升抖动目标下的判定稳健性；请求量小幅上升）
  timeBlindSleepSec: 2, // 时间盲注 sleep 时长（秒）：「探测/提取分离」前的共用基准（P2-P5）。
  // 默认 2 与历史行为一致；显式配置 timeProbeSleepSec / timeExtractSleepSec 可分别压低探测墙钟 /
  // 抬高提取可靠性，二者均未配置时回退本值（零回归）。
  // 时间盲注「最小可行 sleep 标定」（T4，对标 sqlmap 时间盲注优化）：确认注入后先试小 sleep（1s 起），
  // 用「恒真条件」实测该 sleep 耗时能否稳定超过判定阈值，命中用小的降低单点墙钟；未命中逐步加大并回退
  // timeExtractSleepSec（未配置回退 timeBlindSleepSec）。默认 false（关闭标定，直接沿用提取 sleep，与现状一致），
  // true 为 opt-in 开启。
  timeBlindCalibrate: false,
  timeBlindCalibrateMin: 1, // 标定最小 sleep 值（秒）：仅 timeBlindCalibrate=true 时生效
  // 时间盲注探测/提取 sleep 分离（P2-P8，对标 sqlmap 探测-提取两阶段参数化）：
  // timeProbeSleepSec=探测阶段（TimeBlindDetector 检测）sleep，可用较短时长（如 1s）降低单点检测墙钟；
  // timeExtractSleepSec=提取阶段（Extractor.extractTime 二分）sleep，用标准时长保证时间判定阈值可靠。
  // 默认 null=回退 timeBlindSleepSec（与现状一致，零回归）；显式配置才生效。
  timeProbeSleepSec: null,
  timeExtractSleepSec: null,
  maxColumnsGuess: 50, // UNION 猜测列数上限
  // 响应相似度锚点（对标 sqlmap --string / --not-string）：有锚点时检测器优先用锚点判定真/假页面，
  // 不再依赖对动态内容敏感的相似度比对。默认 null=不启用（回落分块比对，保持现状）。
  matchString: null, // 真页面必含文本
  notString: null, // 假页面必含文本
  // 响应匹配多指标（对标 sqlmap --text-only / --code / --regexp / --titles）：用户显式配置时优先用其
  // 判定真/假（真≠假即信号），未配置回退 blindRobust 统计判定 + 分块比对（默认路径不变）。
  matchText: false, // --text-only：剥标签后真/假纯文本不一致即信号（false=关闭）
  matchCode: null, // --code：真/假状态码不同即信号；可指定 { true:200, false:500 } 精确期望（null=关闭）
  matchRegexp: null, // --regexp：真响应命中、假响应不命中（或反之）即信号（null=关闭）
  trueRegexp: null, // 真响应需命中的正则（与 falseRegexp 组合，或单独使用）
  falseRegexp: null, // 假响应需命中的正则
  matchTitle: false, // --titles：真/假 <title> 不同即信号（false=关闭）
  // 自动动态块识别（深化 chunkedSimilar）：对同一注入点多次基线采样识别内容变化的动态块，
  // 后续相似度比对自动排除这些动态块。对标 sqlmap 默认即做动态内容感知（--string/--not-string
  // 之外的自动方式）；默认 true 仅复用已采样的基线做分块哈希比对，不额外增加基线采样请求。
  autoDynamicBlock: true,
  // 参数预筛选（P2-P1）：完整检测前对每个注入点发 1-2 个廉价探测（单引号报错 + 时间向量），
  // 明显无注入迹象的参数点直接跳过完整检测（省 50-75% 请求）。保守：任一探测有信号即保留。
  // 默认开启；config.prefilter !== false 时生效；不影响报告 point 列表。
  prefilter: true,
  // 静态参数跳过（对标 sqlmap --skip-static，opt-in）：开启后对多参数目标做两层廉价预筛——
  //   a) 同值去重：原始值完全相同的参数只测第一个（零请求成本）；
  //   b) 哨兵探测：每参数发 1 次明显不同的哨兵值请求（数字 +1001 / 字符串加 _sst 后缀），
  //      与基线响应比对（状态码 + 长度 + 规范化正文全部一致且哨兵值未回显）→ 判定静态参数跳过检测。
  // 每点成本 1 请求，换 46+ 请求/点的完整检测预算；判定保守，任一维度有差异/探测失败照常检测。
  // 默认 false（关闭 = 零行为变化）；精确标记点（* 指定）不参与跳过。
  skipStatic: false,
  // [P1-PERF 2026-09-08 实战批次] 输入校验型目标的「可证安全跳过」（默认开启）：
  // 针对单参数目标（prefilterSinglePoint 管不到的那一类）：基线正常页 + 单引号 4xx +
  // 良性非法值与两路恒真串探针同构被拒且无 SQL 报错签名 → 判定参数在进 SQL 前已被白名单拦住，
  // 跳过 200+ 请求的完整检测（改为 5 请求）。判据比「报错页相同」强：能排除「有洞但异常被吞」。
  // 保守线：任一探测失败/差异/含报错签名 → 保留完整检测。config.validationSkip=false 可关。
  validationSkip: true,
  // [P0-SEC 2026-09-08] 交付型报告的 PoC 凭据脱敏：默认 false（PoC 要能复制即跑）。
  // 报告文件会随邮件/IM 流通：若担心测试者会话凭据随报告外流，置 true 后
  // Cookie/Authorization/X-Api-Token 等头在 curl/raw/headers 三处统一打码。
  pocRedactAuth: false,
  // [P0-SEC 2026-09-08] 授权范围（渗透作战第一红线）：空数组=不启用；非空时条目形如
  // 'example.com'（含子域）/ '=example.com'（仅裸域）/ '10.0.0.0/8' / 'https://a.example.com/portal'。
  // 启用后：目标 URL、safeUrl、二阶触发页、以及每一跳重定向目标均逐次校验，越界直接拒发。
  scope: [],
  // [perf-FIX 2026-09-07] 单点目标 opt-in 预筛选：默认关（零回归）；本轮显式写进 defaults，
  // 以便前端/CLI 发现与 configWhitelist 守卫覆盖（此前只在 scanRoutes 透传链里，无文档入口）。
  prefilterSinglePoint: false,

  // [P0 2026-09-09 实战批次] 失效值替换（对标 sqlmap --invalid-bignum/--invalid-logical/--invalid-string）：
  // 布尔盲注的「有效值」前缀替换为随机大数/恒真逻辑式/随机串，规避缓存页/静态页噪声
  // （真实站点上布尔盲注最常见的失败原因）。null=不替换（默认，零回归）。
  invalidValue: null,
  // [P0 2026-09-09 实战批次] 已知注入点直通：{ param, quote?, paren?, techniques? }。
  // 手工确认的可注入参数跳过预筛选与闭合探测（闭合形态由使用者给定），techniques 限定技术位。
  knownPoint: null,

  // 提取
  enableExtract: true, // 拖库开关（默认开，前端二次确认）
  excludeSysdbs: true, // 系统库过滤（对标 sqlmap --exclude-sysdbs；false 时拖库含系统库）
  dumpRowLimit: 100, // 单次拖库单表行数上限
  // [sqlmap 对标] 行范围导出（--start/--stop）：dumpStart=起始行偏移（0 起），dumpStop=结束行（绝对行号，0=不限）
  dumpStart: 0,
  dumpStop: 0,
  // [sqlmap 对标] 保活探测（--safe-url/--safe-freq）：每 safeFreq 个扫描请求触发一次对 safeUrl 的 GET，
  // [sqlmap 对标 2026-09-14] --csrf-url/--csrf-token/--csrf-method：CSRF 会话层。
  // csrfUrl 配置后：扫描启动取页提取 token，每请求自动携带（GET 入 query / POST 入表单 data），
  // 每 csrfRefreshFreq 请求刷新一次（token 一次性场景）。自动探测常见 hidden input 名
  // （csrf_token/_csrf/token/authenticity_token 等），显式 csrfTokenName 优先。
  csrfUrl: '',
  csrfTokenName: '',
  csrfMethod: 'GET',
  csrfRefreshFreq: 50,
  // 维持目标应用会话/防空闲锁死。safeUrl 为空时关闭。SSRF 校验由 HttpClient.request 逐请求执行。
  safeUrl: '',
  safeFreq: 0,
  extractConcurrency: 4, // 盲注二分提取并发度（多字符并行二分提速；受目标限速/WAF 敏感度约束）
  dumpConcurrency: 4, // 多表拖库并发度（同库内表级并发，受目标限速/WAF 敏感度约束）
  dumpDatabaseConcurrency: 2, // 跨库拖库并发度（库级并发；默认 2 较保守，受目标限速/WAF 敏感度约束）
  // 盲注常见值缓存（对标 sqlmap --predict-output）：同目标（+同 scanId）内 version()/database()/current_user
  // 等常见表达式的二分提取结果跨注入点复用，命中后直接返回，减少重复二分请求。false 关闭缓存。
  predictOutput: true,

  // WAF 规避（默认全部关闭，开启会改变请求形态与时序）
  wafEvasion: {
    randomUA: false, // 随机 User-Agent 池
    jitterMs: 0, // 请求间随机延时（毫秒），0 表示不延时
    obfuscate: false, // Payload 混淆（大小写随机化 + 内联注释分割）
    // 可插拔 tamper 链式体系（对标 sqlmap --tamper）。enabled 优先于 obfuscate。
    // intensity 仅前端语义 / 报告审计用，引擎 obfuscateWithConfig 不消费。
    tamper: { enabled: false, plugins: [], intensity: 'medium' },
    // [P0-FIX 2026-09-10 实战实测] 拦截证据驱动的自适应重跑（默认开）：
    // 真实站点基线响应永远干净，WAF 厂商指纹识别率天然为 0 → autoRetry 永不触发。
    // 本开关改为「本次扫描出现 403/406/429/503/拦截页 > 0 次且有未命中点」即触发，
    // 用算子替换族（OR→|| / AND→&& / =→RLIKE）重跑一轮。实测把关键词黑名单 WAF 场景
    // 从 0 检出拉到 boolean 命中。关闭：wafEvasion.adaptiveOnBlock=false。
    adaptiveOnBlock: true,
    // [P1-FIX 2026-09-10] 关键词「静默过滤」型绕过重跑（error-only 点 → 套插入式双写链）。
    // 默认开启：实测靶场 bl（删 union/select/and/or/--）由 `[error]` 提升为 `[error,boolean]`，
    // 依赖三项使能——重跑前重探闭合前缀、链验证只认硬拦截、候选纳入 error-only 点
    // （详见 docs/实战渗透实测评估-2026-09-10.md F8）。
    // 仅对「error 命中但数据面通道全 miss 且出现过 5xx」的点触发，安全点不受影响。
    filterAdaptive: true,
    // WAF 自动 tamper 重跑（对标 sqlmap --check-waf 自动套 tamper）：高置信识别出 WAF 且注入点
    // 未命中时，自动套 wafRecommend 推荐链对未命中点重跑一轮快速层（union/error/boolean）。
    // 默认 false 保持现状（仅显式开启才自动兜底）；节流：仅高置信 WAF + 未命中点 + 每点最多重跑一轮。
    autoRetry: false,
  },

  // OOB 带外通道（无回显盲注兜底）。默认关闭，避免意外出站带外请求。
  oob: {
    enabled: false, // 总开关（即使 techniques 含 oob，也需此处开启接收端才启动）
    callbackBase: '127.0.0.1:8899', // 接收端可达地址（真实环境换成自有域名）
    httpPort: 8899, // 接收端独立监听端口（非引擎 4567）
    timeoutMs: 5000, // 轮询等待回连的上限
    // DNS OOB 通道（对标 sqlmap --dns-domain）：通过 DNS 查询外带数据
    // DNS 比 HTTP 更可靠（防火墙几乎不拦截 DNS 出站）
    dnsOob: false, // 总开关：开启后使用 DNS 通道替代 HTTP 通道
    dnsDomain: '', // DNS 回调域名（如 attacker.com），token 放在子域名中
    dnsPort: 53, // DNS 服务器监听端口（默认 53，需 root/管理员权限）
  },

  // 检测技术选择（默认 4 类全选，堆叠/OOB 不勾选 opt-in 以保兼容）
  techniques: ['union', 'error', 'boolean', 'time'],

  // 表单爬取（复杂表单 / 反 CSRF 自动处理）。默认关闭，避免误触发提交副作用。
  crawlForms: false,
  // 站内链接爬取深度（对标 sqlmap --crawl=<depth>）：0=关闭，1-3=爬取深度。
  // 爬虫从目标页递归发现同域链接，将各页 query 参数并入注入点集合。
  // 默认关闭，避免扩大攻击面造成非预期请求；仅对已授权目标显式开启。
  crawlDepth: 0,

  // 代理 / 认证：httpClient 已完整实现（buildProxyAgent 支持 http/https/socks5/socks5h/socks4/socks4a；
  // mergeAuthHeaders 支持 basic/cookie/自定义头）。
  // 默认 null = 不走代理、无认证；经统一 HttpClient 透传，所有检测器/提取器均生效。
  proxy: null, // 代理地址（http:// 或 socks5://），默认不走代理；为空且 trustProxyEnv=true 时回退 *PROXY 环境变量
  auth: null, // 认证配置 { basic:{username,password}, digest:{username,password}, type, cookie, headers }，默认无认证
  dbms: null, // [对标 sqlmap --dbms] 用户强制指定 DBMS（跳过指纹识别），如 'MySQL'/'PostgreSQL'

  // ── [P1-FIX 2026-09-08 ①] 自签 / 内网 CA 目标（实战必踩）────────────────────────
  // 内网与测试系统绝大多数用自签证书。此前全仓无 rejectUnauthorized 配置：
  // DEPTH_ZERO_SELF_SIGNED_CERT / UNABLE_TO_VERIFY_LEAF_SIGNATURE / ERR_TLS_CERT_ALTNAME_INVALID
  // 被列进 NON_RETRYABLE_CODES → 一次 TLS 握手都建不起来就快速失败，扫描结果表现为「扫不出」
  // 而不是「报错」。insecureTls=true 时 HttpClient 改用**专用** httpsAgent（rejectUnauthorized:false，
  // 按 {insecure,keepAlive} 组合缓存），不污染模块级共享 Agent 池，也不影响其它扫描。
  // 代价：失去中间人防护 —— 开启时引擎 logger.warn 一次，并在每个响应 __meta.insecureTls=true
  // 标记，报告必须注明「本次扫描未校验证书」。
  insecureTls: false,

  // ── [P1-FIX 2026-09-08 ②] 代理环境变量信任（对标 curl / sqlmap）─────────────────
  // true（默认）：config.proxy 为空时按 HTTPS_PROXY → https_proxy → HTTP_PROXY → http_proxy →
  // ALL_PROXY 顺序取代理，NO_PROXY 命中目标 host（支持 * 与逗号分隔域名后缀）时不走代理；
  // 命中环境变量代理会 logger.info 明示（opsec：必须知道流量走了哪）。
  // false：完全忽略环境变量（仅认显式配置）—— 需要在有全局代理的机器上「直连扫描」时用它关掉。
  trustProxyEnv: true,

  // ── [P0-FIX 2026-09-09] 本地/私网地址默认绕过环境变量代理 ──────────────────────
  // 背景（实测）：装了 Clash/公司代理（HTTP_PROXY 非空、NO_PROXY 为空）的机器上扫 127.0.0.1 /
  // 内网靶场时，流量被送进代理；代理对 POST 等非 GET 方法或本地地址失败时，该注入点被记为
  // 「已检测、0 漏洞」——同一份代码在有无代理时结论不同（19/19 ↔ 18/19 的二阶假阴性）。
  // true（默认）：环境变量代理不用于 localhost / 127.0.0.0/8 / ::1 / 10/8 / 172.16/12 /
  //   192.168/16 / 169.254/16 等本地与私网目标（curl 同语义：默认不代理 localhost）。
  // false：完全沿用环境变量（需要「连本地也强制走 Burp」时用 config.proxy 显式指定，而非关此开关）。
  // 注意：显式 config.proxy 属用户明确意图，不受本开关影响（要连本地 Burp 就显式配）。
  proxyBypassLocal: true,

  // ── [P1-FIX 2026-09-08 ②] 代理模式下的目标校验语义 ─────────────────────────────
  // 'auto'（默认）：已配置代理时跳过本地 DNS 解析与「严格层」私网判定 —— 域名解析发生在代理侧，
  // 本地解析失败即 fail-closed 抛错会让「目标域名只能经 Burp/跳板解析」的整条请求路径不可用；
  // 但**无条件保留** 0.0.0.0/8、169.254.0.0/16（云元数据）、组播/保留段的 IP 字面量拒绝，并在
  // 首次放行时 logger.warn 一次（目标校验已下放至代理，请确认代理为受控出口）。
  // 'off'：行为与历史完全一致（本地解析 + 全量 SSRF 判定），引擎暴露给不可信调用者时用它会更保守。
  ssrfViaProxy: 'auto',

  // [P1-FIX 2026-09-08 ④] 响应体上限（无 defaults 键，由环境变量控制，此处仅说明以免配置语义漂移）：
  // SSRF_MAX_BODY_MB 默认由 5 提到 10 —— 真实站点「首页 + 静态资源」常 1-3MB，带大表格的列表页
  // 直接超限；超限在 undici 通道是**静默截断**（检测器只看 data/status → 当成「内容相同/不同」而漏检）。
  // 现在两条通道统一在响应上挂 __meta.truncated / __meta.bodyBytes 并 warn 一次；提取路径仍 50MB
  // （EXTRACT_MAX_BODY_MB）不变。

  // 二阶注入检测（Second-order / Stored SQLi）：先注入进库、别处读取触发。
  // 默认关闭：开启=对目标发起真实写请求（POST 注册/评论/资料），仅已授权目标显式开启。
  secondOrder: {
    enabled: false, // 总开关（默认关；开启即代表将对目标发起真实写请求）
    triggerUrls: [], // 候选触发页 URL 列表（仅 http/https），可多个；为空则不跑
    refreshCsrf: true, // 存储前是否 GET actionUrl 重抓 CSRF token（应对单次 token 失效）
    negativeControl: true, // 是否做"存良性值→读触发页"阴性对照（多一次写，提高判定置信）
    oobTrigger: false, // 扩展点：触发判定是否借用 OOB（本期未实现，仅预留开关）
    // [sqlmap 对标] --second-url：写入与读取分离的二阶注入。secondUrl 非空时，
    // 触发阶段的读取请求发往 secondUrl 而非原始 triggerUrl（用于"注入存入 A 页面、
    // 回显在 B 页面"的场景）。secondMethod 默认 GET；secondData 为可选请求体。
    secondUrl: '', // 读取触发页 URL（空=沿用 triggerUrl，保持现有行为）
    secondMethod: 'GET', // 读取触发页的 HTTP 方法（默认 GET；[P0-FIX 2026-09-09] 走白名单归一化，非法值回落 GET）
    secondData: null, // 读取触发页的请求体（可选，POST 场景使用）
    // [P0-FIX 2026-09-09] 触发页读取方法（此前硬编码 GET 的那处：_refreshCsrf 取 actionUrl 的页面）。
    // 默认 GET（零回归）；同样只接受 HTTP 方法白名单，非法值回落 GET。
    triggerMethod: 'GET',
    // [P0-FIX 2026-09-09] 二阶「写请求」确认位：productionMode=true 时，非幂等 method（POST/PUT/PATCH/DELETE）
    // 与触发页写请求都需要 allowWrites===true 才放行，否则跳过并记入 report.summary.constraints。
    // 为什么必须有：二阶检测天然包含「真实写入」（存储阶段 POST 表单），一旦打到生产库就是脏数据 +
    // 业务侧可见的记录（评论/工单/订单）。开关的语义必须是「我知道我在写」，而不是「我勾了二阶就全放开」。
    allowWrites: false,
  },

  // [sqlmap 对标] --null-connection：盲注检测使用 HEAD 请求（无响应体传输），
  // 按状态码 + Content-Length 头判定真假，大幅降低带宽开销。默认关闭。
  nullConnection: false,

  // [sqlmap 对标] --delay：每次请求间的固定延时（秒）。默认 0=不延时。
  // 对标 sqlmap --delay=<seconds>，用于降低请求速率、规避 WAF 频率限制。
  delay: 0,

  // [sqlmap 对标] --reqrate：每秒请求数上限（0=不限速，沿用 ratePerSec 默认值）。
  // 设置 >0 时覆盖 ratePerSec 作为 TokenBucket 速率。
  reqRate: 0,

  // [sqlmap 对标] --max-requests：单次扫描的请求总数上限（0=不限）。
  // 达到上限后 httpClient 拒绝新请求，防止扫描失控。
  maxReq: 0,

  // [P2-5 对标 sqlmap] --force-ssl：http:// 目标强制升级 https（httpClient.request 消费改写）。
  forceSsl: false,

  // [P2-5 对标 sqlmap] --ignore-redirects：不跟随 3xx 跳转，直接返回跳转响应。
  // httpClient 跳转上限置 0；注意目标上行 302（如登录跳转）会直接暴露 3xx。
  ignoreRedirects: false,

  // [P2-5 对标 sqlmap] --hpp：注入参数 query+body 双份提交（仅 GET query 注入点、仅注入请求），
  // WAF 绕过形态（buildInjectionRequest 消费）。
  hpp: false,

  // [G4 对标 sqlmap --parse-errors：opt-in] 开启后 ErrorDetector 解析错误响应原文
  // 与 SQL 上下文片段，写进 result.errorDetail（证据链/AI 报告消费）。默认关闭零行为变化。
  parseErrors: false,

  // [P1-FIX 2026-09-09] 绕过查询结果缓存（对标 sqlmap --fresh-queries）：面板有开关、scanRunner 也读，
  // 但不能只靠「传了才有」——放进 defaults 才能让「defaults ↔ 白名单 ↔ 透传」双向守卫真的管到它。
  freshQueries: false,

  // [sqlmap 对标] 主动 WAF 探测：被动指纹识别无果时，主动发送 WAF 触发 payload
  // 观察拦截响应以识别 WAF 厂商。默认关闭（仅被动识别，零额外发包）。
  activeWafProbe: false,

  // 盲注判定鲁棒性（统计判定增强）：升级 Boolean/Time 检测器内部 detect，不新增检测器类。
  // 默认开启：enabled:true 走统计判定分支（基线分布感知 + 一致率 + 显著性检验）；false 退化为 legacy 逻辑。
  // 说明：v1 实现为 opt-in(false)，经评审与用户确认后改为默认开——统计判定抗抖动/动态内容误报，
  // 且 legacy 路径（双轨）仍完整保留，设 enabled:false 即零成本回退。开启后请求量约 2.8×，稳定/可控目标建议保持开启。
  blindRobust: {
    enabled: true, // 总开关（默认开：统计判定分支；false → legacy 零回归）
    booleanSamples: 3, // 每个真假模板对重复采样次数（一致率分母）
    baselineSamples: 5, // 基线采样次数（Boolean 与 Time 共用，构成基线指纹集/分布）
    timeConfidenceZ: 2, // Time 阈值 Z-score 倍数：threshold = μ + z·σ（σ>0 时）
    minStableRatio: 0.66, // 一致率阈值：Boolean 三一致率 / Time 稳定率 均需 ≥ 此值
    booleanSignificanceZ: 1.645, // 布尔显著性单侧 z 临界（95%）：false 偏离基线需显著超过自然抖动率才判定
    // —— 阈值自适应（v3）：根据目标实测噪声动态标定门槛，替代固定 minStableRatio ——
    adaptive: true, // 总开关：开启后布尔一致率门槛/时间绝对下限随基线噪声自动调整（默认开）
    adaptiveHeadroom: 0.3, // 布尔门槛 = clamp(基线噪声 + 此余量, floor, cap)
    minStableRatioFloor: 0.66, // 自适应门槛下限（稳定目标仍保持严格，控误报）
    minStableRatioCap: 0.95, // 自适应门槛上限（抖动目标要求更清晰的信号，防噪声碰巧达标）
    adaptiveTimeFloorScale: 2, // 时间盲注绝对下限放宽系数：floor = absFloor + scale·σ
    concurrency: 4, // 盲注采样并发度（基线 + 真假对重复采样用，抵消串行开销；与顶层 concurrency 同源但独立可调）
    extractVerify: true, // 盲注提取二次确认（P2-P2/P2-P7）：每字节收敛后对最终值发 1 次等值验证请求，
    // 不一致则回退重测（最多 2 次）；提取完成后另发 1 次「完整值整体投票复验」（对标 sqlmap 关键值重测，
    // 用布尔条件 (expr)='<完整值>' 直接比对，失败标记低置信并注明）。false 关闭（与旧行为一致）
  },
};

export default defaults;
