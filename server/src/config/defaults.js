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
  disableKeepAlive: false,
  // HTTP/2 支持（对标 sqlmap --http2）：开启后爬虫/页面取页路径走 undici（ALPN 协商 h2 优先，
  // 不支持则自动降级 HTTP/1.1）。默认关闭——盲注提取等主请求路径仍走 axios HTTP/1.1（零风险）。
  http2: false,
  // 令牌桶限速（请求/秒）。历史默认 3 req/s 会锁死并发收益（并发池=4 时吞吐恒等于 3），
  // 对标 sqlmap --delay=0 默认无限速，放开到 50 让吞吐由网络 RTT 决定；仍保留用户可调
  // （前端限速设置经 ScanManager 按 scanId 注入 HttpClient 独立桶，真正生效）。
  ratePerSec: 50,

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
  //   risk 1：仅 union/error/boolean（安全，无写请求/无长时间等待）
  //   risk 2：含 time/stacked/oob（默认，与旧行为一致）
  //   risk 3：额外 OR 变体布尔测试（由 Detector 层消费 risk 字段）
  level: 1,
  risk: 2,
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

  // 提取
  enableExtract: true, // 拖库开关（默认开，前端二次确认）
  excludeSysdbs: true, // 系统库过滤（对标 sqlmap --exclude-sysdbs；false 时拖库含系统库）
  dumpRowLimit: 100, // 单次拖库单表行数上限
  // [sqlmap 对标] 行范围导出（--start/--stop）：dumpStart=起始行偏移（0 起），dumpStop=结束行（绝对行号，0=不限）
  dumpStart: 0,
  dumpStop: 0,
  // [sqlmap 对标] 保活探测（--safe-url/--safe-freq）：每 safeFreq 个扫描请求触发一次对 safeUrl 的 GET，
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

  // 代理 / 认证：httpClient 已完整实现（buildProxyAgent 支持 http/https/socks5；mergeAuthHeaders 支持 basic/cookie/自定义头）。
  // 默认 null = 不走代理、无认证；经统一 HttpClient 透传，所有检测器/提取器均生效。
  proxy: null, // 代理地址（http:// 或 socks5://），默认不走代理
  auth: null, // 认证配置 { basic:{username,password}, digest:{username,password}, type, cookie, headers }，默认无认证
  dbms: null, // [对标 sqlmap --dbms] 用户强制指定 DBMS（跳过指纹识别），如 'MySQL'/'PostgreSQL'

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
    secondMethod: 'GET', // 读取触发页的 HTTP 方法（默认 GET）
    secondData: null, // 读取触发页的请求体（可选，POST 场景使用）
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
