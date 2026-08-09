// 引擎默认参数（集中维护，前后端/双形态需同步修改）
export const defaults = {
  // 网络
  port: 4567, // 引擎监听端口
  timeoutMs: 10000, // 单请求超时
  retry: 2, // 失败重试次数
  ratePerSec: 3, // 令牌桶限速（请求/秒）
  requestDelayMs: 0, // 固定请求间延时（毫秒，对标 sqlmap --delay）；0 = 不延时。与 jitter 随机延时正交、叠加生效。
  // HTTP 参数污染（对标 sqlmap --hpp）：对 URL 注入点把参数展开为同名多值（原始值在前、注入值在后）。
  // 绕过只检查"首个参数值"的 WAF/IPS——后端（如 ASP.NET/PHP 部分配置取最后值或逗号拼接）执行注入值，
  // 而 WAF 看到的首值仍是原始合法值，从而放行。默认关闭（hpp:false）。
  hpp: false,
  // 连接复用（对标 sqlmap --keep-alive / --no-keep-alive）：true=复用 TCP 连接（默认，降延迟/更隐蔽）；
  // false=每次请求新连接（Connection: close），部分 WAF/速率限制对"连接级指纹"敏感时更有用。
  keepAlive: true,

  // 调度
  concurrency: 4, // 并发检测线程数

  // 检测
  timeSec: 2, // 时间盲注注入的 SLEEP 触发时长（秒，对标 sqlmap --time-sec）。默认 2 保零回归。
  timeThresholdMs: 1500, // 时间盲注"绝对下限"历史基准（ms）；现由 sleep 派生：absFloor = max(0.3, sleep-0.5)。
  timeBlindSamples: 3, // 时间盲注判定所需稳定采样次数
  maxColumnsGuess: 50, // UNION 猜测列数上限

  // 提取
  enableExtract: true, // 拖库开关（默认开，前端二次确认）
  dumpRowLimit: 100, // 单次拖库单表行数上限
  extractConcurrency: 4, // 盲注二分提取并发度（多字符并行二分提速；受目标限速/WAF 敏感度约束）
  dumpConcurrency: 4, // 多表拖库并发度（同库内表级并发，受目标限速/WAF 敏感度约束）
  dumpDatabaseConcurrency: 2, // 跨库拖库并发度（库级并发；默认 2 较保守，受目标限速/WAF 敏感度约束）

  // WAF 规避（默认全部关闭，开启会改变请求形态与时序）
  wafEvasion: {
    randomUA: false, // 随机 User-Agent 池
    jitterMs: 0, // 请求间随机延时（毫秒），0 表示不延时
    obfuscate: false, // Payload 混淆（大小写随机化 + 内联注释分割）
    // 可插拔 tamper 链式体系（对标 sqlmap --tamper）。enabled 优先于 obfuscate。
    // intensity 仅前端语义 / 报告审计用，引擎 obfuscateWithConfig 不消费。
    tamper: { enabled: false, plugins: [], intensity: 'medium' },
  },

  // OOB 带外通道（无回显盲注兜底）。默认关闭，避免意外出站带外请求。
  oob: {
    enabled: false, // 总开关（即使 techniques 含 oob，也需此处开启接收端才启动）
    callbackBase: '127.0.0.1:8899', // 接收端可达地址（真实环境换成自有域名）
    httpPort: 8899, // 接收端独立监听端口（非引擎 4567）
    timeoutMs: 5000, // 轮询等待回连的上限
  },

  // 检测技术选择（默认 4 类全选，堆叠/OOB 不勾选 opt-in 以保兼容）
  techniques: ['union', 'error', 'boolean', 'time'],

  // 风险等级（对标 sqlmap --risk，1-3）。默认 1（最保守）：二阶/堆查询/OOB 等高风险技术
  // 需提升 risk 才允许（见 src/engine/riskGate.js 的 RISK_MIN）。CLI/API 入口会做门控校验。
  risk: 1,

  // 等级（对标 sqlmap --level，1-5）。控制「测哪些位置」的注入点扩展：
  // 1=仅 URL/Body（默认）；2=+Cookie；3=+显式 Header 与自动 User-Agent/Referer 头。
  // 与 --risk（测多危险）正交，二者共同构成 sqlmap 两大核心旋钮。
  level: 1,

  // 自定义检测判定锚点（对标 sqlmap --string/--not-string/--regexp/--code）。
  // 默认全 null（不激活）：布尔/时间盲注走统计判定。任一字段非空即激活确定性判定，
  // 作为统计判定的补充/覆盖，提升动态内容/定制 404/特殊状态码目标的检出可控性。
  detectMatch: { string: null, notString: null, regexp: null, code: null },

  // 表单爬取（复杂表单 / 反 CSRF 自动处理）。默认关闭，避免误触发提交副作用。
  crawlForms: false,

  // 预留字段（首版未实现）
  proxy: null, // 代理地址（http:// 或 socks5://），默认不走代理
  auth: null, // 认证配置 { basic, cookie, headers }，默认无认证

  // 安全间隔探测（对标 sqlmap --safe-url / --safe-freq）：周期性访问"确信无注入副作用"的
  // 安全 URL，对比初始基线；一旦响应偏离（被 WAF/IPS 拦截、会话失效、限流），立即告警，
  // 提示当前批次结果可能失真。默认关闭（safeUrl 为空），开启需显式传入安全 URL。
  safeProbe: {
    url: null, // 安全 URL（确信不含注入副作用、始终应返回稳定内容的页面）
    freq: 0, // 每发多少次真实请求穿插一次安全探测；0 = 关闭（不探测）
  },

  // 二阶注入检测（Second-order / Stored SQLi）：先注入进库、别处读取触发。
  // 默认关闭：开启=对目标发起真实写请求（POST 注册/评论/资料），仅已授权目标显式开启。
  secondOrder: {
    enabled: false, // 总开关（默认关；开启即代表将对目标发起真实写请求）
    triggerUrls: [], // 候选触发页 URL 列表（仅 http/https），可多个；为空则不跑
    autoDiscover: false, // 触发页自动发现：enabled 且未手填 triggerUrls 时，从目标页链接发现并经哨兵回显确认
    refreshCsrf: true, // 存储前是否 GET actionUrl 重抓 CSRF token（应对单次 token 失效）
    negativeControl: true, // 是否做"存良性值→读触发页"阴性对照（多一次写，提高判定置信）
    oobTrigger: false, // 扩展点：触发判定是否借用 OOB（本期未实现，仅预留开关）
    manualStorePoints: [], // 手动指定存储点参数名列表（逗号/换行分隔经前端解析为数组）；与启发式 isStorePoint 取并集，命中点的 isStorePoint 运行时置真
  },

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
  },
};

export default defaults;
