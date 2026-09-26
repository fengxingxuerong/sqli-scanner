// 前后端共享类型定义（镜像后端 schema，保持契约一致）

/** 请求方法 */
export type MethodType = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** 注入点位置 */
export type InjectionLocation = 'url' | 'body' | 'cookie' | 'header';

/** 检测技术 */
export type TechniqueType = 'union' | 'error' | 'boolean' | 'time' | 'stacked' | 'oob' | 'inline' | 'second_order';

/** 支持的数据库 */
export type DbmsType = 'MySQL' | 'PostgreSQL' | 'SQLite' | 'SQL Server' | 'Oracle' | 'TiDB' | 'DM8' | 'ClickHouse' | 'DB2' | 'Sybase' | 'Firebird' | 'Informix' | 'H2';

/** 风险等级 */
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** 扫描状态 */
export type ScanStatus = 'pending' | 'running' | 'paused' | 'completed' | 'stopped' | 'error';

/** 扫描引擎 */
export type EngineType = 'builtin' | 'sqlmap';

/** sqlmap 专属配置（仅高级模式启用后端 sqlmap 时使用） */
export interface SqlmapConfig {
  level: number; // 检测等级 1-5（越高越全，越慢）
  risk: number; // 风险等级 1-3（越高越可能触发破坏性）
  techniques: string[]; // 技术字母：B/E/U/S/T/Q（对应布尔/报错/联合/堆叠/时间/查询）
  tamper: string[]; // tamper 脚本名（WAF 绕过）
  dbms: string | null; // 指定后端 DBMS（如 'mysql'），null 为自动识别
  threads: number; // 并发线程 1-10
  dump: boolean; // 拖库（破坏性，需确认）
  osShell: boolean; // OS Shell（破坏性，需确认）
  fileRead: string | null; // 读文件（破坏性，需确认）
  // ── 请求控制（P0-U2 新增，透传给 sqlmap 桥，与 buildArgs 契约对齐）──
  proxy: string | null; // 代理地址（http/https/socks5://host:port），透传 --proxy；留空直连
  timeoutMs: number; // 单请求超时（毫秒），透传 --timeout；sqlmap 模式复用内置面板同单位语义
  retry: number; // 请求重试次数，透传 --retries（0 表示不重试）
  randomUA: boolean; // 随机 User-Agent 池，透传 --random-agent
  // ── 对标 sqlmap 高级参数 ──
  flushSession?: boolean; // 清会话缓存重测（--flush-session）
  freshQueries?: boolean; // 绕过查询结果缓存（--fresh-queries）
  unionCols?: string | null; // UNION 探测列数范围（--union-cols，如 "1-15"）
  unionChar?: string | null; // UNION SELECT 占位字符（--union-char，单字符 A-Za-z0-9）
  unionFrom?: string | null; // UNION SELECT 的 FROM 表（--union-from，表名，最多 128 字符）
  smart?: boolean; // 智能启发式（--smart，跳过非注入参数，默认 false）
  timeSec?: number | null; // 时间盲注秒数（--time-sec，1-60）
  ignoreCode?: number | null; // 忽略某 HTTP 状态码（--ignore-code）
  excludeSysdbs?: boolean; // 排除系统库（--exclude-sysdbs，默认 true）
  verbose?: number | null; // 日志详细度 0-6（-v）
  // ── 低优先级 WAF 规避参数 ──
  noCast?: boolean; // 禁止 CAST 包裹（--no-cast，防 CAST 触发 WAF）
  hex?: boolean; // 十六进制编码提取（--hex，盲注用 hex 替代字符二分）
  noEscape?: boolean; // 禁止字符串转义（--no-escape，payload 原样注入）
}

/** tamper 变换配置（对齐后端 wafEvasion.tamper） */
export interface TamperConfig {
  enabled: boolean; // 总开关，默认 false
  plugins: string[]; // 有序插件名数组（顺序=链式顺序），默认 []
  intensity: 'low' | 'medium' | 'high'; // 强度预设档，默认 'medium'（仅前端语义 / 报告审计）
}

/** tamper 清单项（GET /api/tampers 返回，与 TamperRegistry.list() 一致） */
export interface TamperInfo {
  name: string; // 插件名，须与 TamperRegistry 注册名严格一致
  description: string; // 中文/英文说明
}

/** WAF 指纹识别候选（后端 → 前端事件载荷片段） */
export interface WafCandidate {
  vendor: string; // 如 'Cloudflare' / 'ModSecurity'
  confidence: number; // 0~1
  evidence: string; // 命中依据（如 'header: cf-ray'）
}

/** WAF 推荐组合（仅建议，不自动套用） */
export interface WafSuggestion {
  vendor: string;
  plugins: string[]; // 推荐 tamper 插件名（有序）
  intensity?: 'low' | 'medium' | 'high';
}

/** waf_detected 事件载荷（后端识别到 WAF 时经 SSE 推送） */
export interface WafDetectedPayload {
  vendors: WafCandidate[]; // 识别到的 WAF 候选（按置信度降序）
  suggestions: WafSuggestion[]; // 推荐 tamper 组合（仅建议，不自动套用）
}

/** SSE 事件类型 */
export type EventType =
  | 'scan_started'
  | 'scan_phase' // 阶段提示（payload: { phase: string, message: string }）
  | 'http_request' // 请求日志（payload: { method, url, status, ms }）
  | 'point_discovered'
  | 'point_testing'
  | 'point_skipped' // resume 模式跳过已完成注入点（payload: { pointId, reason }）
  | 'detection_found'
  | 'extraction_progress'
  | 'scan_completed'
  | 'scan_stopped'
  | 'scan_paused' // [P0-FIX] 扫描暂停（payload: { scanId }）
  | 'scan_resumed' // 扫描恢复（payload: { scanId }）
  | 'scan_error'
  | 'sqlmap_log' // sqlmap 原始输出行（按级别着色）
  | 'sqlmap_vuln' // sqlmap 确认的注入点
  | 'waf_detected' // payload: { vendors: WafCandidate[]; suggestions: WafSuggestion[] }
  // ── [P0-FIX 2026-09-09] 结论可信度守卫（前端仅消费，不改引擎）──
  | 'scan_validity' // status!=='ok' 时推送的可信度摘要（payload 同 ScanValidity）
  | 'scan_validity_abort' // 守卫中止剩余注入点检测（payload: ScanValidity & { scanId }）
  | 'waf_block_policy'; // 拦截策略变更（payload: WafBlockPolicyPayload）

/** 结论可信度摘要（report.validity / report.summary.validity / scan_validity* 事件同构） */
export interface ScanValidity {
  status: 'ok' | 'blocked' | 'unreachable' | 'session_expired' | 'target_error';
  reliable: boolean; // false = 阴性结论（未检出）不成立，UI 必须显式提示
  reason: string; // 后端给出的一句话原因（中文，含实测数字）
  counts: {
    total: number; // 累计请求数
    failStreak: number; // 连续失败峰值（unreachable 判定依据）
    blockHits: number; // 窗口内拦截特征命中次数
    serverErr: number; // 窗口内 5xx 次数
    authLostHits: number; // 会话失效命中次数
  };
  blockRatio: number; // 拦截占比（0~1）
  suggestBackoffMs: number | null; // Retry-After 实测值（无则 null）
  inconclusivePoints: string[]; // 未完成有效检测的注入点 id
  advice: string; // 中文处置建议
}

/** waf_block_policy 事件载荷（拦截策略变更，仅提示不自动套用） */
export interface WafBlockPolicyPayload {
  action: 'none' | 'preferTamper' | 'pause';
  backoffMs: number | null;
  tamperHint: string[]; // 建议的 tamper 链（有序）
  reason: string; // 决策依据（中文）
}

/** 导出报告挂载的可复现 PoC 证据（仅导出路径生成；UI 拿不到时优雅降级） */
export interface VulnPoc {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  payload: string;
  curl: string; // 单行 curl（复制即跑）
  raw: string; // 原始 HTTP 报文（Burp / sqlmap -r 可导入）
  note: string;
  generatedAt: string;
}

/** 基础认证凭据（Basic Auth） */
export interface BasicCred {
  username: string;
  password: string;
}

/** 认证与自定义头配置 */
export interface AuthConfig {
  basic?: BasicCred; // Basic Auth 用户名/密码
  cookie?: string; // 自定义 Cookie（随每次请求发送）
  headers?: Record<string, string>; // 自定义 Header 键值对（随每次请求发送）
}

/** WAF 规避配置（三项独立开关，默认全关） */
export interface WafEvasionConfig {
  randomUA: boolean; // 随机 User-Agent 池
  jitterMs: number; // 请求间随机延时（毫秒），0 表示不延时
  obfuscate: boolean; // Payload 混淆（legacy，已被 tamper 体系取代）
  tamper: TamperConfig; // 可插拔 tamper 链式体系（对标 sqlmap --tamper）
}

/** 历史记录（持久化到 localStorage） */
export interface HistoryRecord {
  schemaVersion: number; // 存储结构版本，便于后续升级
  scanId: string;
  target: string; // 目标 URL（冗余存储，便于旧结构兼容展示）
  riskLevel: RiskLevel;
  finishedAt: string | null;
  report: ReportModel; // 完整报告快照（离线回溯用）
}

/** 扫描配置 */
// ── [2026-09-23 E2] 枚举 / 拖库动作族（对标 sqlmap --dbs/--tables/--dump/--dump-all/…）──
// 与引擎侧的契约形状（engine/extractScope.js:109 的 switch + ScanManager._extractByScope）：
// 只有 mode 是必填，其余按所选动作填。后端形状校验见 scanRoutes 的 sanitizeExtractScope
// （mode 白名单 + 数组去重/限长/限数量 + 拒控制字符；**不做字符集白名单**，因为引擎侧已 escSql）。
export type ExtractScopeMode =
  | 'dbs' | 'tables' | 'columns' | 'dump' | 'dumpAll'
  | 'commonTables' | 'commonColumns' | 'search'
  | 'currentDb' | 'currentUser' | 'hostname' | 'isDba'
  | 'users' | 'passwords' | 'schema' | 'privileges' | 'roles' | 'count';

export interface ExtractScopeConfig {
  mode: ExtractScopeMode;
  /** 目标数据库（多选）；留空 = 由引擎枚举 */
  dbs?: string[];
  /** 目标表（多选） */
  tables?: string[];
  /** 目标列（多选，仅 dump 用） */
  cols?: string[];
  /** search 模式的匹配关键字 */
  keyword?: string;
  /** 过滤系统库（默认 true，与 CLI 一致） */
  excludeSysdbs?: boolean;
}

export interface ScanConfig {
  concurrency: number;
  timeoutMs: number;
  retry: number;
  timeThresholdMs: number;
  ratePerSec: number;
  enableExtract: boolean;
  proxy: string | null;
  auth: AuthConfig | null;
  wafEvasion: WafEvasionConfig;
  techniques: TechniqueType[];
  level?: number; // 检测等级 1-5
  risk?: number; // 风险等级 1-3
  // payload 前缀/后缀（对标 sqlmap --prefix / --suffix）：注入点原值前拼接 prefix、
  // payload 后拼接 suffix，用于闭合引号/括号再注释尾部。空串 = 不拼接。
  prefix?: string;
  suffix?: string;
  // 会话持久化 / 断点续跑（对标 sqlmap --session / --resume，P2-S11）：
  // sessionFile = 显式会话文件名（后端白名单校验后落盘，下次续跑复用）；
  // sessionDefault = 自动用固定文件名 sqli-session-latest.json 落盘（同 URL 自动 resume）。
  sessionFile?: string;
  sessionDefault?: boolean;
  // 非 SQL 注入检测配置（NoSQL/GraphQL/SSTI），opt-in 独立趟，默认关闭
  noSql?: {
    enabled: boolean;
    kinds?: Array<'nosql' | 'graphql' | 'ssti'>;
  };
  // ── [2026-09-23 UI-REACH] 两条整通道此前「引擎/REST 都支持、UI 无入口」──
  // 带外通道（OOB，无回显盲注的兜底）。★ enabled 是**总开关**：即使 techniques 里勾了 oob，
  // 也需此处开启接收端才会启动（server/src/config/defaults.js 的 oob 段）。
  // 此前 UI 拿不到它 → 界面用户永远测不到带外通道，而该通道在「无回显 + WAF 拦 sleep/报错/union」
  // 的场景里是**唯一可达**的一条（e2e/oob-real-lab 真 PG 16.2 实测）。
  oob?: {
    enabled: boolean;
    callbackBase?: string; // 接收端可达地址（真实环境换成自有域名/公网 IP）
    httpPort?: number; // 接收端监听端口（独立于引擎端口）
    timeoutMs?: number; // 等待回连上限
    dnsOob?: boolean; // 走 DNS 通道替代 HTTP（防火墙几乎不拦 DNS 出站）
    dnsDomain?: string; // DNS 回调域名，token 放子域名里
    dnsPort?: number; // DNS 监听端口（默认 53，需管理员权限）
  };
  // 二阶注入（Second-order / 存储型）：先写进库、别处读取触发。
  // ★ 默认关闭是**产品语义而非未实现** —— 开启即代表将对目标发起**真实写请求**
  // （POST 注册/评论/资料），故面板必须给显式告知；triggerUrls 为空则不跑。
  secondOrder?: {
    enabled: boolean;
    triggerUrls?: string[]; // 候选触发页 URL（仅 http/https），可为多个；为空则不跑
    refreshCsrf?: boolean; // 存储前重抓 CSRF token（应对单次 token 失效）
    negativeControl?: boolean; // 存良性值→读触发页 的阴性对照（多一次写，提高置信）
    oobTrigger?: boolean; // 触发页无回显时改走带外（需 oob.enabled=true 且接收端就绪）
    secondUrl?: string; // 写入与读取分离：读取请求发往此处而非原始触发页
    // ★ 写确认位（server/src/api/scanRoutes.js:486）：productionMode=true 时，非幂等 method
    // （POST/PUT/PATCH/DELETE）与触发页写请求必须 allowWrites===true 才放行。
    // 二阶检测天然要「写一次」才能触发存储型路径，故这一位必须能在 UI 上给出，
    // 否则生产护栏一开、二阶就永远跑不起来（且报「未检出」）。
    allowWrites?: boolean;
    triggerMethod?: string; // 触发页请求方法（白名单归一化，非法值回落 GET）
    // 读写分离（对标 sqlmap --second-url / --second-method / --second-data）：读取阶段的请求
    // 发往 secondUrl、用 secondMethod（引擎 resolveSecondOrderMethod 做过白名单 + 幂等门）、
    // 携带 secondData。★ 这三个字段在 2026-09-23 之前**三条路径全不可达**（CLI 不能设、
    // REST clamp 不保留、UI 无入口）—— 而 SecondOrderDetector._trigger 一直在读它们。
    secondMethod?: string;
    secondData?: string;
  };
  // 站内链接爬取深度（对标 sqlmap --crawl=<depth>）：0=关闭，1-3=深度
  crawlDepth?: number;
  // [2026-09-26 UI-REACH] 表单爬取（对标 sqlmap --forms）：默认 false → 只测 URL 参数，
  // 页面表单（POST body / 隐藏字段）完全不进注入点清单。引擎侧 TargetParser._crawlForms
  // 一直读它，且已在 2026-09-13 与 level 解耦（独立开关），但前端此前无控件 → 一整类注入面
  // 对界面用户不可见。仅当 crawlDepth > 0 时才有意义（面板里据此置灰）。
  crawlForms?: boolean;
  // 授权范围（[P0-SEC] scope 硬约束）：CIDR/域名/URL 前缀列表；空/缺省 = 不启用。
  // 启用后目标与每一跳重定向都必须落在范围内，越界直接拒发（后端 scopeGuard 消费）。
  scope?: string[];
  // 忽略自签/内网 CA 证书（insecureTls=true：关闭证书校验，失去中间人防护，报告须注明）。
  insecureTls?: boolean;
  // 输入校验跳过（默认开）：参数被白名单拦死时跳过 200+ 无效请求；false 可强制完整检测。
  validationSkip?: boolean;
  // ── [P0-FIX 2026-09-09] 后端已支持、UI 此前无入口的调优键 ──
  // 键名与 server/src/api/scanRoutes.js 的 KNOWN_CFG_KEYS 严格一致：白名单外的键被后端
  // `logger.debug` 静默丢弃（既不报错也不生效），所以任何新增键都必须同时登记进
  // src/shared/constants.ts 的 SCAN_CONFIG_KEYS，由契约测试钉住「面板有 → 请求体有」。
  // 参数预筛选总开关（scanRunner 消费）：默认开；关闭 = 每个点都跑完整检测（审计/对照场景，
  // 代价是请求量放大数倍）。prefilter=false 会让 prefilterSinglePoint / validationSkip 失效。
  prefilter?: boolean;
  // 静态参数跳过（对标 sqlmap --skip-static，opt-in）：多参数目标每点 1 请求做哨兵探测，
  // 响应与基线完全一致且哨兵值未回显的参数判为静态并跳过（换掉 46+ 请求/点的完整检测预算）。
  skipStatic?: boolean;
  // 单点目标也走廉价预筛（默认关）：唯一注入点时「探针无信号」不足以判定干净，误杀风险高，
  // 只在赶时间的全量复扫里开。
  prefilterSinglePoint?: boolean;
  // 声明式 payload 注册表（对标 sqlmap XML <test>）：false = 用扁平 payloads/*.js（零回归）；
  // true = 走 PAYLOAD_REGISTRY 按 level/risk/dbms/testFilter/testSkip 精确筛选。
  // ★ testFilter / testSkip 只有在本键为 true 时才生效——面板必须把这条依赖讲清楚。
  useRegistry?: boolean;
  // ── [2026-09-23] 注入点范围（对标 sqlmap 的 path/header 测试）──
  // 默认只测 query + body。这两键显式开启后，TargetParser 会把 REST 路径段 / 请求头值
  // 也当作候选注入点。后端还有一条隐式规则：level ≥ 3 时 testHeaders 自动生效
  // （TargetParser.js:129），故本键语义是「在 level 门控之外强制开启」。
  // 此前引擎已消费、REST 白名单已收（2026-09-20 CFG-REACH），但 UI 无入口 →
  // 使用者少测两类注入点，报告只会写「未检出」。
  testPath?: boolean;
  testHeaders?: boolean;
  // ── [2026-09-23 UI-REACH] 授权与安全护栏（两键默认值即安全默认，但 UI 必须能看见并改）──
  // productionMode（默认 **true**）：把目标当**生产**系统 —— 高危池（写文件 / RCE / 永久改配置 /
  // DoS）只有在 confirmDestructive===true 时才投放，否则跳过并在 report.summary.constraints 记一条。
  // 设为 false 是**显式脱离护栏**（打靶场 / 自建演练环境）：注册表 risk≥3 即投放并打 warn。
  // ⚠️ 这两键不是可选调优项：UI 缺它们时，界面用户既无法「确认授权后投放高危载荷」，
  // 也无法「显式声明这是靶场」，而报告只会写「未检出」—— 能力被默认值锁死（与 OOB 同一形态）。
  productionMode?: boolean;
  confirmDestructive?: boolean;
  // ── [2026-09-23 UI-REACH] 请求节奏（对标 sqlmap --delay / --max-requests）──
  // delay：每次请求间的**固定**延时（秒；引擎侧 httpClient 夹到上限 60），用于规避 WAF 频率限制。
  // 与 ratePerSec 的令牌桶是两套机制（固定间隔 vs 平均速率），不是重复项。
  delay?: number;
  // maxReq：本次扫描的**总请求上限**（0 = 不限），达到即停 —— 靶场与大目标上的安全阀。
  maxReq?: number;
  // [2026-09-23 E2] 枚举 / 拖库动作族。undefined = 不启用（引擎走既有全量提取分支，零行为变化）。
  extractScope?: ExtractScopeConfig | null;
  // payload 白名单（对标 --test-filter）：逗号分隔的注册表 id 子串，大小写不敏感；空 = 不过滤。
  testFilter?: string;
  // payload 黑名单（对标 --test-skip）：逗号分隔的 id 子串，命中即排除；空 = 不跳过。
  testSkip?: string;
  // 强制指定 DBMS（对标 --dbms）：跳过指纹识别（省 8-9 请求/点，payload/提取语句语义确定）。
  // ★ 内置引擎按**引擎规范名精确匹配**（'MySQL' / 'PostgreSQL' / 'SQL Server'…，区分大小写），
  //   与 sqlmap CLI 的 'mysql' / 'microsoft sql server' 拼写不同——拼错等于零 payload 命中。
  //   null / 缺省 = 自动指纹识别（保持现状）。
  dbms?: string | null;
  // 盲注响应锚点（对标 sqlmap --string / --not-string）：真页面必含 / 假页面必含的文本。
  // ★ 后端是**字符串**（Detector.matchAnchors 走 text.includes(String(ms))），不是布尔开关：
  //   把它当开关传 true，判定就变成「真页必须包含字符 'true'」——强动态页面上直接静默失效。
  //   因此 UI 给文本输入框，关闭态省略该键（不发空串、不发布尔）。
  matchString?: string;
  notString?: string;
  // [2026-09-26 UI-REACH] 判定锚点族的其余成员（后端 Detector 已消费，前端此前无控件）。
  //   matchTitle   = --titles：真/假响应的 <title> 不同即信号（严格 === true 才启用）。
  //   matchCode    = --code：**精确期望**形态 { true, false }（100-599）。
  //                  ⚠️ 另有一种弱信号形态 `true`（真假状态码不同即可），后端也收，
  //                  但前端 normalizeScanValue 的 object 分支会把它丢掉 → 面板不暴露，留给 REST/CLI。
  //   matchRegexp  = --regexp：真响应命中、假响应不命中（或反之）即信号；正则源文本。
  //   trueRegexp / falseRegexp = 分别限定真/假侧**必须**命中的正则（可组合，也可单用）。
  // 关闭态一律省略该键（与 matchString 同口径：不发空串、不发布尔 false 冒充）。
  matchTitle?: boolean;
  matchCode?: { true?: number; false?: number };
  matchRegexp?: string;
  trueRegexp?: string;
  falseRegexp?: string;
}

/** 扫描目标 */
export interface Target {
  id: string;
  baseUrl: string;
  method: MethodType;
  bodyParams: Record<string, string>;
  cookieParams: Record<string, string>;
  headerParams: Record<string, string>;
  config: ScanConfig;
}

/** 注入点 */
export interface InjectionPoint {
  id: string;
  location: InjectionLocation;
  param: string;
  originalValue: string;
  confirmed: boolean;
  technique: TechniqueType | null;
  dbms: DbmsType | null;
  // ── 跳过留痕（[P1-AUDIT] 引擎写入；「没测」不得看起来像「测了且无漏洞」）──
  skipReason?: 'prefilter' | 'input_validation' | 'static';
  skipNote?: string;
}

/** 盲注判定采样点（时间线基础单元） */
export interface BlindSamplePoint {
  idx: number;
  len?: number; // 响应长度（布尔）
  likeBaseline?: boolean; // 该样本是否≈基线（布尔真假对）
  ms?: number; // 耗时秒（时间）
  delayed?: boolean; // 是否触发延迟（时间）
  excerpt?: string; // 响应片段（截断前 160 字符，便于人工审计"页面主体变化"）
}

/** 布尔盲注真假对逐采样差异摘要（前端时间线展开看"到底差在哪"） */
export interface BoolPairDiff {
  idx: number; // 采样序号
  lenDelta: number; // 假响应长度 - 真响应长度
  firstDiffOffset: number; // 首个不同字符下标（-1 表示完全相同）
  changedSnippet: string; // 假响应中变化区域片段（截断，差异点附近）
}

/** 布尔盲注真假对轨迹 */
export interface BooleanTracePair {
  ti: number;
  fi: number;
  trueSamples: BlindSamplePoint[];
  falseSamples: BlindSamplePoint[];
  trueRatio: number;
  falseRatio: number;
  meaningfulRatio: number;
  z: number | null;
  significant: boolean;
  diffs?: BoolPairDiff[]; // 逐采样真假差异摘要
}

/** 盲注统计判定结构化轨迹（供前端时间线可视化） */
export interface BlindTrace {
  technique: 'boolean' | 'time';
  adaptive: boolean;
  baselineNoiseRate?: number | null; // 仅布尔
  minStable?: number; // 仅布尔
  mu?: number;
  sigma?: number;
  threshold?: number;
  floor?: number;
  stableRatio?: number;
  baselineSamples: BlindSamplePoint[];
  pairs?: BooleanTracePair[]; // 仅布尔
  injectSamples?: BlindSamplePoint[]; // 仅时间
  decision: 'vulnerable' | 'clean';
}

/** 检测结果 */
export interface DetectionResult {
  pointId: string;
  technique: TechniqueType;
  vulnerable: boolean;
  dbms: DbmsType | null;
  evidence: string;
  payloads: string[];
  trace?: BlindTrace | null;
}

/** 漏洞 */
export interface Vulnerability {
  id: string;
  pointId: string;
  technique: TechniqueType;
  dbms: DbmsType | null;
  riskLevel: RiskLevel;
  payloads: string[];
  description: string;
  evidence?: string; // 检测器原始证据（P1-U2 新增，供详情页单独展示）
  trace?: BlindTrace | null;
  // 可复现 PoC（仅导出路径由 ReportGenerator 惰性挂载；UI 侧报告可能缺失，缺失时不渲染复现区）
  poc?: VulnPoc;
}

/** 提取数据 */
export interface ExtractedData {
  databases: string[];
  tables: Record<string, string[]>;
  columns: Record<string, string[]>;
  rows: Record<string, object[]>;
}

/** 报告模型 */
/** 报告摘要（引擎在 _run 末尾写入；字段多为可选，向后兼容老报告） */
export interface ReportSummary {
  stackedEnabled?: boolean;
  stackedCorroborations?: Array<{ pointId: string; technique: string; dbms: string | null }>;
  // WAF 规避标注（F-20：新增 tamper 子对象）
  wafEvasion?: {
    randomUA: boolean;
    jitterMs: number;
    obfuscate: boolean;
    tamper: TamperConfig;
  };
  // F-20 新增：WAF 指纹识别汇总（来自指纹基线，零额外发包）
  wafDetected?: WafCandidate[];
  // ── [P0-FIX 2026-09-09] 结论可信度（旧报告缺省 = 未知，UI 走兼容分支）──
  verdict?: 'no_vulnerability_detected' | 'inconclusive';
  verdictNote?: string;
  validity?: ScanValidity;
}

export interface ReportModel {
  scanId: string;
  target: Target;
  startedAt: string;
  finishedAt: string | null;
  dbms: DbmsType | null;
  points: InjectionPoint[];
  vulns: Vulnerability[];
  data: ExtractedData | null;
  riskLevel: RiskLevel;
  summary: ReportSummary;
  // 结论可信度摘要（与 report.summary.validity 同构；老报告无此字段）
  validity?: ScanValidity;
  // ── sqlmap 高级模式附加（P0-U1 新增，仅 engine=sqlmap 的报告存在）──
  engine?: EngineType; // 报告来源引擎（内置引擎报告缺省为 builtin 语义，sqlmap 报告显式标注）
  sqlmap?: SqlmapReportData; // sqlmap 原始 {logs, vulns} 包装数据（内置引擎报告无此字段）
}

/** sqlmap 输出日志行（GET /sqlmap/:id/report 返回 logs 元素，与 sqlmapBridge 契约一致） */
export interface SqlmapLogEntry {
  level: 'error' | 'success' | 'info' | 'debug' | 'warn' | 'output';
  text: string;
  ts: string;
}

/** sqlmap 确认注入点（GET /sqlmap/:id/report 返回 vulns 元素，与 sqlmapBridge 契约一致） */
export interface SqlmapVulnEntry {
  param: string | null;
  technique: string;
  raw: string;
}

/** sqlmap 模式报告附加数据（桥 getReport 返回 {logs,vulns} 的包装） */
export interface SqlmapReportData {
  status: string; // completed / stopped / error / killed / running
  logs: SqlmapLogEntry[];
  vulns: SqlmapVulnEntry[];
}

/** SSE 事件载荷类型映射（按 EventType 分发，消除 any） */
interface ScanEventPayloads {
  scan_started: { scanId: string; target: { url: string; method: MethodType } };
  scan_phase: { phase: string; message: string };
  http_request: { method: string; url: string; status: number; ms?: number };
  point_discovered: { points: InjectionPoint[] };
  point_testing: { pointId: string; technique: string; tamperRetry?: boolean };
  point_skipped: { pointId: string; reason: string; note?: string };
  detection_found: DetectionResult & { riskLevel: RiskLevel };
  extraction_progress: { db: string; table: string | null; count: number };
  scan_completed: ReportModel;
  scan_stopped: { scanId: string };
  scan_paused: { scanId: string };
  scan_resumed: { scanId: string };
  scan_error: { message: string; code?: number };
  sqlmap_log: SqlmapLogEntry;
  sqlmap_vuln: SqlmapVulnEntry;
  waf_detected: WafDetectedPayload;
  scan_validity: ScanValidity;
  scan_validity_abort: ScanValidity & { scanId: string };
  waf_block_policy: WafBlockPolicyPayload;
}

/** SSE 事件（判别联合：按 type 分发 payload 类型，消除 any） */
export type ScanEvent = {
  [K in EventType]: {
    type: K;
    scanId: string;
    ts: string;
    /** 服务端单调递增序号，用于断线重连 lastEventId 续传（旧后端/测试构造的事件可缺省） */
    seq?: number;
    payload: ScanEventPayloads[K];
  };
}[EventType];

/** 统一响应包 */
export interface ApiResponse<T> {
  code: number;
  data: T;
  message: string;
}

/**
 * 错误码枚举（镜像后端 server/src/core/errors.js 的 ErrorCode，保持前后端契约一致）。
 * 前端通过此枚举判断错误类型以决定行为（重试 vs 提示），而非匹配中文 message 字符串。
 */
export const ErrorCode = {
  OK: 0,
  INVALID_TARGET: 1001, // 无效目标
  UNSUPPORTED_METHOD: 1002, // 不支持的请求方法
  INVALID_PARAM: 1003, // 入参非法
  SCAN_NOT_FOUND: 2001, // 扫描不存在/已结束
  ENGINE_BUSY: 2002, // 引擎忙
  HTTP_TIMEOUT: 3001, // HTTP 超时
  HTTP_ERROR: 3002, // HTTP 错误
  DETECT_FAILED: 4001, // 检测失败
  EXTRACT_FAILED: 5001, // 提取失败
  UNKNOWN: 9001, // 未知错误
  OOB_RECEIVER_START_FAILED: 6001, // 接收端启动失败
  OOB_DISABLED: 6002, // OOB 未启用
  TAMPER_INVALID_NAME: 6003, // tamper 插件缺唯一 name
  SECOND_ORDER_DISABLED: 6004, // 二阶检测未启用
  EXPLOIT_UNAUTHORIZED: 6005, // 利用操作未授权
  RATE_LIMITED: 4290, // 限速
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/** 利用目标上下文（注入点 + DBMS + 授权声明），对应后端 /exploit/* 入参 */
export interface ExploitTarget {
  target: {
    url: string;
    method: MethodType;
    bodyParams?: Record<string, string>;
    cookieParams?: Record<string, string>;
    headerParams?: Record<string, string>;
  };
  point: { originalValue: string; echoCols?: number };
  dbms: DbmsType;
  authorized: boolean;
}

/** 利用能力清单（GET /exploit/capabilities） */
export interface ExploitCapabilities {
  sqlShell: string[];
  fileRead: string[];
  fileWrite: string[];
  osShell: string[];
}

/** 利用结果（覆盖四动作返回形态，宽松结构） */
export interface ExploitResult {
  ok: boolean;
  error?: string;
  type?: string;
  value?: string | null;
  path?: string;
  status?: number | null;
  raw?: string;
  echoed?: string | null;
  wrote?: boolean;
  verified?: boolean;
  readback?: string | null;
  note?: string;
}
