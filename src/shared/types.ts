// 前后端共享类型定义（镜像后端 schema，保持契约一致）

/** 请求方法 */
export type MethodType = 'GET' | 'POST';

/** 注入点位置 */
export type InjectionLocation = 'url' | 'body' | 'cookie' | 'header';

/** 检测技术 */
export type TechniqueType = 'union' | 'error' | 'boolean' | 'time' | 'stacked' | 'oob';

/** 支持的数据库 */
export type DbmsType = 'MySQL' | 'PostgreSQL' | 'SQLite' | 'SQL Server' | 'Oracle';

/** 风险等级 */
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** 扫描状态 */
export type ScanStatus = 'pending' | 'running' | 'completed' | 'stopped' | 'error';

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

/** point_discovered 事件载荷（解析目标后回传的全部注入点，供扫描页实时全局拓扑） */
export interface PointDiscoveredPayload {
  points: InjectionPoint[];
}

/** SSE 事件类型 */
export type EventType =
  | 'scan_started'
  | 'point_discovered' // payload: { points: InjectionPoint[] }（解析目标后回传的全部注入点）
  | 'point_testing'
  | 'detection_found'
  | 'extraction_progress'
  | 'scan_completed'
  | 'scan_stopped'
  | 'scan_error'
  | 'sqlmap_log' // sqlmap 原始输出行（按级别着色）
  | 'sqlmap_vuln' // sqlmap 确认的注入点
  | 'waf_detected' // payload: { vendors: WafCandidate[]; suggestions: WafSuggestion[] }
  | 'second_order_discovery'; // payload: { candidates: string[]; confirmed: string[] }

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

/** 自定义检测判定锚点（对标 sqlmap --string / --not-string / --regexp / --code） */
export interface DetectMatchConfig {
  string?: string; // TRUE 响应应含、FALSE 响应应不含的串
  notString?: string; // TRUE 响应应不含、FALSE 响应应含的串
  regexp?: string; // TRUE 响应应匹配、FALSE 响应应不匹配的正则（字符串）
  code?: number; // TRUE 响应 HTTP 状态码应 ===、FALSE 应 !== 的数字
}

/** 安全间隔探测配置（对标 sqlmap --safe-url / --safe-urls / --safe-freq / --safe-order） */
export interface SafeProbeConfig {
  url?: string; // 单安全 URL（向后兼容）
  urls?: string[]; // 多安全 URL（逗号分隔合并去重），随机轮询
  freq?: number; // 每 N 次真实请求穿插一次安全探测
  randomize?: boolean; // 默认 true 随机轮询；false=顺序（--safe-order）
}

/** 二阶注入配置（对标 sqlmap --second-order）：开启后向目标发起真实写请求，需明确授权 */
export interface SecondOrderConfig {
  enabled: boolean; // 总开关
  triggerUrls: string[]; // 触发页 URL（确信会回显存储内容的页面）
  autoDiscover?: boolean; // 触发页自动发现：enabled 且未手填 triggerUrls 时，从目标页链接发现并经哨兵回显确认（默认 false）
  refreshCsrf?: boolean; // 每次触发前刷新 CSRF 令牌（默认 true）
  negativeControl?: boolean; // 用负控制页验证"非存储点不触发"（默认 true）
  oobTrigger?: boolean; // 触发页经 OOB 通道回传（需外部 OOB 监听，默认 false）
  manualStorePoints?: string[]; // 手动指定存储点参数名列表（逗号/换行分隔经 UI 解析）；与启发式 isStorePoint 取并集，命中点的 isStorePoint 运行时置真
}

/** OOB 带外注入配置：启用独立接收端，目标 DBMS 回连确认无回显注入（对标 sqlmap 带外通道） */
export interface OobConfig {
  enabled: boolean; // 总开关（即使 techniques 含 oob，也需此处开启接收端才启动）
  callbackBase?: string; // 接收端可达地址（如 your.domain 或 127.0.0.1:8899），目标 DBMS 回连此地址
  httpPort?: number; // 接收端独立监听端口（非引擎 4567），默认 8899
  timeoutMs?: number; // 轮询等待回连上限（毫秒），默认 5000
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
  // ── 对标 sqlmap 的高级检测选项（仅 builtin 引擎消费）──
  level: number; // 检测等级 1-5（控制测哪些注入位置：1=URL/Body；2=+Cookie；3=+Header/UA/Referer）
  risk: number; // 风险等级 1-3（二阶/堆叠/OOB 门控，过低则拦截高风险技术）
  detectMatch?: DetectMatchConfig; // 自定义判定锚点（--string/--not-string/--regexp/--code）
  timeSec?: number; // 时间盲注 SLEEP 触发秒数（--time-sec，默认 2）
  safeProbe?: SafeProbeConfig; // 安全间隔探测（--safe-url/--safe-urls/--safe-freq/--safe-order）
  requestDelayMs?: number; // 固定请求间延时毫秒（--delay，默认 0）
  hpp?: boolean; // HTTP 参数污染（--hpp，默认 false）
  keepAlive?: boolean; // 连接复用（--keep-alive/--no-keep-alive，默认 true；false=每次新连接）
  secondOrder?: SecondOrderConfig; // 二阶注入（--second-order）：开启对目标发起真实写请求，需授权
  oob?: OobConfig; // OOB 带外注入：启用接收端 + 需 techniques 含 oob 且 risk>=3
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
  // —— 二阶注入相关（与后端 createInjectionPoint 对齐；一阶非表单点通常为 undefined）——
  isStorePoint?: boolean; // 是否为潜在"存储型参数点"（候选二阶存储端）
  storeKind?: string | null; // 启发式分类：'registration'|'profile'|'comment'|'unknown'|null
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
  trace?: BlindTrace | null;
  oob?: { token: string; callback: string }; // OOB 带外回连确认的结构化元数据（仅 OOB 命中时存在）
}

/** 提取数据 */
export interface ExtractedData {
  databases: string[];
  tables: Record<string, string[]>;
  columns: Record<string, string[]>;
  rows: Record<string, object[]>;
}

/** 报告模型 */
/** 轻量存储点（用于二阶链路图等展示场景，不含完整注入点信息） */
export interface StorePointLite {
  param: string;
  storeKind?: string | null;
}
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
  // 安全间隔探测告警汇总（对标 sqlmap --safe-url 偏离告警；仅记录不阻断主扫描）
  safeProbeAlerts?: SafeProbeAlert[];
  // 二阶触发页自动发现结果（方向 1）：扫描时若开启 autoDiscover，记录候选链接与经哨兵回显确认的触发页
  secondOrderDiscovery?: {
    candidates: string[]; // 从目标页发现的候选触发页 URL
    confirmed: string[]; // 经"存哨兵→读触发页→断言回显"确认会回显存储值的触发页 URL
    storePoints?: StorePointLite[]; // 发现期识别到的存储点（供实时链路图绘制完整拓扑；可能为空）
  };
}

// 安全间隔探测单条告警（SafeProbeClient.onAnomaly → ScanManager 收集）
export interface SafeProbeAlert {
  url: string;
  reason: string;
  baselineStatus: number | null;
  baselineLen: number | null;
  actualStatus: number | null;
  actualLen: number | null;
  ts: string;
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
}

/** SSE 事件 */
export interface ScanEvent {
  type: EventType;
  scanId: string;
  ts: string;
  payload: any;
}

/** 统一响应包 */
export interface ApiResponse<T> {
  code: number;
  data: T;
  message: string;
}

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
