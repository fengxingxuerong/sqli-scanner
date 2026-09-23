import type { RiskLevel, TechniqueType, ScanConfig, SqlmapConfig, ExtractScopeMode } from './types';

/**
 * [2026-09-23 E2] 枚举 / 拖库动作表（对标 sqlmap 的枚举开关）。
 *
 * `needs` 声明该动作会用到的输入项 —— UI 据此禁用无关输入框，避免「填了表名但选的动作不看表名」
 * 这种「填了没用」的困惑（本仓对「勾了没生效」这类断链有专门纪律）。
 * 与 CLI 的对应关系见 server/bin/cli/config.js:314 buildExtractScope（同一套 mode 名）。
 */
export const EXTRACT_SCOPE_OPTIONS: { value: ExtractScopeMode; needs: ExtractScopeField[] }[] = [
  { value: 'dbs', needs: [] },
  { value: 'tables', needs: ['dbs'] },
  { value: 'columns', needs: ['dbs', 'tables'] },
  { value: 'dump', needs: ['dbs', 'tables', 'cols'] },
  { value: 'dumpAll', needs: [] },
  { value: 'commonTables', needs: ['dbs'] },
  { value: 'commonColumns', needs: ['dbs', 'tables'] },
  { value: 'search', needs: ['keyword'] },
  { value: 'currentDb', needs: [] },
  { value: 'currentUser', needs: [] },
  { value: 'hostname', needs: [] },
  { value: 'isDba', needs: [] },
  { value: 'users', needs: [] },
  { value: 'passwords', needs: [] },
  { value: 'schema', needs: ['dbs', 'tables'] },
  { value: 'privileges', needs: [] },
  { value: 'roles', needs: [] },
  { value: 'count', needs: ['dbs', 'tables'] },
];

/** 枚举动作会用到的输入项（与 ExtractScopeConfig 的子字段同名） */
export type ExtractScopeField = 'dbs' | 'tables' | 'cols' | 'keyword';


/** 检测技术列表（UI 勾选项；inline 内联查询对标 sqlmap Q，默认不勾选，需用户显式开启） */
export const TECHNIQUES: TechniqueType[] = ['union', 'error', 'boolean', 'time', 'stacked', 'inline'];

/** 风险等级中文标签 */
export const RISK_LABEL: Record<RiskLevel, string> = {
  Critical: '严重',
  High: '高危',
  Medium: '中危',
  Low: '低危',
};

/** 检测技术中文标签 */
export const TECHNIQUE_LABEL: Record<TechniqueType, string> = {
  union: '联合查询注入',
  error: '报错注入',
  boolean: '布尔盲注',
  time: '时间盲注',
  stacked: '堆叠注入',
  oob: '带外注入(OOB)',
  inline: '内联查询(Q)',
  second_order: '二阶注入',
};

/** 默认扫描配置（用于 UI 初始值与展示） */
export const DEFAULT_CONFIG: ScanConfig = {
  concurrency: 6,          // 并发数（默认 6，兼顾速度与稳定性）
  timeoutMs: 10000,        // 请求超时（毫秒）
  retry: 2,                // 失败重试次数
  timeThresholdMs: 3000,   // 时间盲注延迟阈值（毫秒，默认 3s，避免误报）
  ratePerSec: 5,           // 每秒请求速率限制
  enableExtract: true,     // 默认开启数据提取（拖库）
  proxy: null,
  auth: null,
  wafEvasion: {
    randomUA: false,
    jitterMs: 0,
    obfuscate: false,
    // 可插拔 tamper 链式体系（对标 sqlmap --tamper）。默认全关，开启才对 payload 生效。
    tamper: { enabled: false, plugins: [], intensity: 'medium' },
  },
  techniques: ['union', 'error', 'boolean', 'time', 'stacked'], // 默认启用 5 种主要技术
  crawlDepth: 1, // 默认开启爬虫深度 1（自动发现同目录下的参数入口）
  // 输入校验跳过（后端 defaults.validationSkip 同为 true）：参数被白名单拦死时短路跳过，
  // UI 开关默认勾选；关闭后对被拦死的点也照跑完整检测（审计场景）。
  validationSkip: true,
  // [2026-09-23] 注入点范围：默认只测 query + body（与 TargetParser 的默认一致）。
  // 注意后端还有一条隐式规则：level ≥ 3 时 testHeaders 会自动生效（TargetParser.js:129），
  // 因此这两个开关的语义是「在 level 门控之外**强制**追加」，不是「唯一入口」。
  testPath: false,
  testHeaders: false,
};

// ── [P0-FIX 2026-09-09] /api/scan/start 的 config 契约：单一事实来源 ────────────────
/**
 * 前端会（且只能）通过 `config` 发给内置引擎的全部键。
 *
 * 为什么需要这张表（实战后果）：后端 `sanitizeStart` 只认 KNOWN_CFG_KEYS 白名单，
 * 白名单外的键被 `logger.debug` 静默丢弃——既不报错也不生效。「面板上勾了、引擎收不到」
 * 这类断链在本项目已连续出现三批（delay/reqRate/maxReq → prefilterSinglePoint → matchString），
 * 每一次都是靠人记住「新开关要接进请求体」。现在把它钉成契约（src/tests/scanConfig.contract.test.ts）：
 *   ① 面板上出现的每个可配置键，都必须出现在 startScan 实际发出的 body.config 里；
 *   ② body.config 里不得出现后端白名单之外的键（抄录白名单见该测试文件）；
 *   ③ 每个键的值类型必须与后端解析口径一致（见下方 SCAN_CONFIG_VALUE_TYPES）。
 * 新增开关的次序：先在这里登记键名 + 类型 → 再写 UI → CI 会替你记住接没接上。
 */
export const SCAN_CONFIG_KEYS = [
  // 网络 / 调度
  'concurrency', 'timeoutMs', 'retry', 'ratePerSec', 'timeThresholdMs',
  // 检测强度与 payload
  'level', 'risk', 'techniques', 'prefix', 'suffix', 'dbms',
  'prefilter', 'skipStatic', 'prefilterSinglePoint', 'useRegistry', 'testFilter', 'testSkip',
  // [2026-09-23] 注入点范围：默认只测 query + body；这两键显式开启后追加 path 段与请求头。
  // 此前引擎已消费（TargetParser）、REST 白名单也已收（2026-09-20 CFG-REACH），
  // 唯独 UI 没有入口 → 使用者少测两类注入点，且报告只写「未检出」（能力缺失，不是便利开关）。
  'testPath', 'testHeaders',
  // [2026-09-23 UI-REACH] 授权与安全护栏 + 请求节奏（四键此前无 UI 入口）
  'productionMode', 'confirmDestructive', 'delay', 'maxReq',
  // 盲注响应判定锚点（字符串，不是布尔）
  'matchString', 'notString',
  // 数据提取
  'enableExtract',
  // [2026-09-23 E2] 枚举 / 拖库动作族（对标 sqlmap --dbs/--tables/--columns/--dump/--dump-all/
  // --users/--passwords/--current-db/--current-user/--hostname/--is-dba/--schema/--privileges/
  // --roles/--count/--search/--common-tables/--common-columns）。
  // 此前这条链断在**两处**：引擎能跑、CLI 能用，但 REST 白名单没收该键（传了静默丢弃）、
  // UI 也没有入口 → Web/桌面/API 三端完全拿不到枚举与拖库能力。
  'extractScope',
  // 爬虫 / 会话 / 非 SQL 注入
  'crawlDepth', 'sessionFile', 'sessionDefault', 'noSql',
  // [2026-09-23 UI-REACH] 两条**整通道**接进 UI（此前 REST 白名单与引擎都支持，
  // 但前端只在 KNOWN_MISSING_UI_KEYS 里当债记着 → 界面用户永远测不到它们）
  'oob', 'secondOrder',
  // 出口层（代理 / 证书 / 授权范围）
  'proxy', 'auth', 'insecureTls', 'validationSkip', 'scope',
  // WAF 规避（tamper 链等整块配置）
  'wafEvasion',
] as const;

/** 前端可控的扫描配置键名（由 SCAN_CONFIG_KEYS 推导，无手写重复） */
export type ScanConfigKey = (typeof SCAN_CONFIG_KEYS)[number];

/** 配置值类型（与后端 sanitizeStart 的 clampStr / pickBool / pickInt 口径对齐） */
export type ScanConfigValueType = 'boolean' | 'number' | 'string' | 'stringOrNull' | 'stringArray' | 'object';

/**
 * 逐键类型声明：`buildStartConfig` 据此归一化，保证不会出现「勾了但传了错的类型」。
 *   · string      → 非空字符串；trim 后为空 = 关闭态，该键从请求体里**省略**（后端 clampStr('') 同义）
 *   · stringOrNull→ 字符串或 null（null = 显式不配，与 DEFAULT_CONFIG 里 proxy/auth 的既有语义一致）
 *   · boolean     → 真正的布尔（false 也必须发——「关预筛」是需要能发出去的动作）
 *   · number      → 有限数（0 合法：delay=0 / crawlDepth=0 都是有效语义）
 *   · stringArray → 字符串数组（容错接受逗号串，后端 parseScope/selectPayloads 同源）
 *   · object      → 对象/数组/null 原样透传（子字段形状由后端逐项校）
 */
export const SCAN_CONFIG_VALUE_TYPES: Record<ScanConfigKey, ScanConfigValueType> = {
  concurrency: 'number',
  timeoutMs: 'number',
  retry: 'number',
  ratePerSec: 'number',
  timeThresholdMs: 'number',
  level: 'number',
  risk: 'number',
  crawlDepth: 'number',
  techniques: 'stringArray',
  scope: 'stringArray',
  prefix: 'string',
  suffix: 'string',
  sessionFile: 'string',
  matchString: 'string',
  notString: 'string',
  testFilter: 'string',
  testSkip: 'string',
  dbms: 'stringOrNull',
  proxy: 'stringOrNull',
  enableExtract: 'boolean',
  sessionDefault: 'boolean',
  insecureTls: 'boolean',
  validationSkip: 'boolean',
  prefilter: 'boolean',
  skipStatic: 'boolean',
  prefilterSinglePoint: 'boolean',
  useRegistry: 'boolean',
  testPath: 'boolean',
  testHeaders: 'boolean',
  // 生产护栏两键走严格布尔（defaults.js 默认 productionMode=true / confirmDestructive=false，
  // 面板必须能把「显式脱离护栏」与「确认投放高危池」这两个动作如实发出去）
  productionMode: 'boolean',
  confirmDestructive: 'boolean',
  // 0 是合法值（delay=0 不延时 / maxReq=0 不限量），不能被当成「未配置」丢掉
  delay: 'number',
  maxReq: 'number',
  auth: 'object',
  noSql: 'object',
  // 嵌套对象：子字段形状由后端逐项 clamp（oob 的回调地址/端口、secondOrder 的触发页列表）
  oob: 'object',
  secondOrder: 'object',
  wafEvasion: 'object',
  extractScope: 'object',
};

/**
 * 内置引擎可选的 DBMS 规范名（[P0-FIX 2026-09-09]）。
 * ★ 这里列的是**引擎侧键名**（server/src/engine/payloads/index.js 的 PAYLOADS 键 +
 *   payloadRegistry 的 `p.dbms.includes(dbms)`），区分大小写；与 sqlmap CLI 的
 *   `--dbms=mysql` / `--dbms="microsoft sql server"` 拼写不通用（那份见 SQLMAP_DBMS_OPTIONS）。
 *   把 sqlmap 拼写喂给内置引擎 = 零 payload 命中，且引擎不会报错（“没测”看起来像“安”）。
 */
export const BUILTIN_DBMS_OPTIONS: { value: string; label: string }[] = [
  { value: 'MySQL', label: 'MySQL' },
  { value: 'MariaDB', label: 'MariaDB' },
  { value: 'TiDB', label: 'TiDB' },
  { value: 'PostgreSQL', label: 'PostgreSQL' },
  { value: 'SQL Server', label: 'SQL Server' },
  { value: 'Oracle', label: 'Oracle' },
  { value: 'SQLite', label: 'SQLite' },
];

// ── tamper 强度三档预设包（与后端 TamperRegistry 注册名严格一致）─────────────
// intensity 仅前端语义：点选即按预设填充 plugins，用户可在此之上微调。
// 预设里所有插件名均来自 tamperRegistry.list()（GET /api/tampers），无拼写漂移。
export const TAMPER_INTENSITY_PRESETS: Record<'low' | 'medium' | 'high', string[]> = {
  low: ['space2comment', 'randomcase'],
  medium: ['space2comment', 'randomcase', 'charencode'],
  high: ['space2comment', 'randomcase', 'charencode', 'modsecurityversioned', 'percentage', 'versionedkeywords'],
};

// ── sqlmap 高级模式专用常量 ──────────────────────────────────────
/** sqlmap 检测技术字母 + 中文标签（B/E/U/S/T/Q） */
export const SQLMAP_TECHNIQUES: { letter: string; label: string }[] = [
  { letter: 'B', label: '布尔盲注' },
  { letter: 'E', label: '报错注入' },
  { letter: 'U', label: '联合查询' },
  { letter: 'S', label: '堆叠注入' },
  { letter: 'T', label: '时间盲注' },
  { letter: 'Q', label: '内联查询' },
];

/** sqlmap 可指定后端 DBMS 选项（部分常用） */
export const SQLMAP_DBMS_OPTIONS: { value: string; label: string }[] = [
  { value: 'mysql', label: 'MySQL' },
  { value: 'postgresql', label: 'PostgreSQL' },
  { value: 'microsoft sql server', label: 'SQL Server' },
  { value: 'sqlite', label: 'SQLite' },
  { value: 'oracle', label: 'Oracle' },
];

/** 常用 tamper 脚本（WAF 绕过预设） */
export const SQLMAP_TAMPER_PRESETS: string[] = [
  'space2comment',
  'randomcase',
  'charencode',
  'equaltolike',
  'between',
  'sleep2getlock',
  'space2plus',
  'versionedkeywords',
];

/** sqlmap 默认配置 */
export const DEFAULT_SQLMAP_CONFIG: SqlmapConfig = {
  level: 1,
  risk: 1,
  techniques: ['B', 'E', 'U', 'T'],
  tamper: [],
  dbms: null,
  threads: 1,
  dump: false,
  osShell: false,
  fileRead: null,
  // 请求控制默认值（P0-U2）：代理直连、超时 30s、重试 3 次、随机 UA 关闭
  proxy: null,
  timeoutMs: 30000,
  retry: 3,
  randomUA: false,
  // 对标 sqlmap 高级参数默认值
  flushSession: false,
  freshQueries: false,
  unionCols: null,
  unionChar: null,
  unionFrom: null,
  smart: false,
  timeSec: null,
  ignoreCode: null,
  excludeSysdbs: true,
  verbose: null,
  // 低优先级 WAF 规避参数（默认关闭）
  noCast: false,
  hex: false,
  noEscape: false,
};
