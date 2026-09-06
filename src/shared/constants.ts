import type { RiskLevel, TechniqueType, ScanConfig, SqlmapConfig } from './types';

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
};

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
