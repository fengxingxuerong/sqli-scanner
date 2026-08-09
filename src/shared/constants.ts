import type { RiskLevel, TechniqueType, DbmsType, ScanConfig, SqlmapConfig } from './types';

/** 风险等级有序列表（降序） */
export const RISK_LEVELS: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low'];

/** 检测技术列表 */
export const TECHNIQUES: TechniqueType[] = ['union', 'error', 'boolean', 'time', 'stacked'];

/** 支持的数据库列表 */
export const DBMS_LIST: DbmsType[] = [
  'MySQL',
  'PostgreSQL',
  'SQLite',
  'SQL Server',
  'Oracle',
];

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
};

/** 默认扫描配置（用于 UI 初始值与展示） */
export const DEFAULT_CONFIG: ScanConfig = {
  concurrency: 4,
  timeoutMs: 10000,
  retry: 2,
  timeThresholdMs: 1500,
  ratePerSec: 3,
  enableExtract: true,
  proxy: null,
  auth: null,
  wafEvasion: {
    randomUA: false,
    jitterMs: 0,
    obfuscate: false,
    // 可插拔 tamper 链式体系（对标 sqlmap --tamper）。默认全关，开启才对 payload 生效。
    tamper: { enabled: false, plugins: [], intensity: 'medium' },
  },
  techniques: ['union', 'error', 'boolean', 'time'],
  // ── 对标 sqlmap 高级检测选项（builtin 引擎，零回归默认值）──
  level: 1, // 检测等级 1-5
  risk: 1, // 风险等级 1-3
  timeSec: 2, // 时间盲注 SLEEP 秒数（--time-sec）
  requestDelayMs: 0, // 固定请求延时 ms（--delay）
  hpp: false, // HTTP 参数污染（--hpp）
  keepAlive: true, // 连接复用（--no-keep-alive 关闭）
  secondOrder: { enabled: false, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: false, manualStorePoints: [] }, // 二阶注入（--second-order）：默认关，开启需授权；manualStorePoints 手动指定存储点参数名
  oob: { enabled: false, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 }, // OOB 带外：默认关，启用需 risk>=3 + techniques 含 oob
};

// ── 扫描配置预设档位（对标 sqlmap --level/--risk 档位思想；仅建议值，用户可手动微调）──
// 三档权衡：快速=省资源/低风险；标准=均衡；激进=高覆盖/高负载/高风险(risk=3)。
// 预设只设 builtin 引擎相关字段，不自动开启二阶/OOB（需单独明确授权开关）。
export const SCAN_PRESETS: {
  quick: Partial<ScanConfig>;
  standard: Partial<ScanConfig>;
  aggressive: Partial<ScanConfig>;
} = {
  quick: {
    concurrency: 2,
    timeoutMs: 5000,
    retry: 0,
    timeThresholdMs: 300,
    ratePerSec: 20,
    level: 1,
    risk: 1,
  },
  standard: {
    concurrency: 4,
    timeoutMs: 10000,
    retry: 2,
    timeThresholdMs: 1500,
    ratePerSec: 3,
    level: 2,
    risk: 1,
  },
  aggressive: {
    concurrency: 10,
    timeoutMs: 30000,
    retry: 3,
    timeThresholdMs: 1000,
    ratePerSec: 5,
    level: 5,
    risk: 3,
  },
};

/** 预设档位中文标签 */
export const SCAN_PRESET_LABEL: Record<'quick' | 'standard' | 'aggressive', string> = {
  quick: '快速',
  standard: '标准',
  aggressive: '激进',
};

/** 性能参数出厂默认值（「恢复默认」按钮用）。
 *  仅覆盖性能字段，与预设档位字段范围一致；不含认证/代理/WAF/二阶/OOB，
 *  避免误清空用户已配置的凭证与规避开关。 */
export const SCAN_DEFAULTS: Partial<ScanConfig> = {
  concurrency: DEFAULT_CONFIG.concurrency,
  timeoutMs: DEFAULT_CONFIG.timeoutMs,
  retry: DEFAULT_CONFIG.retry,
  timeThresholdMs: DEFAULT_CONFIG.timeThresholdMs,
  ratePerSec: DEFAULT_CONFIG.ratePerSec,
  level: DEFAULT_CONFIG.level,
  risk: DEFAULT_CONFIG.risk,
};

/** 单次拖库单表行数上限 */
export const DUMP_ROW_LIMIT = 100;

// ── tamper 强度三档预设包（与后端 TamperRegistry 注册名严格一致）─────────────
// intensity 仅前端语义：点选即按预设填充 plugins，用户可在此之上微调。
// 预设里所有插件名均来自 tamperRegistry.list()（GET /api/tampers），无拼写漂移。
export const TAMPER_INTENSITY_PRESETS: Record<'low' | 'medium' | 'high', string[]> = {
  low: ['space2comment', 'randomcase'],
  medium: ['space2comment', 'randomcase', 'charencode'],
  high: ['space2comment', 'randomcase', 'charencode', 'modsecurityversioned', 'percentage', 'versionedkeywords'],
};

/** 强度三档中文标签 */
export const TAMPER_INTENSITY_LABEL: Record<'low' | 'medium' | 'high', string> = {
  low: '轻度',
  medium: '中度',
  high: '激进',
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
};
