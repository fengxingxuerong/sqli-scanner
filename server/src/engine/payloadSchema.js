// ============================================================================
// payloadSchema.js —— 声明式 payload 的 schema（枚举 / 结构 / 约束）+ 校验器
//
// ■ 这是 E5「payload 声明式 DSL」的**第一步**，范围是刻意收窄的：
//   **只定义 schema 并校验现有数据，不切换任何加载源。**
//   `PAYLOAD_REGISTRY`（payloadRegistry.js）继续作为唯一取数源，本模块零行为变更。
//
// ■ 为什么必须先做这一步（而不是直接抽 YAML/JSON）
//   直接抽 DSL 的风险是「schema 与真实数据对不上」——681 条里有多少可选字段、枚举实际取到哪些值、
//   有没有既成事实的脏数据，不先量清楚就动手，切换时只会把问题搬过去再爆一次。
//   所以第一步的判据是：**现有全部条目必须能被 schema 完整描述并通过校验**；
//   过不了的部分就是真问题（要么修数据，要么扩 schema 并说明理由），当场暴露。
//
// ■ 分级约定（沿用 payloadRegistry.js 头注释，对标 sqlmap）
//   level 1-5：复杂度/边界探测深度；risk 1-3：破坏性；
//   where: 'value' 值位置（谓词值） / 'position' 位置注入（ORDER BY / LIMIT 列位置）。
//
// ■ error 与 warning 的分界
//   - error：**结构性/枚举性**错误（字段缺失、取值越界）—— DSL 化的硬阻塞。
//   - warning：**一致性**可疑（如 where:'position' 却没带 orderby/limit 类 clause）——
//     可能是刻意设计，只提示不阻塞（避免把「我没理解的合法用法」判成错误）。
// ============================================================================

/** technique 允许值（与 payloads.js 的 TECHNIQUE_TYPES 对齐） */
export const TECHNIQUE_VALUES = [
  'union', 'error', 'boolean', 'time', 'stacked', 'oob', 'second_order', 'inline',
];

/** where 允许值：值位置 / 位置注入 */
export const WHERE_VALUES = ['value', 'position'];

/** clause 允许值（子句位置；顺序即消费优先级，见 payloads/index.js 注释） */
export const CLAUSE_VALUES = ['where', 'orderby', 'groupby', 'having', 'limit', 'update'];

/** level / risk 取值区间（对标 sqlmap） */
export const LEVEL_RANGE = { min: 1, max: 5 };
export const RISK_RANGE = { min: 1, max: 3 };

/** 属于「位置注入」的子句（where:'position' 的条目应挂这些） */
export const POSITION_CLAUSES = ['orderby', 'limit', 'update'];

/**
 * schema 认识的字段全集。**这是防漂移的关键清单**：
 * 现有数据里若出现本集合之外的字段，说明 schema 落后于数据（DSL 化会静默丢字段），
 * 由 waf.payloadSchema 测试用真实注册表机械比对并报错 —— 不靠人记得同步。
 */
export const KNOWN_FIELDS = [
  'id', 'dbms', 'technique', 'level', 'risk', 'clause', 'boundary',
  'template', 'falseTemplate', 'where', 'minVersion', 'maxVersion',
];

/** 高危池标记（id 含此串，见 payloadRegistry 的 destructive 策略） */
export const DESTRUCTIVE_ID_MARK = '-dest-';

/**
 * 纯对象判定 —— 写成**类型谓词**（`@returns {v is ...}`），让 checkJs 能在后续分支里收窄类型。
 * 写成普通 boolean 时，`toDslEntry` 里的 `JSON.stringify(e)` 会报
 * `Argument of type '{} | null' is not assignable`（实测 TS2769）。
 * ⚠️ 值类型用 `any` 而非 `unknown`：本模块是**运行时校验器**，入参天然是未知形状，
 *    用 `unknown` 会让 `e.level` 无法做数值比较（实测 TS18046：`'e.level' is of type 'unknown'`），
 *    而校验逻辑恰恰就是要对这些值做区间判断。
 * @param {unknown} v
 * @returns {v is Record<string, any>}
 */
const isPlainObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * 校验单条声明。
 * @param {object} e 待校验条目
 * @returns {{ok: boolean, errors: string[], warnings: string[]}}
 */
export function validatePayloadEntry(e) {
  const errors = [];
  const warnings = [];
  if (!isPlainObj(e)) return { ok: false, errors: ['条目不是对象'], warnings };

  // —— 结构性（error）——
  if (typeof e.id !== 'string' || !e.id) errors.push('id 必须是非空字符串');
  if (!Array.isArray(e.dbms) || e.dbms.length === 0) errors.push('dbms 必须是非空数组');
  else if (e.dbms.some((d) => typeof d !== 'string' || !d)) errors.push('dbms 数组内必须是非空字符串');

  if (typeof e.technique !== 'string') errors.push('technique 必须是字符串');
  else if (!TECHNIQUE_VALUES.includes(e.technique)) errors.push(`technique 取值非法：${e.technique}`);

  if (!Number.isInteger(e.level) || e.level < LEVEL_RANGE.min || e.level > LEVEL_RANGE.max) {
    errors.push(`level 必须是 ${LEVEL_RANGE.min}-${LEVEL_RANGE.max} 的整数（实际：${e.level}）`);
  }
  if (!Number.isInteger(e.risk) || e.risk < RISK_RANGE.min || e.risk > RISK_RANGE.max) {
    errors.push(`risk 必须是 ${RISK_RANGE.min}-${RISK_RANGE.max} 的整数（实际：${e.risk}）`);
  }

  if (e.clause !== undefined) {
    if (!Array.isArray(e.clause)) errors.push('clause 必须是数组');
    else {
      for (const c of e.clause) {
        if (!CLAUSE_VALUES.includes(c)) errors.push(`clause 取值非法：${c}`);
      }
    }
  }
  if (e.where !== undefined && !WHERE_VALUES.includes(e.where)) {
    errors.push(`where 取值非法：${e.where}`);
  }
  if (typeof e.template !== 'string' || !e.template) errors.push('template 必须是非空字符串');
  if (e.falseTemplate !== undefined && typeof e.falseTemplate !== 'string') {
    errors.push('falseTemplate 若存在必须是字符串');
  }
  if (e.boundary !== undefined) {
    if (!Array.isArray(e.boundary)) errors.push('boundary 必须是数组');
    else if (e.boundary.some((b) => typeof b !== 'string')) errors.push('boundary 内必须是字符串');
  }
  // 版本区间：数字 或 {major, minor?}
  for (const key of ['minVersion', 'maxVersion']) {
    const v = e[key];
    if (v === undefined) continue;
    const okNum = typeof v === 'number' && Number.isFinite(v);
    const okObj = isPlainObj(v) && typeof v.major === 'number';
    if (!okNum && !okObj) errors.push(`${key} 必须是数字或 {major, minor?}（实际：${JSON.stringify(v)}）`);
  }

  // —— 一致性（warning，不阻塞）——
  if (e.where === 'position') {
    const hasPositionClause = Array.isArray(e.clause) &&
      e.clause.some((c) => POSITION_CLAUSES.includes(c));
    if (!hasPositionClause) {
      warnings.push(`where='position' 但 clause 未含 ${POSITION_CLAUSES.join('/')}`);
    }
  }
  // ⚠️ **不要**加「boolean 必须有 falseTemplate」这条判据 —— 实测（2026-09-22）注册表里
  //    boolean 条目有**两种合法形态**：
  //      · 成对型：template(真) + falseTemplate(假)，如 mysql-bool-sq-1；
  //      · 半边型：只有 template，且内容本身就是假值半边（如 mysql-boolean-100 的
  //        `{ORIG}' AND '1'='2`）—— 取自 PAYLOADS 的 boolean 数组，配对在上游完成。
  //    单条层面无法区分「漏配」与「刻意半边」，加这条只会制造噪声（首版即如此，已移除）。
  if (typeof e.id === 'string' && e.id.includes(DESTRUCTIVE_ID_MARK) && e.risk !== RISK_RANGE.max) {
    warnings.push(`id 含高危标记 ${DESTRUCTIVE_ID_MARK} 但 risk=${e.risk}`);
  }

  return { ok: errors.length === 0, errors, warnings };
}

/**
 * 批量校验。
 * @param {Array<object>} entries
 * @returns {{total:number, okCount:number, failed:Array<{index:number, id:string|null, errors:string[]}>, warnings:Array<{index:number, id:string|null, warnings:string[]}>, duplicateIds:string[]}}
 */
export function validatePayloadEntries(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const failed = [];
  const warnings = [];
  const seen = new Map();
  const duplicateIds = [];
  let okCount = 0;

  list.forEach((e, index) => {
    const r = validatePayloadEntry(e);
    if (r.ok) okCount += 1;
    else failed.push({ index, id: e && typeof e.id === 'string' ? e.id : null, errors: r.errors });
    if (r.warnings.length) {
      warnings.push({ index, id: e && typeof e.id === 'string' ? e.id : null, warnings: r.warnings });
    }
    const id = e && e.id;
    if (typeof id === 'string' && id) {
      if (seen.has(id)) duplicateIds.push(id);
      else seen.set(id, index);
    }
  });

  return { total: list.length, okCount, failed, warnings, duplicateIds: [...new Set(duplicateIds)] };
}

/**
 * DSL 化：把条目转成**纯 JSON-safe** 的形式（可落 YAML/JSON）。
 * 只做浅层规整（丢 undefined、数组拷贝），不改字段名 —— 字段重命名是切换时的决策，不在本步。
 * @param {object} e
 * @returns {object}
 */
export function toDslEntry(e) {
  if (!isPlainObj(e)) return {};
  return JSON.parse(JSON.stringify(e));
}

/**
 * JSON-safe 判据：DSL 化的前提（YAML/JSON 装不下 undefined / 函数 / Symbol / BigInt）。
 * @param {unknown} v
 * @returns {boolean}
 */
export function isJsonSafe(v) {
  if (v === undefined) return false;
  if (typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') return false;
  if (Array.isArray(v)) return v.every(isJsonSafe);
  if (isPlainObj(v)) return Object.values(v).every(isJsonSafe);
  return true;
}

/** schema 自描述（供报告/测试引用，避免枚举值在多处手抄后漂移） */
export function schemaSummary() {
  return {
    techniques: [...TECHNIQUE_VALUES],
    whereValues: [...WHERE_VALUES],
    clauseValues: [...CLAUSE_VALUES],
    level: { ...LEVEL_RANGE },
    risk: { ...RISK_RANGE },
    destructiveIdMark: DESTRUCTIVE_ID_MARK,
  };
}

export default { validatePayloadEntry, validatePayloadEntries, toDslEntry, isJsonSafe, schemaSummary };
