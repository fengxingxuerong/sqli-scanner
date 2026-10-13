// =====================================================================
// extractMerge.js — 提取结果合并单核（design §2.1.3.9）
//
// 字段清单单点化：所有报告字段以一张表声明，冲突策略参数化。
// mergeExtracted / mergeExtractedForResume 成为本模块的两种策略薄包装。
// 新增报告字段只改 FIELD_TABLE 一处（历史 P0-FIX 两次栽在漏 search/meta）。
// =====================================================================

/**
 * 字段清单（单点化）：每个字段声明其类别与合并语义。
 *
 * @type {Array<{name:string, kind:'union'|'shallow'|'scalar'|'search'}>}
 */
const FIELD_TABLE = [
  { name: 'databases', kind: 'union' },
  { name: 'tables', kind: 'shallow' },
  { name: 'columns', kind: 'shallow' },
  { name: 'rows', kind: 'shallow' },
  { name: 'counts', kind: 'shallow' },
  { name: 'schemas', kind: 'shallow' },
  { name: 'meta', kind: 'shallow' },
  { name: 'currentDb', kind: 'scalar' },
  { name: 'currentUser', kind: 'scalar' },
  { name: 'users', kind: 'scalar' },
  { name: 'passwords', kind: 'scalar' },
  { name: 'passwordAnalysis', kind: 'scalar' },
  { name: 'hostname', kind: 'scalar' },
  { name: 'isDba', kind: 'scalar' },
  { name: 'userPrivs', kind: 'scalar' },
  { name: 'roles', kind: 'scalar' },
  { name: 'search', kind: 'search' },
];

/**
 * 合并提取字段：按 FIELD_TABLE 逐字段合并 src 到 target（就地修改 target）。
 *
 * @param {object} target - 目标对象（就地修改）
 * @param {object} src - 来源对象
 * @param {{onConflict?:'overwrite'|'keep'}} [opts] - 冲突策略
 *   - 'overwrite'：src 覆盖 target 已有值（mergeExtracted 语义）
 *   - 'keep'：target 已有值优先，src 仅填补缺失（mergeExtractedForResume 语义）
 * @returns {object} target（合并后）
 */
export function mergeFields(target, src, opts = {}) {
  const onConflict = opts.onConflict || 'overwrite';
  for (const { name, kind } of FIELD_TABLE) {
    if (src[name] === undefined) continue;
    switch (kind) {
      case 'union':
        mergeUnion(target, src, name);
        break;
      case 'shallow':
        mergeShallow(target, src, name, onConflict);
        break;
      case 'scalar':
        mergeScalar(target, src, name, onConflict);
        break;
      case 'search':
        mergeSearch(target, src, name, onConflict);
        break;
    }
  }
  return target;
}

function mergeUnion(target, src, name) {
  if (!target[name]) target[name] = [];
  for (const item of (src[name] || [])) {
    if (!target[name].includes(item)) target[name].push(item);
  }
}

function mergeShallow(target, src, name, onConflict) {
  if (onConflict === 'keep') {
    target[name] = { ...(src[name] || {}), ...(target[name] || {}) };
  } else {
    target[name] = { ...(target[name] || {}), ...(src[name] || {}) };
  }
}

function mergeScalar(target, src, name, onConflict) {
  if (onConflict === 'keep') {
    if (target[name] === undefined) target[name] = src[name];
  } else {
    target[name] = src[name];
  }
}

function mergeSearch(target, src, name, onConflict) {
  if (onConflict === 'keep') {
    if (!target[name]) target[name] = structuredClone(src[name]);
    return;
  }
  const prev = target[name] || {};
  const cur = src[name];
  const uniq = (a, b) => [...new Set([...(a || []), ...(b || [])])];
  target[name] = {
    keyword: cur.keyword ?? prev.keyword ?? null,
    matchedTables: uniq(prev.matchedTables, cur.matchedTables),
    matchedColumns: uniq(prev.matchedColumns, cur.matchedColumns),
  };
}

export { FIELD_TABLE };