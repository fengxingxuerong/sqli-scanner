// =====================================================================
// extractScope.js — 枚举/拖库动作族（extractScope）的形状校验器
// 自 scanConfigGuard.js 拆出（纯搬移，零依赖）：EXTRACT_SCOPE_MODES 白名单 /
// sanitizeIdentList / sanitizeExtractScope。scanConfigGuard.js 保持 re-export。
// =====================================================================
// ── [2026-09-23 E2] extractScope（枚举 / 拖库动作族）的形状校验 ──────────────
//
// 为什么补这一支：CLI 侧 `--dbs/--tables/--columns/--dump/--dump-all/--users/...` 一直是
// 「把参数解析成 config.extractScope 交给引擎」（bin/cli/config.js:314 buildExtractScope
// → ScanManager._extractByScope → engine/extractScope.js），而 REST 白名单**从未收录该键**
// → Web / 桌面 / API 三端完全没有枚举与拖库能力：传了会被当「未知字段」静默丢弃（仅一条 warn），
// 调用方拿到 200 + scanId，报告里是一句「未检出」——又一个静默假阴性。
//
// 为什么这里**不做字符集白名单**（与 paramDel / dumpWhere 的处理方式不同）：
//   库名/表名/列名会被**原样拼进 SQL**，但引擎侧所有拼接点都已经过了 `escSql()`
//   （extractionMaps.js 全文一致，形如 `WHERE table_schema='${escSql(db)}'`）。
//   在 REST 层再加一套字符集，只会与引擎的口径并存成两份真相：引擎放宽一次、这里就得跟一次，
//   而且真实的库表名可能含中文/空格/连字符 → 窄集合会**误拒合法输入**。
//   所以此处只校验**形状**：类型、非空、长度、元素数量、无控制字符。
//   （判据与危害同源：这里能造成的危害是「形状不对导致引擎 throw / 无界枚举」，不是注入。）
export const EXTRACT_SCOPE_MODES = new Set([
  'dbs', 'tables', 'columns', 'dump', 'dumpAll', 'commonTables', 'commonColumns', 'search',
  'currentDb', 'currentUser', 'hostname', 'isDba', 'users', 'passwords',
  'schema', 'privileges', 'roles', 'count',
  // [D46 2026-10-11 对标 sqlmap -b/--statements/--procs] 运维侦察三模式
  'banner', 'statements', 'procs',
]);

/** 字符串数组：去空、去重、拒控制字符、限长、限数量（超限截断而非整体丢弃） */
function sanitizeIdentList(v, maxItems) {
  if (!Array.isArray(v)) return undefined;
  const out = [];
  for (const raw of v) {
    if (typeof raw !== 'string') continue;
    const s = raw.trim();
    if (!s || s.length > 256) continue;
    if (/[\u0000-\u001f\u007f]/.test(s)) continue; // 控制字符：任何合法标识符都不含
    if (!out.includes(s)) out.push(s);
    if (out.length >= maxItems) break;
  }
  return out.length ? out : undefined;
}

/** 短文本字段形状闸（search 的 keyword 与 [D46] 的 user 同一形状：字符串、trim 非空、≤128、无控制字符）。
 * 抽成助手的原因：两处字面重复的形状闸占了基线余量，[D300] blindDump 入闸后以去重抵平（不放宽基线）。 */
function sanitizeKeyword128(v) {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s && s.length <= 128 && !/[\u0000-\u001f\u007f]/.test(s) ? s : undefined;
}

/**
 * 校验 /scan/start 的 config.extractScope。返回 undefined = 不启用枚举（保持既有全量行为）。
 * mode 必须在白名单内：它是引擎 switch 的判据，传错会直接 throw（extractScope.js:436）。
 */
export function sanitizeExtractScope(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const mode = typeof raw.mode === 'string' ? raw.mode.trim() : '';
  // [D300] blindDump：盲注 opt-in 拖库（scan/extractExtended.js 读取的开关，默认关）。
  // **允许无 mode 单传**：引擎对无 mode 的 scope 走全量拖库分支（engine/extractScope.js:15
  // 的 `scope && scope.mode` 判据），该键不参与模式 switch，mode 缺省不会触碰 default 分支。
  const blindDump = raw.blindDump === true;
  if (!EXTRACT_SCOPE_MODES.has(mode)) return blindDump ? { blindDump: true } : undefined;
  const out = { mode };
  if (blindDump) out.blindDump = true;
  const dbs = sanitizeIdentList(raw.dbs, 100);
  if (dbs) out.dbs = dbs;
  const tables = sanitizeIdentList(raw.tables, 500);
  if (tables) out.tables = tables;
  const cols = sanitizeIdentList(raw.cols, 500);
  if (cols) out.cols = cols;
  // search 的匹配关键字（进 LIKE 模式）与 [D46] -U 用户过滤：同一形状闸（引擎侧 escSql 转义）
  const kw = sanitizeKeyword128(raw.keyword);
  if (kw) out.keyword = kw;
  const user = sanitizeKeyword128(raw.user);
  if (user) out.user = user;
  // [D46] --exclude 库排除（标识符清单，与 dbs 同一 sanitize 闸）
  const excludeDbs = sanitizeIdentList(raw.excludeDbs, 16);
  if (excludeDbs) out.excludeDbs = excludeDbs;
  // 系统库过滤开关：默认 true（与 CLI buildExtractScope 的 ex() 一致）
  if (typeof raw.excludeSysdbs === 'boolean') out.excludeSysdbs = raw.excludeSysdbs;
  return out;
}
