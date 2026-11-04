// ============================================================================
// scanLedger.js —— 扫描台账（Goal Brief: scan-audit-ledger）
//
// 每次扫描导出/完成时把「可追溯快照」落盘到 <dataDir>/ledger/<scanId>/：
//   meta.json     扫描开始/结束时间、目标、注入点数、payload 命中数、结论、配置摘要
//   report.json   完整报告（含全部 payload 与 trace）
//   report.html   交付版 HTML
//   report.md     交付版 Markdown
//   poc/          逐条可复放请求（*.txt，-r 可直接导入）
// 追加写 meta.jsonl（全局索引行），供 `ledger list` / `ledger show <id>` 检索。
// 目录默认：SEA 单文件引擎 → <exe 目录>/data/ledger；node 跑源码 → 模块上两级。
// 优先级 --data-dir > SQLI_LEDGER_DIR > 形态默认值（见 ledgerDir()）。
// ============================================================================
import {
  mkdirSync, writeFileSync, appendFileSync, existsSync, readFileSync, readdirSync, rmSync, renameSync,
  // [D231] 尾部块读：只取索引末尾几 KB~MB，不必把整个索引读进内存
  openSync, fstatSync, readSync, closeSync,
} from 'node:fs';
import { join, dirname, resolve as pathResolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, ErrorCode } from '../core/errors.js';
// [P0-SEC 2026-11-02] 台账落盘统一脱敏：报告/文档/PoC 三处必须同源，
// 否则「导出已打码、台账仍明文」会变成第二条凭据泄露路径。
import { redactPersistedReport, redactPocText } from './reportRedaction.js';
import { isSeaRuntime } from '../core/sqlJsLoader.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * [DATADIR 2026-11-05] 形态默认值（优先级链的最后一档）：
 *   SEA 单文件引擎 → <exe 目录>/data/ledger（绿色包/桌面随包落盘，不再跑到 exe 上两级）；
 *   node 跑源码     → 模块上两级（保持原口径，绝不能落到 node.exe 所在目录）。
 * @param {{isSea?: boolean, execPath?: string, moduleDir?: string}} [opts] 测试注入缝
 * @returns {string}
 */
export function defaultLedgerDir(opts = {}) {
  const sea = opts.isSea ?? isSeaRuntime();
  return sea
    ? pathResolve(dirname(opts.execPath || process.execPath), 'data/ledger')
    : pathResolve(opts.moduleDir || HERE, '../../data/ledger');
}

// CLI `--data-dir` 的显式值（最高优先级）。相对路径在 setter 内按当前工作目录解析。
let cliDirOverride = '';
/** @param {string} dir */
export function setLedgerDirOverride(dir) {
  cliDirOverride = dir ? pathResolve(dir) : '';
}
/** 测试用：清空显式覆盖，避免用例互相污染。 */
export function _resetLedgerDirOverride() {
  cliDirOverride = '';
}

let legacyWarned = false;
/**
 * [DATADIR 2026-11-05] 旧默认位置（exe 上两级）已有台账、新默认位置为空时，提示一次而不搬数据。
 * 只在走"形态默认值"时检查——显式 --data-dir / SQLI_LEDGER_DIR 说明用户已经知道路径，不再打扰。
 * @param {string} dir 当前生效目录
 */
function warnLegacyLedgerOnce(dir) {
  if (legacyWarned || cliDirOverride || process.env.SQLI_LEDGER_DIR) return;
  if (!isSeaRuntime()) return;
  legacyWarned = true;
  const legacy = pathResolve(dirname(process.execPath), '../../data/ledger');
  if (legacy !== dir && existsSync(join(legacy, 'index.jsonl')) && !existsSync(join(dir, 'index.jsonl'))) {
    console.warn(
      `[ledger] 检测到旧位置有台账（${legacy}），新默认位置为空（${dir}）；` +
      '不会自动迁移，请用 --data-dir 指回旧位置或手动搬运。',
    );
  }
}

/**
 * 台账目录：`--data-dir`（CLI 显式） > `SQLI_LEDGER_DIR`（环境变量） > 形态默认值。
 * @returns {string}
 */
function ledgerDir() {
  const d = cliDirOverride || process.env.SQLI_LEDGER_DIR || defaultLedgerDir();
  if (!cliDirOverride && !process.env.SQLI_LEDGER_DIR) warnLegacyLedgerOnce(d);
  mkdirSync(d, { recursive: true });
  return d;
}

/** 落盘 HTML/Markdown 前统一过文本脱敏（调用方预渲染的文档也不豁免）。 */
function writeDocs(write, docs) {
  if (docs.html) write('report.html', redactPocText(docs.html));
  if (docs.markdown) write('report.md', redactPocText(docs.markdown));
}

/**
 * [P0-SEC 2026-11-02] report.json 内容统一来源：优先调用方预渲染 JSON，但**必须重新解析并脱敏**；
 * 解析失败/缺省则回退到已脱敏的报告对象。
 * @param {unknown} docsJson
 * @param {object} safeReport
 * @returns {string}
 */
function buildReportJson(docsJson, safeReport) {
  if (typeof docsJson === 'string' && docsJson) {
    try {
      return JSON.stringify(redactPersistedReport(JSON.parse(docsJson)), null, 2);
    } catch {
      /* 预渲染 JSON 损坏 ⇒ 回退安全报告 */
    }
  }
  return JSON.stringify(safeReport, null, 2);
}

/**
 * 台账登记：把一次扫描的完整快照写入 ledger。
 * @param {object} report 已导出形态的报告。**必须传 ReportGenerator.attachPoc() 的返回值**：
 *   poc 是惰性挂载且不可变的（_attachPoc 返回新对象），直接传原始 report 会让下面
 *   `if (!v.poc) continue` 全部命中 → poc/ 恒为空（2026-09-18 实测 163 次真实台账 0 个 poc 文件）。
 * @param {{html?:string, markdown?:string, json?:string}} [docs] 预渲染文档；缺省时只落 report.json
 * @param {{redactAuth?:boolean}} [opts] 预留（PoC 脱敏由 ReportGenerator 侧决定，此处不重复处理）
 * @returns {{dir:string, scanId:string, files:string[], pruned:object|null}} prune 结果（未配策略时为对象，异常时为 null）
 */
export function recordScan(report, docs = {}, opts = {}) {
  void opts; // 预留参数：脱敏在 ReportGenerator 完成，此处不参与，显式声明以免误读
  if (!report || typeof report !== 'object') throw new AppError(ErrorCode.INVALID_PARAM, 'recordScan: report required');
  // [P0-SEC 2026-11-02] 台账是**长期留存**的第二份报告：内存里/导出时脱敏过，不代表落盘这份也脱敏。
  // 统一在入口强制走 redactPersistedReport（auth/proxy/cookies/Authorization/token + PoC 凭据头）。
  const safeReport = redactPersistedReport(report);
  // [FIX 2026-09-18] scanId 会拼进落盘路径，必须收敛为单层目录名（原先 `../x` 可在
  // ledger 根目录之外创建目录，实测复现）。scanId 缺省时的自动生成值不受影响。
  const scanId = safeScanId(safeReport.scanId || safeReport.id || `scan-${Date.now()}`);
  const dir = join(ledgerDir(), scanId);
  const pocDir = join(dir, 'poc');
  mkdirSync(pocDir, { recursive: true });

  const files = [];
  const write = (name, content) => {
    const p = join(dir, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content, 'utf-8');
    files.push(name);
  };
  writeDocs(write, docs);
  write('report.json', buildReportJson(docs.json, safeReport));

  // PoC 逐条落盘（与 ReportGenerator._pocEntries 同编号规则：poc-N-M-point.txt）
  let n = 0;
  for (const v of safeReport.vulns || []) {
    if (!v || !v.poc) continue;
    n += 1;
    const point = String(v.pointId ?? '-');
    const list = Array.isArray(v.payloads) && v.payloads.length ? v.payloads : [v.poc.payload];
    let m = 0;
    const seen = new Set();
    for (const pl of list) {
      const p = String(pl ?? '');
      if (!p || seen.has(p)) continue;
      seen.add(p);
      m += 1;
      const file = join(pocDir, `poc-${n}-${m}-${point}.txt`);
      writeFileSync(file, redactPocText(String(v.poc.raw || v.poc.curl || '')), 'utf-8');
      files.push(`poc/poc-${n}-${m}-${point}.txt`);
    }
  }

  const startedAt = safeReport.startedAt || safeReport.meta?.startedAt || null;
  const finishedAt = safeReport.finishedAt || new Date().toISOString();
  const meta = {
    scanId,
    target: safeReport.target?.url || safeReport.target?.baseUrl || '-',
    method: safeReport.target?.method || 'GET',
    startedAt,
    finishedAt,
    points: (safeReport.points || []).length,
    vulns: (safeReport.vulns || []).length,
    payloadHits: (safeReport.vulns || []).reduce((acc, v) => acc + (Array.isArray(v.payloads) ? v.payloads.length : 0), 0),
    // [goal-FIX 2026-09-16] verdict 口径修正：vulns>0 时 summary.verdict 仍是阴性口径
    // （scanRunner 仅在无命中时区分 inconclusive/no_vulnerability_detected），台账若原样透传
    // 会出现「vulns=3 verdict=no_vulnerability_detected」的交付级自相矛盾。
    verdict: (safeReport.vulns || []).length > 0 ? 'vulnerability_detected' : (safeReport.summary?.verdict || 'no_vulnerability_detected'),
    dbms: safeReport.dbms || null,
    // [2026-09-29] History 页改由服务端 `GET /api/scans` 供数，UI 要显示风险等级色标；
    // 而台账 meta 此前只存 vulns 条数 ⇒ 前端只能显示"—"，等于接了服务端反而丢了信息。
    // 这里一次性把「最高风险」固化进 meta。**老台账读出来是 undefined ⇒ UI 显示"—"**，
    // 不回填、不猜 —— 没有就是没有。
    highestRisk: highestRisk(safeReport.vulns || []),
    files,
    recordedAt: new Date().toISOString(),
  };
  write('meta.json', JSON.stringify(meta, null, 2));

  // 全局索引追加（一行一个扫描）
  appendFileSync(join(ledgerDir(), 'index.jsonl'), JSON.stringify(meta) + '\n', 'utf-8');

  // 保留策略：写完立刻收敛本次增长。默认关闭（两个环境变量都未设 ⇒ pruneLedger 直接返回、
  // 一个目录都不删），因此既有行为零变化。失败不传播：prune 是附属动作，
  // 不能让"清理历史"把"记录本次"带崩（本次落盘已成功，prune 只能是尽力而为）。
  let pruned = null;
  try {
    pruned = pruneLedger({ dir: ledgerDir() });
  } catch (e) {
    consoleWarn(`台账保留策略执行失败（不影响本次落盘）：${e?.message ?? e}`);
  }
  return { dir, scanId, files, pruned };
}

/** [D231] 尾部块读的初始字节数（约 2700 行台账；不够时按 TAIL_GROW 倍扩） */
const TAIL_CHUNK_BYTES = 1024 * 1024;
/** [D231] 尾块不够 limit 条时的扩容倍率 */
const TAIL_GROW = 4;

/**
 * [D231] 读文件末尾至多 maxBytes 字节。
 * `atHead` 为真表示已读到文件头（首行完整）；否则首行被字节边界截断，调用方必须丢弃它
 * （UTF-8 多字节被切断时 `toString('utf8')` 会得到替换字符）。
 * @param {string} file
 * @param {number} maxBytes
 * @returns {{text: string, atHead: boolean}}
 */
function readTailChunk(file, maxBytes) {
  const fd = openSync(file, 'r');
  try {
    const size = fstatSync(fd).size;
    const start = Math.max(0, size - maxBytes);
    const len = size - start;
    const buf = Buffer.allocUnsafe(len);
    if (len > 0) readSync(fd, buf, 0, len, start);
    return { text: buf.toString('utf8'), atHead: start === 0 };
  } finally {
    closeSync(fd);
  }
}

/**
 * [D231] 从一段（可能被截头的）索引文本里反向取至多 limit 条有效登记。
 * 与旧实现 `split('\n').filter(Boolean).map(parse).filter(Boolean).slice(-limit).reverse()`
 * 同义：空行跳过、坏行跳过、falsy 行丢弃，结果按新→旧。
 * @param {string} text
 * @param {boolean} atHead 片段是否覆盖文件头
 * @param {number} limit
 * @returns {object[]}
 */
function parseTailRows(text, atHead, limit) {
  const out = [];
  let end = text.length;
  while (end > 0 && out.length < limit) {
    const nl = text.lastIndexOf('\n', end - 1);
    const start = nl === -1 ? 0 : nl + 1;
    const line = text.slice(start, end);
    const isHeadLine = start === 0;
    end = isHeadLine ? 0 : start - 1;
    // 截断片段的首行可能缺前半截，不可信 ⇒ 丢弃并结束（不是"解析失败"，无法从本片段补）
    if (isHeadLine && !atHead) break;
    if (!line) continue;
    try {
      const row = JSON.parse(line);
      if (row) out.push(row);
    } catch { /* 坏行跳过，同旧实现的 catch → null → filter(Boolean) */ }
  }
  return out;
}

/**
 * [D231] 全量解析路径：与 D231 之前的实现逐字等价（含 `slice(-limit)` 的反直觉语义）。
 * 两个调用点：limit 非正（语义特殊）、尾块扩容异常（防御退化）。
 * @param {string} idx 索引文件路径
 * @param {number} limit
 * @returns {object[]}
 */
function fullScanRows(idx, limit) {
  const rows = readFileSync(idx, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  return rows.slice(-limit).reverse();
}

/** 台账检索：列出全部登记（取最新的 limit 条，新→旧） */
export function listScans(limit = 50) {
  const idx = join(ledgerDir(), 'index.jsonl');
  if (!existsSync(idx)) return [];
  // limit 非正时保持**旧路径**：`rows.slice(-limit)` 对 0/负数的语义反直觉
  // （`slice(-0)` === `slice(0)` ⇒ 全量；`limit=-5` ⇒ 从第 5 条起），
  // 这里不动它，避免悄悄改变调用方看到的结果。
  if (!(Number(limit) > 0)) return fullScanRows(idx, limit);
  // [D231] 只读尾部字节块：旧实现把整个索引（本机实测 5.8MB / 15605 行）读进来
  // 再 split + 逐行 JSON.parse，每次历史列表 API 同步阻塞 30~40ms，且随台账线性恶化。
  // 现按块从尾部读，凑够 limit 条即停；块不够就按 TAIL_GROW 扩容，最坏退化为全量读。
  let chunk = TAIL_CHUNK_BYTES;
  for (;;) {
    const { text, atHead } = readTailChunk(idx, chunk);
    const rows = parseTailRows(text, atHead, limit);
    if (rows.length >= limit || atHead) return rows;
    const next = chunk * TAIL_GROW;
    // 防御：块不再增长（倍率配错 / 数值溢出）时退化全量读 —— 绝不在原地空转
    if (!(next > chunk)) return fullScanRows(idx, limit);
    chunk = next;
  }
}

/**
 * [FIX 2026-09-18] 校验 scanId 不得逃出 ledger 根目录。
 * 背景：getScan 的 scanId 直接来自 CLI 参数（`cli.js ledger show <scanId>`），完全用户可控；
 * recordScan 的 scanId 来自报告。二者都会拼进路径，`../x` 可越界读写（实测 recordScan 能
 * 在 ledger 目录之外建目录）。此处收敛为「单层目录名」语义：拒绝分隔符、`..`、绝对路径。
 * @param {unknown} scanId
 * @returns {string} 安全的单层目录名
 * @throws {Error} 非法 scanId
 */
function safeScanId(scanId) {
  const s = String(scanId ?? '');
  if (!s || s === '.' || s === '..' || /[\\/]/.test(s) || path_isAbsolute(s) || s.includes('\0')) {
    throw new AppError(ErrorCode.SCAN_ID_INVALID, `scanLedger: 非法 scanId（不得包含路径分隔符或 ..）：${s.slice(0, 80)}`);
  }
  return s;
}

/**
 * 台账检索：读取单次扫描的 meta + 文件清单。
 * [FIX 2026-09-18] files 统一使用 `/` 分隔（此前用 join 产出平台分隔符，Windows 下为
 * `poc\poc-1-1-p1.txt`，与 recordScan 写入 meta.files 的 `poc/poc-1-1-p1.txt` 口径不一致，
 * 导致消费方按 `startsWith('poc/')` 过滤时恒为空）。
 */
export function getScan(scanId) {
  const id = safeScanId(scanId);
  const dir = join(ledgerDir(), id);
  const metaPath = join(dir, 'meta.json');
  if (!existsSync(metaPath)) return null;
  const meta = JSON.parse(readFileSync(metaPath, 'utf-8'));
  const files = [];
  (function walk(d) {
    for (const ent of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, ent.name);
      // withFileTypes 直接给出类型，不再靠 readdirSync 抛 ENOTDIR 反推（对符号链接/权限
      // 异常更稳）。符号链接按目录处理会跟随，故先判 isDirectory 再判 isSymbolicLink。
      if (ent.isDirectory()) walk(p);
      else if (ent.isSymbolicLink() && isDirEntry(p)) walk(p);
      else files.push(relPosix(dir, p));
    }
  })(dir);
  return { meta, dir, files };
}

/** 相对根目录的 POSIX 风格相对路径（统一 `/`，跨平台一致） */
function relPosix(root, p) {
  return p.slice(root.length + 1).split(/[\\/]/).join('/');
}

/** 路径是否为绝对路径（避免直接依赖 path.isAbsolute 的平台歧义） */
function path_isAbsolute(p) {
  return /^([a-zA-Z]:[\\/]|[\\/])/.test(p);
}

/** 判定符号链接目标是否为目录（仅符号链接分支使用） */
function isDirEntry(p) {
  try {
    return readdirSync(p) !== undefined;
  } catch {
    return false;
  }
}

/**
 * 读取台账里的完整报告（report.json）。
 *
 * 为什么需要：台账早就存在（CLI / 一键扫描都写），而 **REST/Web 侧完全没接** ——
 * 引擎的扫描上下文在完成后 30s 就被回收（ScanManager._retire），于是
 * `GET /api/scan/:id/report` 在真实交付里迟早会变成"扫描不存在或已结束"：
 * 使用者刷新页面、换台机器、或者只是隔夜再点开那条 finding，数据就没了
 * （History 页当时显示的是浏览器 localStorage，不是服务端）。
 * 本函数就是那条回退读取路径：读不到返回 null，不抛错——回退是增强，不是主链路。
 * @param {string} scanId
 * @returns {object|null} 台账中保存的报告（recordScan 落盘时已是 attachPoc 之后的形态）
 */
export function readReport(scanId) {
  let id;
  try {
    id = safeScanId(scanId);
  } catch {
    return null; // 非法 id 与"没这条记录"同形：调用方按未找到处理，不额外暴露判据
  }
  const p = join(ledgerDir(), id, 'report.json');
  if (!existsSync(p)) return null;
  try {
    const parsed = JSON.parse(readFileSync(p, 'utf-8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (e) {
    consoleWarn(`台账 report.json 解析失败（${id}）：${e.message}`);
    return null;
  }
}

// ============================================================================
// 台账保留策略（retention）—— 2026-09-29
//
// 背景：每次 recordScan 都追加一行 index.jsonl 并落一整个目录（meta/report/html/md/poc），
// 长期跑的实例只会单调增长，无上限也无淘汰（TODO「接口靶场遗留项」第 5 条）。
//
// 三条设计取舍：
//   ① **默认关闭**：删用户扫描产物是有损操作，不能因为升了个版本就静默清历史。
//      只有显式设 SCAN_LEDGER_MAX / SCAN_LEDGER_MAX_DAYS 才淘汰，未设 ⇒ 零行为变化。
//   ② **目录与索引必须同批消失**：只删目录不删索引 ⇒ 列表里还在、点开 404；
//      只删索引不删目录 ⇒ 磁盘不释放。二者在同一次 prune 内成对处理。
//   ③ **先原子重写索引、再删目录**：顺序刻意倒过来（看似该先删数据再记账）。
//      理由看失败模式——
//        先删目录：目录删成功而索引重写失败 ⇒ 列表里有、读不到 ⇒ **半份数据**（最坏）。
//        先写索引：索引已收敛而目录删除失败 ⇒ 磁盘泄漏 + 一条孤儿目录 ⇒ 列表干净、可重试。
//      宁可泄漏也不能出现"不知道是不是删了一半"的状态。
// ============================================================================

/** 把 env 值解析成正整数；空/非法/负数一律 0（= 该维度不限制） */
function positiveInt(v) {
  const n = Number.parseInt(String(v ?? '').trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * 当前生效的保留策略（环境变量驱动）。
 * @returns {{max:number, maxDays:number}} 0 = 不限制
 */
export function retentionPolicy() {
  return {
    max: positiveInt(process.env.SCAN_LEDGER_MAX),
    maxDays: positiveInt(process.env.SCAN_LEDGER_MAX_DAYS),
  };
}

/**
 * 台账记录的可排序时间戳（毫秒）。取不到时间字段 ⇒ -Infinity（视作最老，最优先被淘汰）。
 * ⚠️ 不能兜底成 Date.now()/0：前者会让它永远最新（永远不淘汰 = 泄漏），
 *    后者会让"没时间戳的新条目"被误杀。取负无穷的代价只是它排在最前被清 —— 缺时间戳者先走。
 * @param {object} row 索引行
 * @returns {number}
 */
function entryTs(row) {
  const raw = row?.finishedAt ?? row?.recordedAt ?? row?.startedAt;
  const t = Date.parse(String(raw ?? ''));
  return Number.isFinite(t) ? t : -Infinity;
}

/**
 * 按保留策略淘汰台账条目：删目录 + 从索引移除（成对）。
 * @param {{dir?:string, policy?:{max?:number,maxDays?:number}, now?:number}} [opts]
 * @returns {{removed:number, kept:number, removedIds:string[], keptIds:string[], failed:Array<{id:string,error:string}>, skipped:boolean, reason:string}}
 */
export function pruneLedger(opts = {}) {
  /** @type {{removed:number, kept:number, removedIds:string[], keptIds:string[], failed:Array<{id:string,error:string}>, skipped:boolean, reason:string}} */
  const res = { removed: 0, kept: 0, removedIds: [], keptIds: [], failed: [], skipped: false, reason: '' };
  const dir = opts.dir || ledgerDir();
  const policy = opts.policy || retentionPolicy();
  const max = positiveInt(policy?.max);
  const maxDays = positiveInt(policy?.maxDays);

  if (!max && !maxDays) {
    res.skipped = true;
    res.reason = 'no-limit'; // 未配策略 = 不淘汰
    return res;
  }
  const idxPath = join(dir, 'index.jsonl');
  if (!existsSync(idxPath)) {
    res.skipped = true;
    res.reason = 'no-index';
    return res;
  }

  // 解析索引：有效行去重（同 scanId 保留最新一行），坏行不参与判定但原样留回。
  // 顺带修掉"重复登记"——recordScan 是 appendFileSync，同一 scanId 再记一次会多一行，
  // 列表于是出现两条同名目。重写是唯一能收敛它的时机。
  const rawLines = readFileSync(idxPath, 'utf-8').split('\n');
  const byId = new Map();
  const order = [];
  const others = [];
  let rowCount = 0; // 有效 JSON 行数（去重前）—— 与去重后行数对比得出「是否有重复登记」
  for (const line of rawLines) {
    if (!line.trim()) continue; // 空行不回写
    let row = null;
    try {
      row = JSON.parse(line);
    } catch {
      others.push(line);
      continue;
    }
    if (!row || typeof row !== 'object') { others.push(line); continue; }
    const id = String(row.scanId ?? '');
    if (!id) { others.push(line); continue; }
    rowCount += 1;
    if (byId.has(id)) byId.set(id, row); // 后写的更新 ⇒ 保留最后一次登记
    else { byId.set(id, row); order.push(id); }
  }
  const rows = order.map((id) => byId.get(id));
  const hasDuplicate = rowCount > rows.length;

  const keep = new Set(rows.map((r) => String(r.scanId)));
  // ① 天数维度：早于 cutoff 的直接出局
  if (maxDays) {
    const nowMs = Number.isFinite(opts.now) ? Number(opts.now) : Date.now();
    const cutoff = nowMs - maxDays * 86400000;
    for (const r of rows) {
      if (entryTs(r) < cutoff) keep.delete(String(r.scanId));
    }
  }
  // ② 条数维度：天数筛剩下的里按时间降序只留最新 max 条
  if (max && keep.size > max) {
    const survivors = rows
      .filter((r) => keep.has(String(r.scanId)))
      .sort((a, b) => entryTs(b) - entryTs(a));
    for (const r of survivors.slice(max)) keep.delete(String(r.scanId));
  }

  const keepLines = rows.filter((r) => keep.has(String(r.scanId))).map((r) => JSON.stringify(r));
  const dropIds = rows.map((r) => String(r.scanId)).filter((id) => !keep.has(id));
  // ⚠️ 早退条件不能只看 dropIds：重复登记的行只能靠"重写索引"收敛，
  //    此时一条都不用删、却必须重写。少了 `hasDuplicate` 这一项，索引里的重复项永远去不掉。
  if (!dropIds.length && !hasDuplicate) {
    res.kept = keep.size;
    res.keptIds = [...keep];
    res.reason = 'nothing-to-drop';
    return res;
  }

  // ③ 先原子替换索引（rename 失败 ⇒ 索引保持原样，一个目录都不删）
  const tmp = join(dir, 'index.jsonl.prune.tmp');
  writeFileSync(tmp, [...others, ...keepLines].map((l) => `${l}\n`).join(''), 'utf-8');
  try {
    renameSync(tmp, idxPath);
  } catch (e) {
    res.skipped = true;
    res.reason = `rewrite-index-failed: ${e?.message ?? e}`;
    res.kept = keep.size;
    consoleWarn(`台账索引重写失败，本次未删除任何历史目录（${res.reason}）`);
    return res;
  }

  // ④ 再删目录：单条失败不算失败（记进 failed 供运维追），不影响其余条目
  for (const id of dropIds) {
    try {
      rmSync(join(dir, safeScanId(id)), { recursive: true, force: true });
      res.removed += 1;
      res.removedIds.push(id);
    } catch (e) {
      res.failed.push({ id, error: String(e?.message ?? e) });
    }
  }
  res.kept = keep.size;
  res.keptIds = [...keep];
  return res;
}

/**
 * 取 vulns 里的最高风险等级。
 * 只认四档规范值 —— 未知/缺字段一律跳过（返回 null），不猜也不兜底：
 * 前端 `t('risk.' + lower)` 拿到规范外的值会渲染出 i18n key 原文，比显示"—"更难看。
 * @param {Array<{riskLevel?:string}>} vulns
 * @returns {string|null}
 */
const RISK_ORDER = ['Low', 'Medium', 'High', 'Critical'];
export function highestRisk(vulns) {
  let best = null;
  for (const v of vulns || []) {
    const r = v?.riskLevel;
    if (!r || !RISK_ORDER.includes(r)) continue;
    if (best === null || RISK_ORDER.indexOf(r) > RISK_ORDER.indexOf(best)) best = r;
  }
  return best;
}

/** 台账根目录（响应里如实标注数据落在哪，便于归档与取证） */
export function ledgerRoot() {
  return ledgerDir();
}

function consoleWarn(msg) {
  try {
    console.warn(`[scanLedger] ${msg}`);
  } catch {
    /* 无控制台（打包进 sidecar）时忽略 */
  }
}

export default { recordScan, listScans, getScan, readReport, ledgerRoot, pruneLedger, retentionPolicy, highestRisk };
