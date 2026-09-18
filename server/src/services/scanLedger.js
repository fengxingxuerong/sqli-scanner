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
// 目录默认 <repo>/data/ledger，可用 env SQLI_LEDGER_DIR 覆盖。
// ============================================================================
import { mkdirSync, writeFileSync, appendFileSync, existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve as pathResolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_DIR = pathResolve(HERE, '../../data/ledger');

function ledgerDir() {
  const d = process.env.SQLI_LEDGER_DIR || DEFAULT_DIR;
  mkdirSync(d, { recursive: true });
  return d;
}

/**
 * 台账登记：把一次扫描的完整快照写入 ledger。
 * @param {object} report 已导出形态的报告。**必须传 ReportGenerator.attachPoc() 的返回值**：
 *   poc 是惰性挂载且不可变的（_attachPoc 返回新对象），直接传原始 report 会让下面
 *   `if (!v.poc) continue` 全部命中 → poc/ 恒为空（2026-09-18 实测 163 次真实台账 0 个 poc 文件）。
 * @param {{html?:string, markdown?:string, json?:string}} [docs] 预渲染文档；缺省时只落 report.json
 * @param {{redactAuth?:boolean}} [opts] 预留（PoC 脱敏由 ReportGenerator 侧决定，此处不重复处理）
 * @returns {{dir:string, scanId:string, files:string[]}}
 */
export function recordScan(report, docs = {}, opts = {}) {
  void opts; // 预留参数：脱敏在 ReportGenerator 完成，此处不参与，显式声明以免误读
  if (!report || typeof report !== 'object') throw new Error('recordScan: report required');
  // [FIX 2026-09-18] scanId 会拼进落盘路径，必须收敛为单层目录名（原先 `../x` 可在
  // ledger 根目录之外创建目录，实测复现）。scanId 缺省时的自动生成值不受影响。
  const scanId = safeScanId(report.scanId || report.id || `scan-${Date.now()}`);
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
  if (docs.html) write('report.html', docs.html);
  if (docs.markdown) write('report.md', docs.markdown);
  write('report.json', docs.json || JSON.stringify(report, null, 2));

  // PoC 逐条落盘（与 ReportGenerator._pocEntries 同编号规则：poc-N-M-point.txt）
  let n = 0;
  for (const v of report.vulns || []) {
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
      writeFileSync(file, String(v.poc.raw || v.poc.curl || ''), 'utf-8');
      files.push(`poc/poc-${n}-${m}-${point}.txt`);
    }
  }

  const startedAt = report.startedAt || report.meta?.startedAt || null;
  const finishedAt = report.finishedAt || new Date().toISOString();
  const meta = {
    scanId,
    target: report.target?.url || report.target?.baseUrl || '-',
    method: report.target?.method || 'GET',
    startedAt,
    finishedAt,
    points: (report.points || []).length,
    vulns: (report.vulns || []).length,
    payloadHits: (report.vulns || []).reduce((acc, v) => acc + (Array.isArray(v.payloads) ? v.payloads.length : 0), 0),
    // [goal-FIX 2026-09-16] verdict 口径修正：vulns>0 时 summary.verdict 仍是阴性口径
    // （scanRunner 仅在无命中时区分 inconclusive/no_vulnerability_detected），台账若原样透传
    // 会出现「vulns=3 verdict=no_vulnerability_detected」的交付级自相矛盾。
    verdict: (report.vulns || []).length > 0 ? 'vulnerability_detected' : (report.summary?.verdict || 'no_vulnerability_detected'),
    dbms: report.dbms || null,
    files,
    recordedAt: new Date().toISOString(),
  };
  write('meta.json', JSON.stringify(meta, null, 2));

  // 全局索引追加（一行一个扫描）
  appendFileSync(join(ledgerDir(), 'index.jsonl'), JSON.stringify(meta) + '\n', 'utf-8');
  return { dir, scanId, files };
}

/** 台账检索：列出全部登记（取最新的 limit 条，新→旧） */
export function listScans(limit = 50) {
  const idx = join(ledgerDir(), 'index.jsonl');
  if (!existsSync(idx)) return [];
  const rows = readFileSync(idx, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  return rows.slice(-limit).reverse();
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
    throw new Error(`scanLedger: 非法 scanId（不得包含路径分隔符或 ..）：${s.slice(0, 80)}`);
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

export default { recordScan, listScans, getScan };
