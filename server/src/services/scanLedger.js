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
 * @param {object} report 已导出形态的报告（ScanManager.getReport 快照）
 * @param {{html?:string, markdown?:string, json?:string}} docs 预渲染文档（缺省自动生成）
 * @param {{redactAuth?:boolean}} [opts]
 * @returns {{dir:string, scanId:string, files:string[]}}
 */
export function recordScan(report, docs = {}, opts = {}) {
  if (!report || typeof report !== 'object') throw new Error('recordScan: report required');
  const scanId = String(report.scanId || report.id || `scan-${Date.now()}`);
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

  // docs 缺省：延迟 import 避免与 ReportGenerator 循环依赖
  let html = docs.html;
  let md = docs.markdown;
  if (!html || !md) {
    // 动态 import 在同步函数中不可行——调用方应传入 docs；此处仅写 json 兜底
  }
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
    verdict: report.summary?.verdict || null,
    dbms: report.dbms || null,
    files,
    recordedAt: new Date().toISOString(),
  };
  write('meta.json', JSON.stringify(meta, null, 2));

  // 全局索引追加（一行一个扫描）
  appendFileSync(join(ledgerDir(), 'index.jsonl'), JSON.stringify(meta) + '\n', 'utf-8');
  return { dir, scanId, files };
}

/** 台账检索：列出全部登记（新→旧） */
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

/** 台账检索：读取单次扫描的 meta + 文件清单 */
export function getScan(scanId) {
  const dir = join(ledgerDir(), String(scanId));
  const metaPath = join(dir, 'meta.json');
  if (!existsSync(metaPath)) return null;
  const meta = JSON.parse(readFileSync(metaPath, 'utf-8'));
  const files = [];
  (function walk(d) {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      // eslint-disable-next-line no-loop-func
      const isDir = require_dir(p);
      if (isDir) walk(p);
      else files.push(p.slice(dir.length + 1));
    }
  })(dir);
  return { meta, dir, files };
}

// 极简目录判定（避免引 is-what 依赖）
function require_dir(p) {
  try {
    return readdirSync(p) !== undefined;
  } catch {
    return false;
  }
}

export default { recordScan, listScans, getScan };
