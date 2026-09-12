// ============================================================================
// e2e/redteam-lab/diff-reports.mjs —— 两次扫描报告的「行为等价性」对比工具
//
// 用途：重构 / 拆分核心流程后，证明**行为没变**。
// 比"单测通过"更强的地方：单测覆盖不到时序与副作用，而报告字段是端到端的最终产物。
// （2026-09-12 用它验证 runScanLoop 拆分第一批：1184→1035 行，三靶点字段级一致。）
//
// 用法：
//   node e2e/redteam-lab/diff-reports.mjs <beforeDir> <afterDir> <id1,id2,...>
//   例：node e2e/redteam-lab/diff-reports.mjs \
//         e2e/redteam-lab/out/diff-before e2e/redteam-lab/out A1-int-union,C7-boolean
//   文件命名约定：<beforeDir>/<id>.json  与  <afterDir>/<id>*.json（自动匹配第一个）
//
// 对比口径：归一化掉「必然不同」的字段（时间戳、请求数、scanId/pointId 等随机 id），
// 只比结构化的结论字段；任何一项不一致即判失败（退出码 1），可直接用于 CI 门禁。
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';

const [beforeDir, afterDir, idList] = process.argv.slice(2);
if (!beforeDir || !afterDir || !idList) {
  console.error('用法：node diff-reports.mjs <beforeDir> <afterDir> <id1,id2,...>');
  process.exit(2);
}

// 匹配改后报告。⚠️ 不要用 readdirSync().find() 取"第一个匹配"——目录顺序由文件系统决定，
// 同一靶点常有多个档位结果（如 <id>.r1.json / <id>.r2.json），readdir 顺序下曾误取到 r1
// 而把档位差异误判成"重构导致行为变化"（2026-09-12 实测踩到）。
// 正确做法：精确名优先，其余按 mtime 取最新。
const findAfter = (dir, id) => {
  const cands = fs.readdirSync(dir)
    .filter((n) => n === `${id}.json` || new RegExp(`^${id}\\..*\\.json$`).test(n));
  if (!cands.length) throw new Error(`${dir} 下找不到 ${id} 的报告`);
  const exact = cands.find((n) => n === `${id}.json`);
  if (exact) return path.join(dir, exact);
  cands.sort((a, b) => fs.statSync(path.join(dir, b)).mtimeMs - fs.statSync(path.join(dir, a)).mtimeMs);
  if (cands.length > 1) {
    console.log(`   [提示] ${id} 有 ${cands.length} 个候选，取最新的 ${cands[0]}`);
  }
  return path.join(dir, cands[0]);
};

// 归一化：只保留结论性字段，去掉时间戳 / 随机 id / 请求数等「必然不同」的部分
const norm = (r) => {
  const ptById = new Map((r.points || []).map((p) => [p.id, p]));
  return {
    riskLevel: r.riskLevel,
    dbms: r.dbms || null,
    pointCount: (r.points || []).length,
    points: (r.points || []).map((p) => `${p.location}:${p.param}`).sort(),
    vulns: (r.vulns || []).map((v) => {
      const p = ptById.get(v.pointId) || {};
      return `${v.technique}|${v.riskLevel}|${p.location || '?'}:${p.param || '?'}`;
    }).sort(),
    dataKeys: Object.keys(r.data || {}).sort(),
    rowsKeys: Object.keys((r.data && r.data.rows) || {}).sort(),
    searchKeys: Object.keys((r.data && r.data.search) || {}).sort(),
    summaryKeys: Object.keys(r.summary || {}).filter((k) => !/time|At$|Duration/i.test(k)).sort(),
    validityStatus: r.validity?.status ?? null,
    blockPolicyAction: r.summary?.blockPolicy?.action ?? null,
    dbmsEvidenceLevel: r.summary?.dbmsEvidence?.level ?? null,
    healthAborted: r.dbHealth?.aborted ?? null,
  };
};

let allOk = true;
for (const id of idList.split(',').map((s) => s.trim()).filter(Boolean)) {
  const before = JSON.parse(fs.readFileSync(path.join(beforeDir, `${id}.json`), 'utf8'));
  const afterPath = findAfter(afterDir, id);
  const after = JSON.parse(fs.readFileSync(afterPath, 'utf8'));
  const a = norm(before), b = norm(after);
  const diffs = [];
  for (const k of Object.keys(a)) {
    const va = JSON.stringify(a[k]), vb = JSON.stringify(b[k]);
    if (va !== vb) {
      diffs.push(k);
      if (diffs.length <= 3) {
        console.log(`   [${id}] ${k}\n     改前: ${va.slice(0, 220)}\n     改后: ${vb.slice(0, 220)}`);
      }
    }
  }
  const ok = diffs.length === 0;
  if (!ok) allOk = false;
  console.log(`${ok ? '✅' : '❌'} ${id}  ${ok ? '报告字段一致' : '差异字段: ' + diffs.join(', ')}`);
}

console.log('');
console.log(allOk ? '结论：行为等价（报告字段级一致）' : '结论：存在行为差异，需排查');
process.exit(allOk ? 0 : 1);
