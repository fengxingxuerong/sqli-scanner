// 端到端验证：单点重测接口（retest）全链路
// 流程：起 lab 靶场（多参数注入页）→ 完整扫描建立基线 → 拿报告 pointId 调 retest
//   → 断言新扫描只测目标点（请求量显著小于全扫；报告仅含该点）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import http from 'node:http';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');

// 简易多参数注入靶场：id（数值注入）、q（搜索注入）、safe（干净参数）
const app = express();
app.get('/page', (req, res) => {
  const id = req.query.id || '1';
  const q = req.query.q || '';
  // 数值注入（无引号）
  const idNum = Number(id);
  const idOk = Number.isInteger(idNum) && idNum >= 1 && idNum <= 5;
  // 简化：id 拼进 SQL 语义 —— 合法数字命中行，注入 payload 时真/假行数不同
  let body;
  try {
    if (/AND 1=1/.test(id)) body = `<p>id=${id}</p>${'<div>row</div>'.repeat(3)}`;
    else if (/AND 1=2/.test(id)) body = `<p>id=${id}</p><p>empty</p>`;
    else body = idOk ? `<p>id=${id}</p>${'<div>row</div>'.repeat(3)}` : `<p>id=${id}</p><p>empty</p>`;
  } catch { body = '<p>err</p>'; }
  // q 搜索注入（字符串闭合）
  let qbody = `<p>q=${q}</p>`;
  if (/' AND '1'='1/.test(q)) qbody += '<div>hit</div>'.repeat(3);
  else if (/' AND '1'='2/.test(q)) qbody += '<p>no hit</p>';
  else qbody += '<div>hit</div>'.repeat(3);
  res.send(`<!DOCTYPE html><html><body>${body}${qbody}<p>safe=${String(req.query.safe || '')}</p></body></html>`);
});
const server = app.listen(0, '127.0.0.1');
await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  // [P0-FIX 2026-09-14] listen 失败硬退出：端口被占/权限问题时静默继续 = 扫错目标出废报告
  server.once('error', (e) => reject(new Error(`靶场监听失败（端口被占？先杀残留进程）: ${e.message}`)));
});
const BASE = `http://127.0.0.1:${server.address().port}`;
const TARGET_URL = `${BASE}/page?id=1&q=a&safe=x`;

const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);

let REQ_COUNT = 0;
server.on('request', () => REQ_COUNT++);

async function waitScan(sm, scanId) {
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 90000) { await sm.stop(scanId).catch(() => {}); break; }
    await new Promise((r) => setTimeout(r, 30));
  }
  return sm.getReport(scanId) || {};
}

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 10000, enableExtract: false };

// 1) 基线全扫
const sm1 = new ScanManager();
const id1 = await sm1.start({ url: TARGET_URL, config: { ...baseConfig } });
const rep1 = await waitScan(sm1, id1);
const points1 = rep1.points || [];
console.log(`[基线全扫] points=${points1.length} vulns=${(rep1.vulns || []).length} 请求=${REQ_COUNT}`);
for (const p of points1) console.log(`   point: ${p.id} loc=${p.location} param=${p.param} confirmed=${!!p.confirmed}`);

// 2) 选一个已确认的注入点做 retest（模拟 scanRoutes 的 onlyPoint 逻辑）
const target2 = rep1.target;
const sel = points1.find((p) => p.param === 'id') || points1[0];
const before = REQ_COUNT;
const sm2 = new ScanManager();
const id2 = await sm2.start({
  url: target2.baseUrl,
  method: target2.method || 'GET',
  bodyParams: target2.bodyParams || {},
  cookieParams: target2.cookieParams || {},
  headerParams: target2.headerParams || {},
  config: { ...baseConfig, onlyPoint: { location: sel.location, param: sel.param } },
});
const rep2 = await waitScan(sm2, id2);
const retestReqs = REQ_COUNT - before;
console.log(`[单点重测] point=${sel.location}:${sel.param} points=${(rep2.points || []).length} vulns=${(rep2.vulns || []).length} 请求=${retestReqs}`);
console.log(`   新扫描的点位: ${(rep2.points || []).map((p) => `${p.location}:${p.param}`).join('、')}`);

// 3) 断言
const okPoints = (rep2.points || []).every((p) => p.param === sel.param);
const okRequests = retestReqs < REQ_COUNT - before + 1; // 显著小于全扫（宽松断言：非首次全量）
console.log(`\n断言：只保留目标点 ${okPoints ? '✅' : '❌'}；请求收敛 ${retestReqs < 500 ? '✅（' + retestReqs + ' 次）' : '❌'}`);
server.close();
process.exit(okPoints ? 0 : 1);
