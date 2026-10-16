// D87 整链真机验证（网络门控：需能出网访问协作端）
// ============================================================================
// 验证面：真实 ScanManager 扫描 → OobDetector 投放 OOB 载荷 → 靶站"数据库"执行
// 带外原语（真实发起 DNS 解析 / HTTP 回连）→ interactsh 协作端记录 → 扫描器 poll
// 取回 → 归因到本次 token → OOB 技术命中。
//
// 与既有 e2e/oob-real-lab 的分工（互补，不替代）：
//   · 既有套件：**本地接收端**（真 PG COPY TO PROGRAM → 回连本机）
//   · 本套件：**外部隧道**（回连协作端，扫描器只需出网）——补 P1-3 的拓扑面
//
// ⚠ 靶站语义说明（避免误读为"真实 DBMS 行为"）：本靶站是一台"无回显"的 HTTP 应用，
// 它把载荷里出现的主机名解释为「数据库尝试做带外解析/连接」，因此对两种载荷形态都动作：
//   · HTTP/URL 形态（Oracle UTL_HTTP、MSSQL xp_cmdshell ping 等用 {CALLBACK}）→ 真实 HTTP 请求
//   · UNC 主机形态（MySQL/MariaDB/TiDB LOAD_FILE、MSSQL xp_dirtree 等用 {UNC}）→ 真实 DNS 解析
//     （真实环境里 UNC 由 Windows 解析成 DNS 查询再走 SMB；Linux MySQL 无此行为，见文档边界）
// 这是**靶站侧的模拟**，用于证明隧道链路与归因判据成立，不证明某个 DBMS 原语的可用性。
//
// 网络门控：无法访问协作端时**跳过并如实标注**（不计通过，也不计失败）。
// 复跑：SSRF_ALLOW_PRIVATE=1 node e2e/oob-interactsh-lab/run.mjs
// ============================================================================

import http from 'node:http';
import dns from 'node:dns/promises';
import { oobTunnel } from '../../server/src/core/oobTunnel.js';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const PORT = Number(process.env.OOB_INT_LAB_PORT) || 8177;
const SERVER = process.env.OOB_INT_SERVER || 'oast.pro';
const BASE_CONFIG = {
  concurrency: 1,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 10000,
  techniques: ['oob'],
  enableExtract: false,
  level: 1,
  // oob 在 risk 1 被技术门控排除（避免出站请求），本套件专测 OOB 故用 risk 2
  risk: 2,
  oob: {
    enabled: true,
    timeoutMs: 30000,
    interactsh: { enabled: true, server: SERVER, pollIntervalMs: 1500 },
  },
  productionMode: false,
};

/** 从载荷中提取协作端主机名（HTTP/URL 形态与 UNC 形态都要认） */
function extractCallbackHost(text, server) {
  const s = String(text || '');
  const hostRe = new RegExp(`([a-z0-9]{20,}[a-z0-9]*)\\.${server.replace(/\./g, '\\.')}`, 'i');
  const m = s.match(hostRe);
  return m ? m[1] + '.' + server : null;
}

function startLab() {
  const state = { hits: 0, dns: 0, http: 0 };
  const server = http.createServer(async (req, res) => {
    state.hits += 1;
    const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
    // 载荷可能出现在任意参数值里（引擎会按注入点位置投放）
    const raw = [...u.searchParams.values()].join(' ');
    const host = extractCallbackHost(raw, SERVER);
    if (host) {
      // UNC 形态 → 真实 DNS 解析（interactsh 的 DNS 通道据此记录）
      state.dns += 1;
      dns.lookup(host).catch(() => {});
      // HTTP 形态 → 真实 HTTP 回连（interactsh 的 HTTP 通道据此记录）
      state.http += 1;
      fetch(`http://${host}/oob`, { signal: AbortSignal.timeout(8000) }).catch(() => {});
    }
    // 永远返回同一个"正常"页面：无回显、无报错、无时间差——这正是 OOB 通道存在的意义
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><html><body><p>ok</p></body></html>');
  });
  return {
    state,
    listen: () => new Promise((r) => server.listen(PORT, '127.0.0.1', r)),
    close: () => new Promise((r) => server.close(r)),
  };
}

async function networkOk() {
  try {
    const r = await fetch(`https://${SERVER}/`, { signal: AbortSignal.timeout(8000) });
    return r.status > 0;
  } catch {
    return false;
  }
}

const lab = startLab();
await lab.listen();
console.log(`[lab] 靶站就绪 http://127.0.0.1:${PORT}/item?id=1（无回显、无报错、无时间差）`);

if (!(await networkOk())) {
  console.log(`[SKIP] 无法访问协作端 ${SERVER} —— 本套件需出网，跳过（不计通过亦不计失败）`);
  await lab.close();
  process.exit(0);
}

const sm = new ScanManager({});
const scanId = await sm.start({ url: `http://127.0.0.1:${PORT}/item?id=1`, config: BASE_CONFIG });

const t0 = Date.now();
let report = null;
for (;;) {
  const s = sm.scans.get(scanId);
  if (s && (s.status === 'completed' || s.status === 'error')) {
    report = sm.getReport(scanId);
    break;
  }
  if (Date.now() - t0 > 120000) {
    sm.stop(scanId);
    console.log('❌ 扫描超时');
    await lab.close();
    await oobTunnel.stop().catch(() => {});
    process.exit(1);
  }
  await new Promise((r) => setTimeout(r, 100));
}

const vulns = (report && report.vulns) || [];
const oobHit = vulns.filter(
  (v) => String(v.technique || '') === 'oob' || /oob|带外|OOB/i.test(JSON.stringify(v))
);
console.log(`[scan] 靶站收到请求 ${lab.state.hits} 次（DNS 解析 ${lab.state.dns} · HTTP 回连 ${lab.state.http}）`);
console.log(`[scan] 检出漏洞 ${vulns.length} 条，其中 OOB 通道 ${oobHit.length} 条`);
for (const v of vulns.slice(0, 3)) {
  console.log(`   · ${v.vulnType?.nameZh || v.type || v.technique} | ${v.riskLevel || '-'} | 参数=${v.param || v.affectedParam || v.affectedParam || '-'}`);
}

const ok = oobHit.length > 0;
console.log(ok
  ? '✅ OOB 外部隧道整链通过：无回显目标经协作端回连被检出'
  : '❌ 未检出 OOB —— 隧道链路或检测判据有问题');

await lab.close();
await oobTunnel.stop().catch(() => {});
process.exit(ok ? 0 : 1);
