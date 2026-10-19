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
  // [D96] 字符类必须覆盖引擎 nanoid token 的完整字母表（URL-safe：a-z0-9_-）。
  // 两次 CI 逃逸实锤：
  //  · run 262 acceptance：回连域含 `-`（`…s79cu7nof-qk5isw.oast.pro`）；
  //  · run 266 e2e-self-contained：回连域含 `_`（`…pr7x_0xts-wq_gr4.oast.pro`，
  //    nanoid 默认字母表 useandom-26T…_GQZ… 含下划线）。
  // 原 `[a-z0-9]{20,}` 一遇这两个字符就断开 ⇒ 14 个请求 0 提取 ⇒ 假 FAIL。
  // 提取正则必须与 token 生成端（interactshClient 的 normToken 输出）同字母表，
  // 且 DNS 标签本来就允许 `-`（`_` 为宽松实践，服务端照收）。
  const hostRe = new RegExp(`([\\w-]{20,})\\.${server.replace(/\./g, '\\.')}`, 'i');
  const m = s.match(hostRe);
  return m ? m[0] : null;
}

/**
 * [D96] 判据自证：提取正则与 token 生成端的字母表必须同源可达 ——
 * 空转的正则会让整条 OOB 链路在「收到请求但 0 回连」的形态上静默假红/假绿。
 * 样本取自两次 CI 真实事故（连字符 / 下划线），加自定义 server 形态。
 */
function selftestExtract(server) {
  const p = 'x'.repeat(34);
  const cases = [
    [`\\\\${p}s79cu7nof-qk5isw.${server}\\oob\\x`, true], // run 262 连字符事故样本
    [`http://${p}pr7x_0xts-wq_gr4.${server}/oob`, true], // run 266 下划线事故样本
    [`${p}PLAIN-TOKEN.${server}`, true], // 大写（DNS 大小写不敏感）
    ['http://127.0.0.1/x?id=1', false], // 无回连域 ⇒ 不提取
    [`short-${server}`, false], // 标签过短 ⇒ 不提取（防把根域本身当 token）
  ];
  for (const [text, want] of cases) {
    const got = extractCallbackHost(text, server) !== null;
    if (got !== want) {
      throw new Error(`[selftest] extractCallbackHost 空转：${JSON.stringify(text)} 期望 ${want} 实际 ${got}`);
    }
  }
}
selftestExtract(SERVER);
if (SERVER !== 'oast.pro') selftestExtract('oast.pro');


function startLab() {
  const state = { hits: 0, dns: 0, http: 0 };
  const server = http.createServer(async (req, res) => {
    state.hits += 1;
    const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
    // 载荷可能出现在任意参数值里（引擎会按注入点位置投放）；[D108] 背景哨兵向请求头
    // 播撒 token ⇒ 头值也必须参与提取，否则场景 B 恒「收到请求但 0 回连」。
    const raw = [...u.searchParams.values(), ...Object.values(req.headers)].join(' ');
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

/**
 * 跑一次完整扫描并等到终态；返回 { report, vulns, oobHit }。
 * 超时/错误抛异常，由调用方统一收尾。
 * @param {{url:string, config:object}} input
 * @param {string} label 日志前缀
 */
async function runScan(input, label) {
  const sm = new ScanManager({});
  const scanId = await sm.start(input);
  const t0 = Date.now();
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) {
      const report = sm.getReport(scanId);
      const vulns = (report && report.vulns) || [];
      const oobHit = vulns.filter(
        (v) => String(v.technique || '') === 'oob' || /oob|带外|OOB/i.test(JSON.stringify(v))
      );
      return { report, vulns, oobHit };
    }
    if (Date.now() - t0 > 120000) {
      sm.stop(scanId);
      throw new Error(`${label} 扫描超时`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

// ── 场景 A（D87 原判据）：显式 techniques=['oob'] + risk 2，参数面整链 ──────────
const A = await runScan(
  { url: `http://127.0.0.1:${PORT}/item?id=1`, config: BASE_CONFIG },
  '[场景A]'
);
console.log(`[场景A] 靶站收到请求 ${lab.state.hits} 次（DNS 解析 ${lab.state.dns} · HTTP 回连 ${lab.state.http}）`);
if (lab.state.hits > 0 && lab.state.dns === 0 && lab.state.http === 0) {
  console.log('[场景A] ⚠ 收到请求但没提取到任何协作端主机 —— 载荷形态与提取正则不匹配（检查 extractCallbackHost 与投放向量）');
}
console.log(`[场景A] 检出漏洞 ${A.vulns.length} 条，其中 OOB 通道 ${A.oobHit.length} 条`);
for (const v of A.vulns.slice(0, 3)) {
  console.log(`   · ${v.vulnType?.nameZh || v.type || v.technique} | ${v.riskLevel || '-'} | 参数=${v.param || v.affectedParam || '-'}`);
}
const hitA = A.oobHit.length > 0;
console.log(hitA
  ? '✅ OOB 外部隧道整链通过：无回显目标经协作端回连被检出'
  : '❌ 场景A 未检出 OOB —— 隧道链路或检测判据有问题');

// ── 场景 B（D108 背景哨兵）：无参数 URL + risk 1 + 技术集不含 oob ──────────────
// 判据：**未显式配置注入点**（URL 无 query 参数、level 1 不生成头点）时，背景哨兵
// 向 headerParams/常见头播撒 token，仍能经协作端回连检出 —— 这正是 P1-5 的验收口径。
const BG_CONFIG = {
  ...BASE_CONFIG,
  techniques: ['union', 'error', 'boolean'], // 不含 oob：一阶不会做任何 OOB 投放
  risk: 1, // 技术门控会把 oob 剔除；哨兵是唯一带外通道
  oob: {
    enabled: true,
    timeoutMs: 30000,
    background: { enabled: true, maxRequests: 8, timeoutMs: 30000, headers: ['User-Agent'] },
    interactsh: { enabled: true, server: SERVER, pollIntervalMs: 1500 },
  },
};
const B = await runScan(
  {
    url: `http://127.0.0.1:${PORT}/item`,
    config: BG_CONFIG,
    headerParams: { 'X-Api-Key': 'demo-key' },
  },
  '[场景B]'
);
const bgHit = B.vulns.filter((v) => v.technique === 'oob' && v.oobBackground === true);
const headerHit = bgHit.filter((v) => v.location === 'header' || String(v.param || '').toLowerCase().includes('user-agent') || String(v.param || '').toLowerCase() === 'x-api-key');
console.log(`[场景B] 靶站收到请求 ${lab.state.hits} 次（DNS 解析 ${lab.state.dns} · HTTP 回连 ${lab.state.http}）`);
console.log(`[场景B] 检出漏洞 ${B.vulns.length} 条，其中背景哨兵 ${bgHit.length} 条（头面 ${headerHit.length} 条）`);
for (const v of bgHit.slice(0, 3)) {
  console.log(`   · ${v.technique} | ${v.riskLevel || '-'} | 位置=${v.location || '-'} | 参数=${v.param || v.affectedParam || '-'}`);
}
const hitB = bgHit.length > 0 && headerHit.length > 0;
console.log(hitB
  ? '✅ OOB 背景哨兵整链通过：未显式配置注入点仍经带外回连检出'
  : '❌ 场景B 未检出背景哨兵 —— 面收集/播撒/归因链路有问题');

const ok = hitA && hitB;
console.log(ok
  ? '✅ OOB 外部隧道整链通过（场景 A + B）'
  : '❌ OOB 整链未通过（见上方场景结论）');

await lab.close();
await oobTunnel.stop().catch(() => {});
process.exit(ok ? 0 : 1);
