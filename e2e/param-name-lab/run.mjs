// ============================================================================
// e2e/param-name-lab/run.mjs —— [D93] 参数名注入真靶场判据
//
// 判据（读引擎报告的事实字段，不看套件自报）：
//   ① /colfilter（键名拼 SQL）开启 testParamNames 后**必须检出**，且命中点 location='paramName'
//   ② /colfilter-safe（同写法 + 白名单）**必须零检出**（证明不是「见 query 就报」）
//   ③ 关闭 testParamNames 时 /colfilter **不应检出**（证明能力的开关语义真实存在，
//      而不是既有通道的漏光）
//
// 环境：需 MySQL（blackbox_lab.products 表）+ 靶场。未就绪输出 [SKIP] 并 exit 0
// （acceptance 读文本判据，不看退出码）。
//
// 用法：node e2e/param-name-lab/run.mjs
// ============================================================================

import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const PORT = Number(process.env.PARAMNAME_LAB_PORT || 8123);
const BASE = `http://127.0.0.1:${PORT}`;
const MAX_MS = Number(process.env.PARAMNAME_LAB_TIMEOUT_MS) || 120000;

const portOpen = (port) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1');
  s.on('connect', () => { s.end(); resolve(true); });
  s.on('error', () => { s.destroy(); resolve(false); });
});

/** 扫一个端点，返回 { verdict, vulns, reqs }（ScanManager.start + 轮询终态，与 juice-shop-lab 同范式） */
async function scan(path, testParamNames) {
  const mgr = new ScanManager({});
  const cfg = {
    concurrency: 1,
    ratePerSec: 0,
    retry: 0,
    timeoutMs: 8000,
    techniques: ['union', 'boolean', 'error'],
    enableExtract: false,
    level: 1,
    risk: 2,
    productionMode: false,
    testParamNames,
  };
  const id = await mgr.start({ url: `${BASE}${path}`, config: cfg });
  const t0 = Date.now();
  for (;;) {
    const st = mgr.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) {
      const report = mgr.getReport(id) || {};
      return {
        verdict: report?.summary?.verdict ?? null,
        vulns: Array.isArray(report?.vulns) ? report.vulns : [],
        reqs: report?.summary?.validity?.counts?.total ?? 0,
      };
    }
    if (Date.now() - t0 > MAX_MS) {
      mgr.stop(id);
      throw new Error('scenario timeout');
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function withLab(body) {
  if (await portOpen(PORT)) return body(false);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('./lab.mjs', import.meta.url))], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)),
    stdio: 'ignore',
  });
  for (let i = 0; i < 30; i++) {
    if (await portOpen(PORT)) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  try {
    if (!(await portOpen(PORT))) return { skip: '靶场未能启动（端口 8123 未就绪）' };
    return await body(true);
  } finally {
    try { proc.kill(); } catch { /* 已退出 */ }
  }
}

const timeout = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('scenario timeout')), MAX_MS))]);

const main = async () => {
  const skipOr = async (fn) => fn();
  const out = await skipOr(() => withLab(async () => {
    // 先探测 MySQL 是否可用（靶场起了但库不在 ⇒ 所有请求 500 ⇒ 结论无意义）
    const probe = await fetch(`${BASE}/colfilter?name=Keyboard`).then((r) => r.text()).catch(() => '');
    if (!/sql=/.test(probe)) return { skip: '靶场探针失败（MySQL 未就绪？）' };

    const on = await timeout(scan('/colfilter?name=Keyboard', true));
    const off = await timeout(scan('/colfilter?name=Keyboard', false));
    const safe = await timeout(scan('/colfilter-safe?name=Keyboard', true));

    const paramHits = on.vulns.filter((v) => v.location === 'paramName').length;
    const facts = {
      vuln检出: `${on.vulns.length}`,
      'vuln中paramName点': `${paramHits}`,
      开关关闭: `${off.vulns.length}`,
      安全点检出: `${safe.vulns.length}`,
    };
    const pass = on.vulns.length > 0 && paramHits > 0 && off.vulns.length === 0 && safe.vulns.length === 0;
    return { facts, pass, verdict: on.verdict };
  }));

  if (out?.skip) {
    console.log(`[SKIP] 参数名注入靶场：${out.skip}`);
    process.exit(0);
  }
  const f = out.facts || {};
  console.log(`[param-name] vuln=${f.vuln检出} paramNameHit=${f['vuln中paramName点']} off=${f.开关关闭} safe=${f.安全点检出}`);
  console.log(out.pass ? '[PASS] 参数名注入（D93）' : '[FAIL] 参数名注入（D93）');
  process.exit(out.pass ? 0 : 1);
};

main().catch((e) => {
  console.error('[param-name] 运行失败：', e && e.message);
  process.exit(1);
});
