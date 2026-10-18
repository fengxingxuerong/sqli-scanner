// ============================================================================
// e2e/param-mine-lab/run.mjs —— [D102] 参数挖掘真靶场判据
//
// 判据（读引擎报告的事实字段，不看套件自报；与 param-name-lab 同范式）：
//   ① /api/items 开 --param-mine 后**必须检出**隐藏参数 kw（参数不在链接里，只能靠
//      字典挖掘发现）—— 3 轮复跑取多数决（redteam-lab 口径，单轮抖动不撑强断言）
//   ② 关闭 paramMine 时同端**零检出**（证明「不开挖就漏检」的能力语义真实存在，
//      而不是既有值注入通道的漏光）
//   ③ /api/safe（同款隐藏参数 kw、值参数化）开挖掘后**零检出**（挖到 ≠ 必报）
//
// 环境：需 MySQL + 靶场（自带幂等夹具：自建 parammine_lab + 种子，可连即可跑）。
// 未就绪输出 [SKIP] 并 exit 0（acceptance 读文本判据，不看退出码）。
//
// 用法：node e2e/param-mine-lab/run.mjs
// ============================================================================

import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const PORT = Number(process.env.PARAMMINE_LAB_PORT || 8126);
const BASE = `http://127.0.0.1:${PORT}`;
const MAX_MS = Number(process.env.PARAMMINE_LAB_TIMEOUT_MS) || 120000;
const RUNS = Number(process.env.PARAMMINE_LAB_RUNS) || 3;

const portOpen = (port) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1');
  s.on('connect', () => { s.end(); resolve(true); });
  s.on('error', () => { s.destroy(); resolve(false); });
});

/** 扫一个端点，返回 { verdict, vulns, reqs }（ScanManager.start + 轮询终态，与 juice-shop-lab 同范式） */
async function scan(path, paramMine) {
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
    paramMine,
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

/** 命中口径：检出项里存在 kw 点的证据（参数名或挖掘溯源标记，取字段并集防报告形态演进而脆断） */
const kwHit = (vulns) => vulns.some((v) => [v.param, v.minedParam, v.point?.param].includes('kw') || v.mined === true);

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
    if (!(await portOpen(PORT))) return { skip: '靶场未能启动（端口未就绪）' };
    return await body(true);
  } finally {
    try { proc.kill(); } catch { /* 已退出 */ }
  }
}

const timeout = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('scenario timeout')), MAX_MS))]);

const main = async () => {
  // 先探测 MySQL 是否可用（靶场起了但库不在 ⇒ 所有请求 query failed ⇒ 结论无意义）。
  // ⚠ 判据不能用「响应里有没有 err=」这类自反形态（D95 实测踩过假 SKIP/假 FAIL）。
  const out = await withLab(async () => {
    const probe = await fetch(`${BASE}/api/items?id=1`).then((r) => r.text()).catch(() => '');
    if (!/Mechanical Keyboard/.test(probe) || /query failed/.test(probe)) return { skip: '靶场探针失败（MySQL 未就绪？）' };

    // ① 开挖掘 3 轮复跑取多数决
    const onRuns = [];
    for (let i = 0; i < RUNS; i++) onRuns.push(await timeout(scan('/api/items?id=1', true)));
    const onHits = onRuns.filter((r) => r.vulns.length > 0 && kwHit(r.vulns)).length;
    // ②③ 开关语义 + 安全对照（各 1 轮：对照点是「必须零」的形态，多跑只花预算不加信息）
    const off = await timeout(scan('/api/items?id=1', false));
    const safe = await timeout(scan('/api/safe?id=1', true));

    const facts = {
      开挖掘检出轮次: `${onHits}/${RUNS}`,
      关挖掘检出: `${off.vulns.length}`,
      安全点检出: `${safe.vulns.length}`,
    };
    const pass = onHits > RUNS / 2 && off.vulns.length === 0 && safe.vulns.length === 0;
    return { facts, pass, verdict: onRuns.find((r) => r.vulns.length > 0)?.verdict };
  });

  if (out?.skip) {
    console.log(`[SKIP] 参数挖掘靶场：${out.skip}`);
    process.exit(0);
  }
  const f = out.facts || {};
  console.log(`[param-mine] on=${f.开挖掘检出轮次} off=${f.关挖掘检出} safe=${f.安全点检出}`);
  console.log(out.pass ? '[PASS] 参数挖掘（D102）' : '[FAIL] 参数挖掘（D102）');
  process.exit(out.pass ? 0 : 1);
};

main().catch((e) => {
  console.error('[param-mine] 运行失败：', e && e.message);
  process.exit(1);
});
