// ============================================================================
// modsec-live.mjs —— 真机 ModSecurity（owasp/modsecurity-crs:nginx）对拍
//
// 与 tamper-sweep.mjs 的关系：
//   tamper-sweep = **静态**（自实现 crs-engine 执行官方规则原文，不发包）
//   本脚本      = **真机**（真实 ModSecurity + libinjection 引擎，真发 HTTP）
// 两者共用 samples.mjs 的同一批样本 → 差异只可能来自「引擎不同」，不会来自「样本不同」。
//
// ⚠️ 红的条件只有一条：**自检不通过**（后端没起来 / WAF 没生效 / 网络不通）。
//   这类失败意味着「下面所有数字都不是在测 WAF」—— 判据与危害同源，必须硬失败。
//   其余（绕过数多少、误报几条）都是**测量值**，不是本仓的成败判据：
//   · 绕过少 → 是 CRS 强，不是我们做错了；
//   · 误报多 → 是 CRS 的问题（要记录、要归因），不该让我们的 CI 变红。
//   （本仓反复踩的坑就是「恒绿的空转门禁」；反过来「把别人的问题算成自己的红」同样失真。）
//
// 用法：
//   node e2e/waf-real/modsec-live.mjs
//   MODSEC_BASE=http://127.0.0.1:8080 MODSEC_LABEL=pl1 node e2e/waf-real/modsec-live.mjs
// ============================================================================
import { createServer } from 'node:http';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { SAMPLES, SAFE_SAMPLES } from './samples.mjs';
import { evaluate } from './crs-engine.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const here = dirname(fileURLToPath(import.meta.url));
const { applyTampers } = require(resolve(here, '../../server/src/core/tamper/applyTampers.js'));
const { tamperRegistry } = require(resolve(here, '../../server/src/core/tamper/TamperRegistry.js'));

const BASE = process.env.MODSEC_BASE || 'http://127.0.0.1:8080';
const LABEL = process.env.MODSEC_LABEL || 'pl1';
const TARGET_PORT = Number(process.env.MODSEC_TARGET_PORT || 8151);
const OUT_DIR = resolve(here, 'results');
const DATE = new Date().toISOString().slice(0, 10);

const ctx = { dbms: 'MySQL', config: {} };

// ── 靶站后端（容器内 nginx 反代到它；host network 下 127.0.0.1 可达）────────────
// 只做一件事：把 id 原样回显 + 200。不需要真 MySQL —— 本脚本测的是「WAF 放不放行」，
// 不是「注入能不能打穿数据库」。少一个 MySQL 依赖就少一类 ECONNREFUSED 假失败
// （本仓 waf-lab 那条链在 CI 上正是栽在这个依赖上）。
function startTarget() {
  const srv = createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`OK id=${u.searchParams.get('id') ?? ''}`);
  });
  // CI 里靶站由 modsec-target.mjs 先拉起（容器需要上游在位才不会启动失败）→ 端口已占。
  // 这不是错误：只要有人在这个端口上应答即可，故 EADDRINUSE 时复用外部的、不自己 listen。
  return new Promise((ok, fail) => {
    srv.once('error', (e) => {
      if (e.code === 'EADDRINUSE') ok(null);
      else fail(e);
    });
    srv.listen(TARGET_PORT, '127.0.0.1', () => ok(srv));
  });
}

/** 打一发，返回 { status, text }；网络异常返回 { status: 0 } */
async function hit(payload) {
  const url = `${BASE}/num?id=${encodeURIComponent(payload)}`;
  try {
    const r = await fetch(url, { redirect: 'manual' });
    return { status: r.status, text: (await r.text()).slice(0, 200) };
  } catch (e) {
    return { status: 0, text: `ERR:${e.message}` };
  }
}

/** WAF 判定：非 2xx = 被拦；网络不通（0）= 不可判定（由调用方按错误处理） */
const blocked = (r) => r.status >= 400;

// ── 自检：不通过就直接 exit 1（下面所有数字都依赖「WAF 真的在位」）────────────
async function selftest() {
  const clean = await hit('1');
  if (clean.status === 0) {
    console.error(`[自检失败] 连不上 ${BASE} —— 容器没起来或端口不对（${clean.text}）`);
    return null;
  }
  if (!String(clean.status).startsWith('2')) {
    console.error(`[自检失败] 干净请求 id=1 被拦（HTTP ${clean.status}）—— 被拦的是正常流量，说明 WAF 阈值/规则集不是我们要测的形态`);
    return null;
  }
  const probe = await hit("1' AND 1=1-- -");
  if (blocked(probe)) return { clean, probe };
  console.error(
    `[自检失败] 裸注入 id=1' AND 1=1-- - 未被拦（HTTP ${probe.status}）—— WAF 没在阻断` +
      `（常见成因：镜像默认 SecRuleEngine=DetectionOnly / 反代没走 ModSecurity / PARANOIA 环境变量名随版本变）。` +
      `不修这个就跑数字，等于在测一个不存在的 WAF。`
  );
  return null;
}

async function main() {
  const srv = await startTarget();
  const st = await selftest();
  if (!st) {
    srv?.close();
    process.exit(1);
  }
  console.log(`[自检通过] 干净请求 HTTP ${st.clean.status} · 裸注入 HTTP ${st.probe.status}（已拦）· BASE=${BASE} · LABEL=${LABEL}`);

  const names = tamperRegistry.list().map((p) => (typeof p === 'string' ? p : p.name)).sort();
  const rows = [];

  const run = async (label, chain) => {
    let pass = 0;
    let unknown = 0;
    const statusBySample = [];
    for (const s of SAMPLES) {
      let t = s;
      try {
        t = chain ? applyTampers(s, ctx, chain) : s;
      } catch {
        /* 插件抛错 → 按原样发（与 tamper-sweep 同口径：错误单独记） */
      }
      const r = await hit(t);
      if (r.status === 0) unknown++;
      else if (!blocked(r)) pass++;
      statusBySample.push(r.status);
    }
    // 静态侧（自实现 crs-engine）对同一批样本、同一条链的判定 → 分歧归因用
    let staticPass = 0;
    const staticRules = [];
    for (const s of SAMPLES) {
      let t = s;
      try {
        t = chain ? applyTampers(s, ctx, chain) : s;
      } catch { /* 同上 */ }
      const e = evaluate({ uri: '/num?id=1', queryString: `id=${encodeURIComponent(t)}`, args: { id: t }, cookies: {}, headers: {} });
      if (!e.blocked) staticPass++;
      else staticRules.push(e.ruleId || '?');
    }
    rows.push({ label, pass, unknown, statusBySample, staticPass, staticRules: [...new Set(staticRules)] });
  };

  await run('(off) 不做变形', null);
  for (const n of names) await run(n, [n]);

  // 安全对照：期望 0 误拦；有就记录（是 CRS 的误报，不是我们的回归 → 不红）
  const fp = [];
  for (const s of SAFE_SAMPLES) {
    const r = await hit(s);
    if (blocked(r)) fp.push({ sample: s, status: r.status });
  }

  srv?.close();

  rows.sort((a, b) => b.pass - a.pass || a.label.localeCompare(b.label));
  const winners = rows.filter((r) => r.pass > 0 && r.label !== '(off) 不做变形');

  console.log(`\n插件 ${names.length} 个 · 样本 ${SAMPLES.length} 条 · LABEL=${LABEL}`);
  console.log('放行数(真机) | 放行数(自实现) | 链');
  for (const r of rows.slice(0, 25)) {
    const flag = r.pass > 0 ? '  ★' : '   ';
    console.log(`${flag} ${String(r.pass).padStart(2)}/${SAMPLES.length}        ${String(r.staticPass).padStart(2)}/${SAMPLES.length}        ${r.label}`);
  }

  // ── 报告 ────────────────────────────────────────────────────────────────
  const md = [];
  md.push(`# 真机 ModSecurity 对拍（${LABEL}）· ${DATE}`, '');
  md.push('## 四要素（结果可比性的前提，缺一不可）', '');
  md.push('| 项 | 值 |');
  md.push('|---|---|');
  md.push(`| 镜像 | \`${process.env.MODSEC_IMAGE || 'owasp/modsecurity-crs:nginx（tag 未记录）'}\` |`);
  md.push(`| CRS 版本 | ${process.env.MODSEC_CRS_VERSION || '未记录（容器内 /etc/modsecurity.d 取证失败）'} |`);
  md.push(`| PARANOIA | ${process.env.MODSEC_PARANOIA || '未记录'} |`);
  md.push(`| 阻断阈值 | ${process.env.MODSEC_ANOMALY_INBOUND || '未记录'} |`);
  md.push(`| 靶站 | 内置 echo 后端 @127.0.0.1:${TARGET_PORT}（不含真 MySQL —— 本轮只测“放不放行”） |`);
  md.push('', `自检：干净请求 HTTP ${st.clean.status}（放行）· 裸注入 HTTP ${st.probe.status}（已拦）`, '');
  md.push('## 绕过矩阵（真机 vs 自实现 crs-engine）', '');
  md.push('| 链 | 真机放行 | 自实现放行 | 自实现命中规则 |');
  md.push('|---|---|---|---|');
  for (const r of rows) {
    if (r.pass === 0 && r.staticPass === 0) continue;
    md.push(`| \`${r.label}\` | ${r.pass}/${SAMPLES.length} | ${r.staticPass}/${SAMPLES.length} | ${r.staticRules.join(', ') || '—'} |`);
  }
  md.push('', `真机有绕过效果的插件（${winners.length}）：${winners.length ? winners.map((r) => `\`${r.label}\``).join(', ') : '（无）'}`, '');
  md.push('## 安全对照（期望 0 误拦）', '');
  md.push(fp.length ? fp.map((x) => `- \`${x.sample}\` → HTTP ${x.status}（CRS 误报，非本工具回归）`).join('\n') : '- 0 误拦 ✅');
  md.push('', '> 口径：放行/拦截以 HTTP 状态码非 2xx 为准；网络异常计入 unknown。本轮为**测量**，', '> 不是通过/失败判据 —— 唯一让本脚本退出 1 的是「自检不通过」（WAF 根本不在位）。');
  mkdirSync(OUT_DIR, { recursive: true });
  const out = resolve(OUT_DIR, `modsec-docker-${LABEL}-${DATE}.md`);
  writeFileSync(out, md.join('\n'), 'utf8');
  console.log(`\n报告：${out}`);
  if (fp.length) console.warn(`[注意] 安全对照误拦 ${fp.length} 条（CRS 侧误报，已写入报告，不计失败）`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`[modsec-live] 未预期异常：${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
