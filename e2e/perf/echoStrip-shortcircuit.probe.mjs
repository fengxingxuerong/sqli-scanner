#!/usr/bin/env node
// ============================================================================
// e2e/perf/echoStrip-shortcircuit.probe.mjs —— [D230] 回显归一化短路的收益探针
//
// 为什么单独留一个脚本：D230 的合法性来自「逐码元等价」，收益数字必须能被人
// 在原机复跑，否则 CHANGELOG 里的 6.9× 就只是我一个人的说法。
//
// 口径：
//   · 每个场景构造 10MB 响应体（本仓响应体默认上限，limits.js），跑 N 次取均值；
//   · 对比「D230 之前的实现」（内联副本，逐字复制）与当前实现；
//   · 数字跨机器会变（V8/CPU），只有**比值**有意义；绝对值用于说明量级。
//
// 已知边界（别把它当普适加速）：
//   收益取决于响应形态 —— 无 HTML 实体、无 URL 编码的响应（JSON API）收益最大；
//   含 `&amp;` 的 HTML 页只有 1.1×，因为实体替换本身是实功，不该省。
//
// 跑法：node e2e/perf/echoStrip-shortcircuit.probe.mjs [--runs=20]
// ============================================================================
import { normalizeEcho as newNormalizeEcho, stripEchoedPayload as newStrip, echoVariants as newVariants } from '../../server/src/engine/echoStrip.js';

const MB = 1024 * 1024;
const RUNS = Number((process.argv.find((a) => a.startsWith('--runs=')) || '').split('=')[1]) || 20;
const PAYLOAD = "' AND extractvalue(1,concat(0x7e,(select user())))--";

// ── D230 之前的实现（oracle，逐字复制，勿优化） ─────────────────────────────
function oldNormalizeEcho(s) {
  let t = String(s || '');
  t = t
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d) || 0))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16) || 0))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, String.fromCharCode(34))
    .replace(/&apos;/g, String.fromCharCode(39))
    .replace(/&amp;/g, '&');
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(t.replace(/\+/g, ' '));
      if (d !== t) t = d; else break;
    } catch {
      break;
    }
  }
  return t;
}

function oldStrip(body, payload) {
  if (!body) return '';
  let t = oldNormalizeEcho(body);
  if (!payload) return t;
  for (const v of newVariants(payload)) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  const p = String(payload || '');
  if (p.length >= 16) {
    for (let n = p.length; n >= 16; n--) {
      const pre = p.slice(0, n);
      if (t.includes(pre)) return t.split(pre).join('');
    }
  }
  return t;
}

// 变体集合新旧一致（D230 没有改动它），直接借用当前实现

const mk = (unit) => unit.repeat(Math.ceil((10 * MB) / unit.length)).slice(0, 10 * MB);

const CASES = [
  ['JSON 多行 / 无实体无编码', mk('{"id":1,"name":"item","desc":"lorem ipsum","price":12.5},\n')],
  ['JSON 单行 / 无换行', `{"a":${'"x",'.repeat(Math.ceil((10 * MB) / 5)).slice(0, 10 * MB - 8)}1}`],
  ['HTML / 含 &amp;', mk('<div><span>a &amp; b</span></div>\n')],
  ['HTML / CSS 百分比 50%（% 非 %XX）', mk('<div style="width:50%">x</div>\n')],
];

function bench(fn, body) {
  for (let i = 0; i < 3; i++) fn(body, PAYLOAD);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < RUNS; i++) fn(body, PAYLOAD);
  return Number(process.hrtime.bigint() - t0) / 1e6 / RUNS;
}

console.log(`stripEchoedPayload @10MB，runs=${RUNS}\n`);
console.log('场景'.padEnd(36) + 'D230 前'.padStart(10) + '当前'.padStart(10) + '倍数'.padStart(9));
console.log('-'.repeat(65));
let sum = 0;
for (const [name, body] of CASES) {
  const a = bench(oldStrip, body);
  const b = bench(newStrip, body);
  sum += a / b;
  console.log(name.padEnd(36) + `${a.toFixed(1)}ms`.padStart(10) + `${b.toFixed(1)}ms`.padStart(10) + `${(a / b).toFixed(1)}×`.padStart(9));
}
console.log('-'.repeat(65));
console.log(`平均 ${(sum / CASES.length).toFixed(2)}×（比值跨机器稳定，绝对值随 CPU 变化）`);
console.log('注：HTML/含 &amp; 档在 1.0× 上下浮动属噪声 —— 实体替换本身是实功，不该省；');

// 单函数口径：normalizeEcho 自身（不含变体剔除/前缀剔除）
console.log('\nnormalizeEcho 单函数 @10MB');
for (const [name, body] of CASES) {
  const a = bench((b) => oldNormalizeEcho(b), body);
  const b = bench((x) => newNormalizeEcho(x), body);
  console.log(`  ${name.padEnd(34)}${a.toFixed(1)}ms → ${b.toFixed(1)}ms (${(a / b).toFixed(1)}×)`);
}

// ── 被淘汰的候选修法（D230 的推翻链证据，勿删） ─────────────────────────────
// 结论：分块早停无收益（V8 正则本就线性扫全文），字面量预筛负收益（多趟扫描更贵）。
console.log('\n候选修法实测（ERROR_SIG @10MB，用于证明它们被否决）');
const ERROR_SIG = (await import('../../server/src/core/errorSig.js')).default;
const PRE_RE = /SQL|ORA-|error|exception|syntax|quotation|column|table|Division|ODBC|Jet|Sybase|Informix|Firebird|MonetDB|HSQLDB|Derby|DB2|Access|parse/i;

function scanChunked(body, CHUNK = 512 * 1024) {
  let start = 0;
  while (start < body.length) {
    let end = Math.min(start + CHUNK, body.length);
    if (end < body.length) {
      const nl = body.indexOf('\n', end);
      end = nl === -1 ? body.length : nl + 1;
    }
    const m = body.slice(start, end).match(ERROR_SIG);
    if (m) return m;
    start = end;
  }
  return null;
}

const plain = CASES[0][1];
const withHitAt = (off) => plain.slice(0, off) + 'SQL syntax error' + plain.slice(off + 17);
const sigCases = [
  ['无命中', plain],
  ['命中@100B', withHitAt(100)],
  ['命中@5MB', withHitAt(5 * MB)],
  ['命中@末尾', withHitAt(plain.length - 200)],
];
console.log('  ' + '场景'.padEnd(16) + '全量'.padStart(10) + '分块早停'.padStart(12) + '预筛短路'.padStart(12));
for (const [name, body] of sigCases) {
  const full = bench((b) => b.match(ERROR_SIG), body);
  const ch = bench((b) => scanChunked(b), body);
  const pre = bench((b) => (PRE_RE.test(b) ? b.match(ERROR_SIG) : null), body);
  console.log('  ' + name.padEnd(16) + `${full.toFixed(1)}ms`.padStart(10) + `${ch.toFixed(1)}ms`.padStart(12) + `${pre.toFixed(1)}ms`.padStart(12));
}
console.log('  ⇒ 分块：命中位置靠后时比全量更慢（切片分配），无一处更快 —— 否决。');
console.log('  ⇒ 预筛：无命中档确实快 ~2×，但①真实 HTML 的 error/table/Access 命中率高 ⇒ 退化成两遍扫描；');
console.log('     ②PRE_RE 必须覆盖 ERROR_SIG 全部 45 个分支的必要子串（本文件的清单就已漏 `isc_`），');
console.log('     漏一个即静默假阴性 —— 判据同步成本高于收益，否决。');
