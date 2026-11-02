// ============================================================================
// server/tests/echoStrip.shortCircuit.guard.test.js —— [D230] 回显归一化的短路优化，
// 必须**逐码元等价**于优化前实现。
//
// 出处（性能实测，2026-11-02）：
//   `stripEchoedPayload` 是报错/布尔通道每探针都走的热路径，10MB body 实测
//   旧 87.5ms / 含 %XX 162.8ms —— 其中 URL 解码两轮 50ms、12 个变体的 split/join 28ms
//   完全花在「输入里根本没有对应形态」的恒等变换上。
//
// 本条改动的**唯一合法性**来自「等价」：短路只在数学上恒等的位置生效
//   · 无 `&` ⇒ 7 次实体 replace 全恒等；
//   · 无 `%XX` 且无 `+` ⇒ `decodeURIComponent(t.replace(/\+/g,' '))` 恒等且不抛错；
//   · 变体在 t 中不存在 ⇒ `t.split(v).join('')` 恒等；
//   · payload 最短前缀都不在 ⇒ 任何更长前缀（都以它开头）也不在。
// 因此本文件用**旧实现副本作 oracle**，对边界语料 + 确定性伪随机语料逐码元比对。
//
// ⚠️ 纪律：
//   · oracle 是 D230 **之前**的实现。若将来要改剔除语义，必须同时改 oracle 并在
//     CHANGELOG 说明「语义变更」，不许只让 oracle 跟着实现漂移（否则等价性测试变成自证）。
//   · 「短路是否真的生效」不靠墙钟断言（本仓教训：拿墙钟当活性上限 = 在测机器负载）。
//     它由 §A 的判据真值表 + deadcode 门禁联动看守：短路一旦被删，判据函数就没有
//     调用方，`deadcode-guard` 当场红。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeEcho,
  stripEchoedPayload,
  echoVariants,
  needsHtmlEntityDecode,
  needsUrlDecode,
} from '../src/engine/echoStrip.js';

// ── oracle：D230 之前的实现（逐字复制，勿"顺手优化"） ──────────────────────
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

function oldStripLongestPrefix(t, payload, minLen = 16) {
  const p = String(payload || '');
  if (p.length < minLen) return t;
  for (let n = p.length; n >= minLen; n--) {
    const pre = p.slice(0, n);
    if (t.includes(pre)) return t.split(pre).join('');
  }
  return t;
}

function oldStripEchoedPayload(body, payload) {
  if (!body) return '';
  let t = oldNormalizeEcho(body);
  if (!payload) return t;
  for (const v of echoVariants(payload)) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  return oldStripLongestPrefix(t, payload, 16);
}

// ── 语料 ────────────────────────────────────────────────────────────────────
const PAYLOADS = [
  "' OR 1=1--",
  "' AND extractvalue(1,concat(0x7e,(select user())))--",
  'apple_juice.jpg%27%29%27',
  '1" OR "1"="1',
  "admin'--",
  '%27',
  `${'x'.repeat(40)}'`,
  '',
];

/**
 * 边界语料：每条都对着一个已知会踩坑的形态
 * （双重编码 `&#38;lt;`、非法 URL 序列 `%E4`、`%` 非转义 `50%`、`+` 与非法序列同现 `a+b%E4`）
 */
const FIXED = [
  '',
  'plain ascii no entities',
  'a<b>&c',
  '&#39;', '&#x27;', '&#38;lt;', '&amp;lt;', '&amp;#39;', '&#38;#x41;',
  '&lt;script&gt;', '&quot;&apos;&amp;',
  '50%', '100%25', '%20%27', '%E4%B8%AD', '%E4', '%ZZ', '%2', '%%20',
  'a+b', 'a+b%E4', 'a%2Bb', '1+1=2',
  '%2520', '%25', '&#37;20',
  '中文%27', '😀&#39;',
  '<div style="width:50%">60%</div>',
  'Cannot GET /api/safe/error&#39;%20AND%20extractvalue(1,concat...',
  '{"e":"\\u0027 OR 1=1"}',
  '\\u0027',
];

/** 确定性伪随机（LCG）：不用 Math.random，失败可复现 */
function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

const CHARS = ['&', '%', '+', '#', ';', '2', '7', 'E', '4', 'x', 'l', 't', 'g', 'a', 'm', 'p', 'q', 'u', 'o', "'", '"', '<', '>', '中', ' ', '\n', '😀', '\\', 'u', '0'];

function randomCorpus(count, seed) {
  const rnd = lcg(seed);
  const out = [];
  for (let i = 0; i < count; i++) {
    const len = 1 + Math.floor(rnd() * 60);
    let s = '';
    for (let j = 0; j < len; j++) s += CHARS[Math.floor(rnd() * CHARS.length)];
    out.push(s);
  }
  return out;
}

// ── §A 短路判据真值表 ───────────────────────────────────────────────────────
test('§A needsHtmlEntityDecode：只在含 & 时为真', () => {
  for (const s of ['', 'abc', '100%', '%E4', 'a+b']) assert.equal(needsHtmlEntityDecode(s), false, s);
  for (const s of ['&', 'a&amp;b', '&#39;', '&nbsp;']) assert.equal(needsHtmlEntityDecode(s), true, s);
  assert.equal(needsHtmlEntityDecode(null), false);
  assert.equal(needsHtmlEntityDecode(undefined), false);
});

test('§A needsUrlDecode：%XX 与 + 为真，纯 % 与非转义为假', () => {
  // `%XX` 形状：真
  for (const s of ['%20', '%27', '%E4%B8%AD', 'a%2Bb', '%25']) assert.equal(needsUrlDecode(s), true, s);
  // `+`：真（原实现会用 replace 把 + 变空格）
  for (const s of ['a+b', '1+1=2']) assert.equal(needsUrlDecode(s), true, s);
  // 非转义形态：假 —— 这些正是「decodeURIComponent 会恒等或抛错、结果都不变」的输入
  for (const s of ['', 'abc', '50%', '%2', '%ZZ', '宽度100%']) assert.equal(needsUrlDecode(s), false, s);
  // `%%20` 里第 2 个 `%` 起就是合法 `%20` ⇒ 必须判真（宁可多解码，不可漏）
  assert.equal(needsUrlDecode('%%20'), true);
  assert.equal(needsUrlDecode(null), false);
});

// ── §B normalizeEcho 逐码元等价 ─────────────────────────────────────────────
test('§B normalizeEcho：边界语料与旧实现逐码元一致', () => {
  for (const s of FIXED) {
    assert.equal(normalizeEcho(s), oldNormalizeEcho(s), `input=${JSON.stringify(s)}`);
  }
});

test('§B normalizeEcho：400 组确定性随机语料一致', () => {
  for (const s of randomCorpus(400, 20261102)) {
    assert.equal(normalizeEcho(s), oldNormalizeEcho(s), `input=${JSON.stringify(s)}`);
  }
});

test('§B normalizeEcho：非法 URL 序列下的异常路径不被短路改变', () => {
  // `a+b%E4`：decodeURIComponent 抛 URIError ⇒ 旧实现保留**未做 +→空格**的原串。
  // 若把 `+` 提前替换掉再判，这里会得到 "a b%E4" —— 本断言就是钉这个差异。
  assert.equal(normalizeEcho('a+b%E4'), oldNormalizeEcho('a+b%E4'));
  assert.equal(normalizeEcho('a+b%E4'), 'a+b%E4');
  // 合法序列时正常解码
  assert.equal(normalizeEcho('a+b%20c'), 'a b c');
});

// ── §C stripEchoedPayload 等价 ──────────────────────────────────────────────
test('§C stripEchoedPayload：边界语料 × 全部 payload 变体一致', () => {
  for (const s of FIXED) {
    for (const p of PAYLOADS) {
      assert.equal(stripEchoedPayload(s, p), oldStripEchoedPayload(s, p), `body=${JSON.stringify(s)} payload=${JSON.stringify(p)}`);
    }
  }
});

test('§C stripEchoedPayload：400 组随机语料 × 轮转 payload 一致', () => {
  const corpus = randomCorpus(400, 77);
  for (let i = 0; i < corpus.length; i++) {
    const p = PAYLOADS[i % PAYLOADS.length];
    assert.equal(stripEchoedPayload(corpus[i], p), oldStripEchoedPayload(corpus[i], p), `body=${JSON.stringify(corpus[i])}`);
  }
});

test('§C stripEchoedPayload：截断型回显（最短前缀到全长）逐档一致', () => {
  const p = "' AND extractvalue(1,concat(0x7e,(select user())))--";
  for (let n = 0; n <= p.length; n++) {
    const body = `<p>Error near: ${p.slice(0, n)}</p>`;
    assert.equal(stripEchoedPayload(body, p), oldStripEchoedPayload(body, p), `prefixLen=${n}`);
  }
});

test('§C stripEchoedPayload：1MB body 上的回显剔除与旧实现一致', () => {
  const filler = '<div class="row"><span>a &amp; b</span></div>\n'.repeat(24000);
  const p = "' OR 1=1--";
  const cases = [
    filler,
    filler.slice(0, 500000) + p + filler.slice(500000),
    `<p>SQL syntax error near '${p.slice(0, 20)}'</p>` + filler,
  ];
  for (const body of cases) {
    assert.equal(stripEchoedPayload(body, p), oldStripEchoedPayload(body, p));
  }
});

// ── §D 短路不改变调用方的判定事实 ───────────────────────────────────────────
test('§D 无实体/无转义的响应：归一化后文本不变（短路的事实前提）', () => {
  const plain = '<html><body>SQL syntax error</body></html>';
  assert.equal(normalizeEcho(plain), plain);
  // 含 & 或 %XX 时才可能变
  assert.equal(normalizeEcho('&lt;b&gt;'), '<b>');
  assert.equal(normalizeEcho('%27'), "'");
});
