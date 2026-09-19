// ============================================================================
// blindLenCapped.test.js —— 长度二分「顶到上界」时的处置契约
// ============================================================================
// 病根（TODO §B）：`binaryProbe` 早就给出了 `capped` 标记，但 `_binarySearch` 只
// `return r.n + 1`，把标记丢了。后果是判据失效时**拿上界当长度**去逐字节提取 ——
// 历史事故：上界 65531，一个 5 字符的值要提 6.5 万字符，一次扫描拖成十几分钟。
//
// 难点（也是本文件存在的理由）：「顶到上界」有**两种**成因，探测层面无法区分，
// 所以裁决必须分层，一刀切判失败会把正常的长值提取打死（实测挂 2 个用例）：
//   ① 真实长度 ≥ 上界 → 合法信号，要么延伸续段（主段 255），要么按 blindMaxLen 截断；
//   ② 判据恒真失效 → 顶到哪儿都真，上界就是个假长度。
// 裁决依据：主段顶到 255 → 交 `_extendLength` 预检；延伸段顶到 maxLen →
//   maxLen 是用户显式配的按①截断、是默认护栏(4096)按②判失败。
//
// 本文件用「回显型目标」复现真实形态：目标把请求原样回显 → 真/假两侧文本必然不同
// → 判据结构性恒真，而响应骨架（剥数字后）完全相同 → 备份判据也无法区分。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 判据恒真 + 骨架不可区分的 oracle：
//   · 真条件响应带一个随 payload 长度变的数字 → 与 false 基准「不同」→ truthy 恒真
//   · responseSkeleton 剥数字后两侧都是 `OK<!--NN-->` → 备份判据区分不出 → capped
function makeEchoOracle(counter) {
  return {
    async request(opts) {
      counter.n++;
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: 'OK', status: 200 };
      return { data: `OK<!--${q.length}-->`, status: 200 };
    },
  };
}

// 正常字节级预言机（真长值用，验证成功路径不受影响）
function makeByteOracle(secret) {
  const bytes = Buffer.from(secret, 'utf-8');
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: Number(lenM[1]) < bytes.length ? 'OK' : '', status: 200 };
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        const code = bytes[i - 1];
        return { data: c < code ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10, ...overrides },
  };
}

const ex = new Extractor();

test('判据不可区分时：长度探测判失败（null），不拿上界当长度逐字节提取', async () => {
  const counter = { n: 0 };
  const ctx = buildCtx(makeEchoOracle(counter));
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, null, '判据不可信时必须放弃该字段，而不是返回一串垃圾字节');
  assert.equal(ctx.blindLenCapped, true, '失败原因要写在 ctx 上，供 report.summary.constraints 上报');
  // 关键：不能按上界去逐字节提取。默认护栏 4096 字节 × 每字节 ~8 轮 ≈ 3 万请求；
  // 判失败后只剩「主段二分 + 备份判据端点 + 延伸段二分」这几轮。
  assert.ok(counter.n < 100, `请求数应远小于按上界提取的量，实际 ${counter.n}`);
});

test('显式 blindMaxLen 截断语义不变（顶到用户授权上限 ≠ 判据失效）', async () => {
  const counter = { n: 0 };
  const ctx = buildCtx(makeEchoOracle(counter), { blindMaxLen: 300 });
  const out = await ex.extractBoolean(ctx, 'version()');
  // 用户显式授权「最多 300 字节」→ 顶到它按截断处理（旧行为），不判失败
  assert.equal(out?.length, 300);
});

test('真长值（300 字节）经延伸二分成功 → 不得误记 capped', async () => {
  const secret = 'A'.repeat(300);
  const ctx = buildCtx(makeByteOracle(secret));
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.ok(!ctx.blindLenCapped, '主段顶到 255 是合法信号，延伸段量出真值后必须撤销标记');
});
