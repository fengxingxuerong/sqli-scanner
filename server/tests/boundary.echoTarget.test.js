// ============================================================================
// boundary.echoTarget.test.js —— 「回显型目标」上闭合探测与版本回显定库的回归钉
//
// 为什么单独一套 mock（不依赖真 MySQL）：2026-09-18 在 blackbox-lab 真 MySQL 上实测出两个
// 同根缺陷 —— 目标把注入值原样打回页面（`sql=…` 调试回显 / 报错页回显 URL）时，
// **一切基于「响应 vs 基线」的比较都会被那份回显污染**：
//   ① probeBoundary：13 个闭合候选全部判不相似 → boundary='' → 该点 union/boolean 全灭；
//   ② 版本回显定库：`__S__…__E__` 在页面里出现**两份**（回显的 SQL 文本 + 真实结果行），
//      `match` 取第一处 → 永远拿到 SQL 文本 → 18 库 sig 全落空 → 退化成误判高发通道。
// 两者都能用一个纯 JS mock 复现，所以钉在这里（真 MySQL 靶场留给 e2e，不进单测）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';
import { createTarget } from '../src/engine/models.js';

const ROWS = '<p>1 | Mechanical Keyboard | peripherals | 499.00</p>';
const NOROW = '<p>no row</p>';
const ERR = '<p class="err">query failed</p>';
const ORIG = 'Keyboard';

/**
 * 模拟 `WHERE name LIKE '%${v}%'` 且**把注入值原样回显**的目标。
 * 闭合形态：值后紧跟 `'` 或 `%'` 才算闭合出字面量；未闭合则整条落在字符串里 → 恒假但不报错。
 * @param {{versionEcho?: string, supportedFuncs?: string[]}} [opts] versionEcho 非空时，
 *   UNION 探针回显该值（真库版本串）；supportedFuncs 声明**这台假引擎能执行哪些探针表达式**——
 *   不给这一层，mock 就等于「任何库的探针都回同一个版本」，测不出「宽松 sig 前置后抢走裸版本号」。
 */
function makeEchoTarget(opts = {}) {
  // 默认按真 MySQL 8.0.28 的可执行集合：version() 可跑，H2VERSION() 报错无回显（2026-09-19 实测）
  const supported = opts.supportedFuncs ?? ['version()'];
  const calls = [];
  return {
    calls,
    async request(reqOpts) {
      const u = new URL(reqOpts.url);
      const v = u.searchParams.get('q') ?? ORIG;
      calls.push(v);
      const rest = v.slice(ORIG.length);
      const closed = /^%?'/.test(rest);
      const truthy = /(AND|OR)\s+1\s*=\s*1/.test(rest);
      const falsy = /(AND|OR)\s+1\s*=\s*2/.test(rest);
      let body = '';
      // 版本回显探针：结果列里带真实版本串（另有一份「被回显的 SQL 文本」在下面拼上）
      if (closed && /UNION SELECT/.test(rest) && opts.versionEcho) {
        // 哨兵探针（定位回显列）一律照常回显；版本探针只有这台假引擎**能执行该表达式**时才有回显
        const probe = /SQLISCANNER/.test(rest) || supported.some((f) => rest.includes(f));
        body = probe ? `<p>${opts.versionEcho}</p>` : ERR;
      } else if (closed && /ORDER BY (\d+)/.test(rest)) {
        const n = Number(/ORDER BY (\d+)/.exec(rest)[1]);
        body = n <= 3 ? ROWS : ERR;
      } else if (!closed) {
        // 未闭合 → 整条留在 LIKE 字面量里 → 只有「原值本身」还能匹配到行
        body = rest === '' ? ROWS : NOROW;
      } else {
        body = truthy ? ROWS : falsy ? NOROW : ERR;
      }
      // 关键污染：把注入值原样写回页面（真实目标里的调试回显/报错回显就是这个形态）
      return {
        status: 200,
        headers: {},
        data: `<html><body><div class="env">sql=SELECT * FROM products WHERE name LIKE '%${v}%'</div>${body}</body></html>`,
      };
    },
  };
}

function makeCtx(httpClient, extraPoint = {}) {
  const url = 'http://mock/?q=Keyboard';
  const target = createTarget({ url, method: 'GET' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: ORIG, ...extraPoint };
  return { httpClient, target, point, config: {} };
}

test('回显型目标：闭合探测必须拿到真正闭合的前缀，而不是回退空串', async () => {
  const det = new Detector('union');
  const ctx = makeCtx(makeEchoTarget());
  const boundary = await det.probeBoundary(ctx);
  // `'` 与 `%'` 都能闭合这个 LIKE 上下文；空串意味着「整句落在字面量内」= 该点 union 全灭
  assert.ok(
    boundary === "'" || boundary === "%'",
    `闭合探测应拿到可用闭合前缀，实得 ${JSON.stringify(boundary)}（空串=回显污染未剔除的旧行为）`
  );
});

test('回显型目标：闭合探测不得把「未闭合」的空调当成命中（防判据反向放松成假阳性）', async () => {
  // 反例守卫：目标是**参数化**的（任何输入都回同一张正常页），闭合探测不该报命中。
  const flat = {
    async request(reqOpts) {
      const u = new URL(reqOpts.url);
      return { status: 200, headers: {}, data: `<div>sql=${u.searchParams.get('q')}</div><p>rows</p>` };
    },
  };
  const det = new Detector('union');
  const boundary = await det.probeBoundary(makeCtx(flat));
  assert.equal(boundary, '', '恒定回显页面无闭合信号，应回退空串');
});

test('回显型目标：版本回显定库取真实结果行，而不是被回显的 SQL 文本', async () => {
  const httpClient = makeEchoTarget({ versionEcho: '__S__8.0.28__E__' });
  const ctx = makeCtx(httpClient, { boundary: "'" });
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(ctx);
  assert.equal(res?.dbms, 'MySQL', `应定库 MySQL，实得 ${res?.dbms}（取到 SQL 文本时会是 null/误判）`);
  assert.equal(res?.version?.raw, '8.0.28', '版本串应来自结果行，而不是被回显的 SQL 文本');
  assert.equal(res?.version?.major, 8, '主版本号应被正确解析（后续按版本选 payload/枚举语句要用）');
});

// [EXCL-FIX 2026-09-19] 定库判据的机制钉：H2 之所以能排在 MySQL 之前，靠的是「exclusive 函数」
// 而不是「sig 能区分」——H2 的 sig 就是裸版本号 `/^\d+\.\d+/`，与 MySQL/SQLite/ClickHouse/
// Firebird/MonetDB 全重叠。于是守卫落在**可执行集合**上：跑不动的表达式必须没有回显。
//   · 正向：H2 假引擎只认 H2VERSION() → 必须判 H2（修复前这台是 dbms=null，见 multi-engine-lab A/B）。
//   · 反向：MySQL 假引擎只认 version() → 必须仍判 MySQL。若有人把 H2 换回通用的 version()，
//     前置的 H2 条目就会在 MySQL 上抢走裸版本号 → 这条先炸。
test('exclusive 版本探针：只有 H2 能跑 H2VERSION() 时，裸版本号判给 H2 而非 MySQL', async () => {
  const httpClient = makeEchoTarget({ versionEcho: '__S__2.2.224__E__', supportedFuncs: ['H2VERSION()'] });
  const ctx = makeCtx(httpClient, { boundary: "'" });
  const res = await new DBFingerprinter().fingerprint(ctx);
  assert.equal(res?.dbms, 'H2', `应定库 H2，实得 ${res?.dbms}`);
  assert.equal(res?.version?.raw, '2.2.224');
});

test('exclusive 版本探针的反向守卫：MySQL 上 H2 探针无回显 → 仍判 MySQL（前置不抢库）', async () => {
  // 与上一条同构，只把可执行集合换成 MySQL 系（version() 可跑、H2VERSION() 报错）。
  // 若哪天有人把 H2 的 sig 放宽到能吃下「别的库回显的裸版本号」，这条会先炸。
  const httpClient = makeEchoTarget({ versionEcho: '__S__8.0.28__E__', supportedFuncs: ['version()'] });
  const ctx = makeCtx(httpClient, { boundary: "'" });
  const res = await new DBFingerprinter().fingerprint(ctx);
  assert.equal(res?.dbms, 'MySQL', `应定库 MySQL，实得 ${res?.dbms}`);
});

// ============================================================================
// [TODO §C 2026-09-20] 路径点基线 4xx → 跳过闭合探测
//
// 语义：闭合前缀回答的是「怎么跳出 SQL 字符串字面量」，前提是该路径**真的执行了 SQL**。
// 路径不存在（404）时后端没路由到查询代码，13 个候选只会拿到同一张 404 页
// （Express 默认错误页还回显请求 URL），剔除回显后仍偶有同形判定 → 噪声 boundary
// 进而**触发整轮指纹/列数探测（每次约 40 请求）**，全打在一条不存在的路径上。
//
// 实测来源：e2e 记录 `/api/sleep` 开 --test-path 时 path 点拿到 boundary `%"`。
// 守卫要点（两个方向都要钉）：
//   · 正向：path 点 + 404 → 0 候选请求，boundary=''，且留下跳过原因；
//   · 反向：path 点 + 200 → 照常探测（不能把真实路径点也砍掉）；
//   · 边界：401/403/429 不跳过（鉴权/限流 ≠ 路径不存在）；
//   · 边界：非 path 点（url/body/cookie/header）即便 404 也不走这条早退（那是另一类语义）。
// ============================================================================

/** 固定状态码的桩，记录每个请求的 URL（用于断言「有没有真的投候选」）。 */
function makeStatusTarget(status, body = '') {
  const urls = [];
  return {
    urls,
    async request(reqOpts) {
      urls.push(reqOpts.url);
      return { status, headers: {}, data: body };
    },
  };
}

test('§C 正向：path 点基线 404 → 不发任何闭合候选，boundary 回退空串并记原因', async () => {
  const det = new Detector('union');
  const httpClient = makeStatusTarget(404, '<html><body><p>Cannot GET /shop/user/1</p></body></html>');
  const ctx = makeCtx(httpClient, { kind: 'path', location: 'path' });
  const boundary = await det.probeBoundary(ctx);
  assert.equal(boundary, '', 'path 点 404 时应回退空串');
  // 早退后只应有基线那 1 次请求；旧行为是 1 + 13 个候选（可比对先看到 14）
  assert.equal(
    httpClient.urls.length,
    1,
    `path 点 404 应只发基线 1 次请求，实发 ${httpClient.urls.length} 次（13 候选未跳过=§C 未修）`
  );
  assert.ok(
    typeof ctx.point.boundarySkipReason === 'string' && ctx.point.boundarySkipReason.includes('404'),
    '应留下可解释的跳过原因（供报告/排障），实得 ' + JSON.stringify(ctx.point.boundarySkipReason)
  );
});

test('§C 反向：path 点基线 200 → 照常投放闭合候选（不误伤真实路径点）', async () => {
  const det = new Detector('union');
  // 200 且回显 payload：与 makeEchoTarget 同形态，确保候选真的被投出去
  const httpClient = makeEchoTarget();
  const ctx = makeCtx(httpClient, { kind: 'path', location: 'path' });
  const before = httpClient.calls.length;
  await det.probeBoundary(ctx);
  assert.ok(
    httpClient.calls.length > before,
    'path 点 200 时仍应正常探测（早退条件不得命中）'
  );
  assert.equal(ctx.point.boundarySkipReason, undefined, '200 路径不应留下跳过原因');
});

test('§C 边界：401/403/429 不跳过（鉴权/限流 ≠ 路径不存在）', async () => {
  const det = new Detector('union');
  for (const status of [401, 403, 429]) {
    const httpClient = makeStatusTarget(status, '<html><body>denied</body></html>');
    const ctx = makeCtx(httpClient, { kind: 'path', location: 'path' });
    await det.probeBoundary(ctx);
    assert.ok(
      httpClient.urls.length > 1,
      `HTTP ${status} 属「路径存在但本次被拒」，不应走 404 早退（实发 ${httpClient.urls.length} 次）`
    );
  }
});

test('§C 边界：非 path 点基线 404 不走这条早退（语义不同，避免误砍）', async () => {
  const det = new Detector('union');
  const httpClient = makeStatusTarget(404, '<html><body><p>not found</p></body></html>');
  // url 点：404 可能只是缺参数，闭合探测仍有意义（后端逻辑可能照跑）
  const ctx = makeCtx(httpClient, { kind: 'url', location: 'url' });
  await det.probeBoundary(ctx);
  assert.ok(
    httpClient.urls.length > 1,
    `非 path 点不应被此早退影响（实发 ${httpClient.urls.length} 次）`
  );
});
