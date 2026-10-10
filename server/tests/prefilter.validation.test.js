// [P1-PERF 2026-09-08 实战批次] 输入校验型目标「可证安全跳过」测试（node:test）
// 覆盖 ScanManager._validationGuardedSkipPoints：
//   1) 白名单校验型目标（探针一律同构 400）→ 跳过完整检测（实测 fp_strict 类 211 请求 → 5 请求）；
//   2) 「有洞但异常被吞」反例（恒真串返回正常页）→ 必须保留（这是单点目标最怕的漏检场景）；
//   3) 报错页回显非法输入（`Invalid id: 1'`）→ 剥回显后仍判定成立；
//   4) 保守红线：探测失败 / 含 SQL 报错签名 / 基线本身异常 → 一律保留。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]v=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.v !== 'undefined') return String(opts.data.v);
  return '';
}

const POINTS = [{ id: 'p1', location: 'url', param: 'v', originalValue: '1' }];
const TARGET = { url: 'http://mock.test/?v=1', baseUrl: 'http://mock.test/', method: 'GET', config: {} };

function makeSm(handler) {
  const sm = new ScanManager();
  let requests = 0;
  sm.httpClient = {
    async request(opts) {
      requests++;
      return handler(extractQuery(opts), opts);
    },
  };
  sm._requests = () => requests;
  return sm;
}

async function skipCheck(sm, points = POINTS, config = {}, extras = {}) {
  const ctxBase = { httpClient: sm.httpClient, config, target: TARGET, ...extras };
  return sm._validationGuardedSkipPoints(ctxBase, TARGET, points);
}

// [D35 实战 P0-1 补] 「启用了请求变换」与「没启用」必须是两种语义 —— 差分用例，一次跑两边。
// 为什么必须停用这条剪枝：在签名/加密型目标上，"改一个字段就连良性值一起被拒"
// 正是**签名没覆盖 / 密文没重算**的定义，而不是输入校验拦截。照旧剪点的后果是
// 整轮只发几条请求就收工，transform_rejected 的样本（injectRejects≥8）根本攒不齐，
// 结论安静地落成「未检出」—— 实弹出处：e2e/signed-api-lab 的 B2 场景（第一版 5 请求即结束）。
test('变换生效 ⇒ 同构 400 不再判为输入校验（保留完整检测）；未启用时仍照旧削减', async () => {
  // 白名单校验形态：数字才回 200，其余一律同构 400 —— 与上面第一条用例完全同一份 handler
  const handler = (q) =>
    /^\d+$/.test(q)
      ? { status: 200, data: `<h1>Item #${q}</h1>` }
      : { status: 400, data: '<h1>400 Bad Request</h1><p>id 必须为数字</p>' };

  const off = makeSm(handler);
  const { candidate: offCand, skipped: offSkip } = await skipCheck(off);
  assert.equal(offCand.length, 0, '未启用变换时行为必须不变（这条削减是 fp_strict 类目标的性能底线）');
  assert.equal(offSkip[0].reason, 'input_validation');
  assert.equal(off._requests(), 5, `未启用时应发满 5 次探测，实得 ${off._requests()}`);

  const on = makeSm(handler);
  const { candidate: onCand, skipped: onSkip } = await skipCheck(on, POINTS, {}, {
    validity: { transformActive: true },
  });
  assert.equal(onCand.length, 1, '变换生效时必须保守保留该点，否则签名/加密目标会静默"未检出"');
  assert.equal(onSkip.length, 0, '不得留下 input_validation 跳过记录');
  // 早退位置也钉住：既然不打算据此剪点，就不该再花那 3 条探针请求
  assert.equal(on._requests(), 2, `变换生效应只发基线+单引号两探即保留，实得 ${on._requests()} 次`);
});

test('输入校验型目标（探针同构 400）→ 判定跳过，且只发 5 个廉价请求', async () => {
  const sm = makeSm((q) =>
    /^\d+$/.test(q)
      ? { status: 200, data: `<h1>Item #${q}</h1>` }
      : { status: 400, data: '<h1>400 Bad Request</h1><p>id 必须为数字</p>' }
  );
  const { candidate, skipped } = await skipCheck(sm);
  assert.equal(candidate.length, 0, '白名单校验点应被跳过');
  assert.equal(skipped.length, 1);
  assert.equal(skipped[0].reason, 'input_validation');
  assert.equal(sm._requests(), 5, `应只发 5 次探测，实际 ${sm._requests()} 次`);
});

test('错误页回显非法输入 → 剥回显后仍判定为输入校验（否则这类目标削减不了）', async () => {
  const sm = makeSm((q) =>
    /^\d+$/.test(q)
      ? { status: 200, data: `<h1>Item #${q}</h1>` }
      : { status: 400, data: `<h1>Bad Request</h1><p>Invalid id: ${q.replace(/</g, '&lt;')}</p>` }
  );
  const { candidate } = await skipCheck(sm);
  assert.equal(candidate.length, 0, '回显型 400 页不应阻断判定');
});

test('反例：有洞但异常被统一吞掉（恒真串返回正常页）→ 必须保留完整检测', async () => {
  const sm = makeSm((q) => {
    if (/^\d+$/.test(q)) return { status: 200, data: '<h1>Item</h1><p>row found</p>' };
    // 异常被吞：任何含引号的输入都是通用 500 空页；但恒真条件在 SQL 里成立 → 回到正常页
    if (q.includes("OR '1'='1") || q.includes('OR 1=1')) {
      return { status: 200, data: '<h1>Item</h1><p>row found</p>' };
    }
    return { status: 500, data: '<h1>Server Error</h1><p>系统繁忙，请稍后重试</p>' };
  });
  const { candidate, skipped } = await skipCheck(sm);
  assert.equal(candidate.length, 1, '恒真串有响应差异 → 不可跳过');
  assert.equal(skipped.length, 0);
});

test('响应体含 SQL 报错签名 → 明确保留（error 技术有活可干）', async () => {
  const sm = makeSm((q) =>
    /^\d+$/.test(q)
      ? { status: 200, data: '<h1>Item</h1>' }
      : { status: 500, data: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '1'" }
  );
  const { candidate } = await skipCheck(sm);
  assert.equal(candidate.length, 1);
});

test('保守红线：任一探测失败/超时（返回 null）→ 保留', async () => {
  let n = 0;
  const sm = makeSm(() => {
    n++;
    return n === 4 ? null : { status: 400, data: 'blocked' };
  });
  const { candidate } = await skipCheck(sm);
  assert.equal(candidate.length, 1, '探测失败必须保守保留');
});

test('保守红线：基线本身即 4xx（形态不明）→ 保留', async () => {
  const sm = makeSm(() => ({ status: 404, data: '<h1>Not Found</h1>' }));
  const { candidate } = await skipCheck(sm);
  assert.equal(candidate.length, 1);
});

test('WAF 拦截差异：单引号 403 而良性值 400 → 保留（不同源不可判为输入校验）', async () => {
  const sm = makeSm((q) => {
    if (/^\d+$/.test(q)) return { status: 200, data: '<h1>Item</h1>' };
    if (q.includes("'")) return { status: 403, data: '<h1>Forbidden</h1><p>your request was blocked by WAF</p>' };
    return { status: 400, data: '<h1>Bad Request</h1><p>id must be number</p>' };
  });
  const { candidate } = await skipCheck(sm);
  assert.equal(candidate.length, 1);
});

test('多点位隔离：只跳过满足全部条件的点，其余照常检测', async () => {
  const points = [
    { id: 'p1', location: 'url', param: 'v', originalValue: '1' }, // 白名单校验 → 跳过
    { id: 'p2', location: 'url', param: 'v', originalValue: '2' }, // 有回显差异 → 保留
  ];
  const sm = makeSm((q) => {
    if (q.startsWith('2')) {
      return /^\d+$/.test(q)
        ? { status: 200, data: `<h1>Item ${q}</h1>` }
        : { status: 200, data: '<h1>Item</h1><p>sql returned 1 row</p>' };
    }
    return /^\d+$/.test(q) ? { status: 200, data: '<h1>Item</h1>' } : { status: 400, data: '<h1>400</h1>' };
  });
  const { candidate, skipped } = await skipCheck(sm, points);
  assert.deepEqual(candidate.map((p) => p.id), ['p2']);
  assert.deepEqual(skipped.map((s) => s.pointId), ['p1']);
});

test('config.validationSkip=false 时调用方（scanRunner）不改行为：本方法仍可用但零跳过判定不启用', async () => {
  // 契约测试：开关在调用方判定，本方法自身保持纯判定逻辑（便于单测与复用）
  const sm = makeSm(() => ({ status: 400, data: 'x' }));
  const { candidate } = await skipCheck(sm, POINTS, { validationSkip: false });
  assert.equal(candidate.length, 1, '基线也是 400 → 不满足条件 ① → 保留（与开关无关）');
});
