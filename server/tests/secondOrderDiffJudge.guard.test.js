// server/tests/secondOrderDiffJudge.guard.test.js —— [D301 GAP②] 二阶布尔差异判定守卫。
// 背景：报错抑制型触发页（DVWA sqli high 的 "Something went wrong." 形态）上，
// ERROR_SIG 签名判定永远不可见 ⇒ 二阶检测静默漏报（all-levels 实测检出=[]）。
// 判据：diffJudge opt-in + 三重防误报（探针页稳定 × 阴性页稳定 × 差异存在）⇒ 命中；
// 关闭（零回归）/ 探针页不稳 / 阴性页不稳 / 无差异 ⇒ 不命中。删 _maybeDiffJudge 调用 ⇒ DIFF-1 红。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecondOrderDetector } from '../src/engine/detectors/SecondOrderDetector.js';

const TRIGGER = 'http://t/trigger';
const STORE = 'http://t/store';
// 报错抑制形态：不匹配 ERROR_SIG（正是签名判定失效的根因）
const SUPPRESSED_ERR = '<html><h1>点评面板错误</h1><pre>Something went wrong.</pre></html>';
const NEG_PAGE = '<html><table><tr><th>first_name</th></tr><tr><td>admin</td></tr></table></html>';

function makeCtx(secondOrder) {
  const detector = new SecondOrderDetector();
  // 触发页读取脚本（按调用次序）：detect 签名阶段 3 次读（基线/探针/阴性），
  // diff 阶段 2 次读（探针复验/阴性复验）。存储请求不计入脚本。
  const script = secondOrder.__triggerBodies;
  let n = 0;
  const httpClient = {
    request: async (opts) => {
      const url = String(opts?.url || '');
      if (url.includes('/trigger')) {
        const body = script[Math.min(n, script.length - 1)];
        n += 1;
        return { status: 200, data: body };
      }
      return { status: 200, data: '' }; // 存储 POST：靶场侧真实写，判定只看响应成功
    },
  };
  const ctx = {
    httpClient,
    target: { url: STORE, cookieParams: {}, headerParams: {} },
    point: { id: 'p1', location: 'body', param: 'id', actionUrl: STORE, formValues: {}, originalValue: '1' },
    dbms: 'MySQL',
    config: { secondOrder },
    triggerUrl: TRIGGER,
  };
  return { detector, ctx, readCount: () => n };
}

test('DIFF-1 diffJudge opt-in + 三重稳定 ⇒ 命中（报错抑制形态的唯一检出路径）', async () => {
  const { detector, ctx, readCount } = makeCtx({
    enabled: true, negativeControl: true, diffJudge: true, refreshCsrf: false,
    __triggerBodies: ['<p>empty</p>', SUPPRESSED_ERR, NEG_PAGE, SUPPRESSED_ERR, NEG_PAGE],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, true, '报错抑制 + 探针/阴性稳定 + 差异存在 ⇒ 必须命中');
  assert.ok(String(r.evidence).includes('布尔差异路径'), '证据须标注判定路径（对外口径）');
  assert.equal(r.dbms, 'MySQL');
  assert.ok(readCount() >= 5, 'diff 阶段必须真实复验（探针复验 1 读 + 阴性复验 1 读，[D302] 复用签名阶段读）');
});

test('DIFF-2 反例：diffJudge 缺省（关闭）⇒ 不命中且不发起复验请求（零回归）', async () => {
  const { detector, ctx, readCount } = makeCtx({
    enabled: true, negativeControl: true, refreshCsrf: false,
    __triggerBodies: ['<p>empty</p>', SUPPRESSED_ERR, NEG_PAGE],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, false, '既有签名口径零行为变化（不命中）');
  assert.equal(readCount(), 3, '不得偷偷发起 diff 复验请求（基线/探针/阴性各一次）');
});

test('DIFF-3 反例：探针页两次读取不一致（动态页面噪声）⇒ 放弃判定', async () => {
  const { detector, ctx } = makeCtx({
    enabled: true, negativeControl: true, diffJudge: true, refreshCsrf: false,
    __triggerBodies: ['<p>empty</p>', SUPPRESSED_ERR, NEG_PAGE, '完全不同的动态页面', NEG_PAGE],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, false, '探针页不稳定 ⇒ 宁漏不误');
});

test('DIFF-4 反例：阴性页两次读取不一致 ⇒ 放弃判定', async () => {
  const { detector, ctx } = makeCtx({
    enabled: true, negativeControl: true, diffJudge: true, refreshCsrf: false,
    __triggerBodies: ['<p>empty</p>', SUPPRESSED_ERR, NEG_PAGE, SUPPRESSED_ERR, '随机噪声页'],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, false, '阴性页不稳定 ⇒ 无可信基线，宁漏不误');
});

test('DIFF-5 反例：探针页与阴性页无内容差异 ⇒ 无注入信号', async () => {
  const { detector, ctx } = makeCtx({
    enabled: true, negativeControl: true, diffJudge: true, refreshCsrf: false,
    __triggerBodies: ['<p>same</p>', '<p>same</p>', '<p>same</p>', '<p>same</p>', '<p>same</p>'],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, false, '探针=阴性 ⇒ 存储值没有改写查询行为');
});

test('DIFF-6 易变内容归一：长数字水印/HTML 注释被剥离（两次读取仅水印不同 ⇒ 视为稳定）', async () => {
  const w = (n) => `<html><!-- generated at ${n} --><h1>点评面板错误</h1><pre>Something went wrong.</pre></html>`;
  const { detector, ctx } = makeCtx({
    enabled: true, negativeControl: true, diffJudge: true, refreshCsrf: false,
    __triggerBodies: ['<p>empty</p>', w(1795023718), NEG_PAGE, w(1795099999), NEG_PAGE],
  });
  const r = await detector.detect(ctx);
  assert.equal(r.vulnerable, true, '仅时间戳水印不同 ⇒ 归一后稳定 ⇒ 照常命中');
});
