// ============================================================================
// tests/nosqlUnusableResponse.test.js —— NoSQL/SSTI 探测的失败样本护栏
//
// ── 缺陷（实测确认）──────────────────────────────────────────────────────────
// NoSqlInjectionDetector._detectNosql / _detectSsti 用
//     String((await this.send(...))?.data ?? '')
// 把网络失败折成空串参与差异判定。实测四种场景：
//   A 首探针真侧失败、其余正常   → vulnerable=true，evidence 写「真长 0 ≠ 假长 17」
//   B 每个探针真侧都失败        → vulnerable=true
//   C 全部失败                  → vulnerable=false（双边空串恰好相同，巧合正确）
//   D 首次真侧正常、假侧失败    → vulnerable=true，「真长 37 ≠ 假长 0」
//
// 即**单边失败一律误报**，且报告里把「超时」写成「真条件返回空」——
// 对使用者是误导性证据（会以为目标真的对 NoSQL 运算符有响应）。
//
// 与 Union 同源但更隐蔽：Union 的门控失败只是"放行后续探测"（假阳性风险），
// NoSQL 是**直接产出结论与 evidence**（结论污染）。
//
// ── 修法 ────────────────────────────────────────────────────────────────────
// 复用 Detector.prototype.unusableOf（= egressOpts.isUnusableResponse 单一真源），
// 失败样本不参与判定，重发一次；重发仍失败则该探针跳过（continue）。
// 注意是"跳过该探针"而非"整体放弃"——不得降低检出能力。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NoSqlInjectionDetector } from '../src/engine/detectors/NoSqlInjectionDetector.js';

const FAIL = { __netErr: { kind: 'timeout', message: 'timeout' } };
const OK = (data) => ({ data, status: 200 });
const SHORT = OK('<html>暂无数据</html>');
const LONG = OK('<html>用户admin 邮箱a@b.com 角色root 注册于2024</html>');

// target/point 必须对齐 buildInjectionRequest 的真实契约（injection.js:103）：
//   - target.baseUrl  才是 URL（我最初误用 target.url ⇒ 请求里 params/data 全空，
//     payload 根本没发出去，判据看不到内容 ⇒ 守卫恒绿 = 装饰品）
//   - point.param     才是参数名（误用 point.name ⇒ 实测 URL 变成 `?undefined=...`）
//   - point.location='url' ⇒ payload 写进 query string
const TARGET = { baseUrl: 'http://x/?id=1', method: 'GET' };
const POINT = { id: 'p1', param: 'id', originalValue: '1', location: 'url' };
const BASE = '<html>页面加载中</html>';

function scripted(pattern) {
  let i = 0;
  return {
    // 把请求参数一并透给 pattern —— isTrueSide 需要看 payload 内容才能区分真/假侧。
    // ⚠️ 注意 send() 传给 httpClient.request 的是 buildEgressOpts 的结果（不是原始 req），
    //    所以这里必须透出**合并后**的对象，否则判据看不到 payload。
    request: async (opts) => pattern(i++, opts),
    calls: () => i,
  };
}

/** 记录一次请求的 payload 形态，供自证用例核对 */
let lastReq = null;
const detect = async (pattern) => {
  const d = new NoSqlInjectionDetector();
  const c = scripted((i, req) => { lastReq = req; return pattern(i, req); });
  const r = await d._detectNosql({ httpClient: c, target: TARGET, config: {} }, POINT, BASE,
    { vulnerable: false, evidence: '', payloads: [] });
  return { r, n: c.calls(), lastReq };
};

/**
 * 判别请求属于探针的「真值」侧还是「假值」侧。
 * 判据来自 NOSQL_OPERATOR_PROBES 的真实字面量（实测打印，非猜测）：
 *   真侧含  {"$gt": ""}   {"$where": "1"}   {"$regex": ".*"}
 *   假侧含  {"$ne": ""}   {"$where": "0"}   {"$regex": "a^"}
 * 用正/反两个不靠位次、不靠单一运算符的判据，任意探针都能正确区分。
 */
// ⚠️ 判据必须对 URL 编码鲁棒：实测 payload 进 URL 后空格被编成 `+`，
//    形如 `{"$gt":+""}`，用 `\s*` 匹配不上（第一版就是这么恒绿的）。
//    故先 decodeURIComponent 再按解码后的字面量匹配。
const isTrueSide = (req) => {
  const raw = String(req?.url ?? '') + JSON.stringify(req?.params ?? {});
  const s = (() => { try { return decodeURIComponent(raw.replace(/\+/g, ' ')); } catch { return raw; } })();
  return /"\$gt":\s*"/.test(s) || /"\$where":\s*"1/.test(s) || /"\$regex":\s*"\.\*/.test(s);
};

test('自证-0) isTrueSide 判据本身有效（否则缺陷-1 会恒绿，守卫成装饰品）', async () => {
  // 抓一次真侧和一次假侧的请求，确认判据能分开 —— 不验证判据就没有验证。
  const seen = [];
  await detect((_i, req) => { seen.push({ isTrue: isTrueSide(req), url: req?.url }); return SHORT; });
  const trues = seen.filter((s) => s.isTrue).length;
  const falses = seen.filter((s) => !s.isTrue).length;
  assert.ok(trues > 0, `判据未识别出任何真侧请求（total=${seen.length}）—— 判据失效`);
  assert.ok(falses > 0, `判据把所有请求都判成真侧（total=${seen.length}）—— 判据失效`);
  assert.ok(seen.length > 0, '未捕获到任何请求，测试基线无效');
  assert.ok(
    seen[0].url && /"\$(gt|where|regex)"/.test(decodeURIComponent(seen[0].url.replace(/\+/g, ' '))),
    `请求 URL 未包含 NoSQL payload，测试基线无效：${JSON.stringify(seen[0])}`
  );
});

test('缺陷-1) 真侧失败不得报成注入（真侧持续失败 + 假侧正常）', async () => {
  // ⚠️ 场景设计注意：护栏会**重发**，"第几次请求"与"哪一侧"不再一一对应，
  //    不能用 i%2 假设位次（重发会打乱奇偶）。改为按 payload 内容判别：
  //    真侧一律失败（重发也拿不到可用响应），假侧一律成功 ——
  //    这正是"网络故障期间不得产出结论"的真实情形。
  const { r } = await detect((_i, req) => (isTrueSide(req) ? FAIL : SHORT));
  assert.equal(r.vulnerable, false,
    `真侧持续网络失败被当成了"真条件返回空"并报出注入（evidence=${(r.evidence || '').slice(0, 80)}）`);
});

test('缺陷-1b) 假侧失败不得报成注入（假侧持续失败 + 真侧正常）', async () => {
  const { r } = await detect((_i, req) => (isTrueSide(req) ? LONG : FAIL));
  assert.equal(r.vulnerable, false,
    `假侧持续网络失败被当成了注入信号（evidence=${(r.evidence || '').slice(0, 80)}）`);
});

test('缺陷-2) 假侧失败同样不得报成注入', async () => {
  const { r } = await detect((i) => (i % 2 === 0 ? LONG : FAIL));
  assert.equal(r.vulnerable, false,
    `假侧网络失败被当成了注入信号（evidence=${(r.evidence || '').slice(0, 80)}）`);
});

test('缺陷-3) 每个探针真侧都失败时不得报成注入', async () => {
  const { r } = await detect((i) => (i % 2 === 0 ? FAIL : SHORT));
  assert.equal(r.vulnerable, false, '全部探针真侧失败时不得报成注入');
});

test('缺陷-4) evidence 不得出现"真长 0 / 假长 0"这类把失败写成结论的措辞', async () => {
  // 比第 1 条更强：不只看 vulnerable，还要看证据文本本身是否误导。
  const { r } = await detect((i) => (i % 2 === 0 ? FAIL : SHORT));
  if (r.vulnerable) {
    assert.fail(`报出了注入，且 evidence 把网络失败写成了响应长度：${r.evidence}`);
  }
});

test('契约-5) 全部失败时保持原有保守行为（不报）', async () => {
  const { r } = await detect(() => FAIL);
  assert.equal(r.vulnerable, false, '全部探针失败时应保持不报');
});

test('契约-6) 真阳性不得被护栏误伤：真假响应显著不同且全部成功 ⇒ 必须报', async () => {
  // 最关键的一条：护栏只为挡失败样本，绝不能把正常命中也挡掉。
  const { r } = await detect((i) => (i % 2 === 0 ? LONG : SHORT));
  assert.equal(r.vulnerable, true,
    '真/假响应显著不同且请求全部成功时必须仍能报出 NoSQL 注入（不得降低检出能力）');
});

test('契约-7) 重发成功时 evidence 不得再把失败写成"真长 0"', async () => {
  // 重发语义：偶发失败（第一次失败、第二次成功）应当被救回来。
  const { r, n } = await detect((i) => {
    if (i === 0) return FAIL;   // 偶发失败
    return i % 2 === 0 ? LONG : SHORT;
  });
  if (r.vulnerable) {
    assert.ok(!/真长 0\b/.test(r.evidence),
      `重发成功后 evidence 不应再出现"真长 0"：${r.evidence}`);
  }
  assert.ok(n >= 4, `至少应发出探针请求，实际 ${n}`);
});