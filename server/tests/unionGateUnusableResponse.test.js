// ============================================================================
// tests/unionGateUnusableResponse.test.js —— Union 门控必须排除失败样本
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// UnionDetector._gateInjection 取响应体用的是：
//     String((await this.send(...))?.data ?? '')
// —— 完全不看这次请求**是否失败**。而同族检测器都有失败样本护栏：
//     BooleanBlindDetector:266/333/431   this.unusableOf(rTrue) || this.unusableOf(rFalse)
//     TimeBlindDetector:171              this.unusableOf(baseRes) || this.unusableOf(injectRes)
//     StackedDetector:75/148             !r.__error && r.resp != null
//     prefilter.js:24 甚至写了纪律："本模块统一用 isUnusableResponse(res)，
//                                    **不要**改回 res == null"
// Union 是唯一漏掉这道闸的。
//
// 实测后果（真跑 _gateInjection，非推理）：
//   场景甲：真探针超时失败、假探针正常返回
//         → trueBody='' ，falseBody='正常页面内容'
//         → _similar('','正常页面内容')=false ⇒ 返回 **pass=true**
//         ⇒ 网络抖动被当成"SQL 真假分化"，误判参数在 SQL 上下文 ⇒
//            门控本该防的参数反射误报从这里放行。
//   场景乙：两次探针都失败
//         → 都是 '' ⇒ _similar 判相似 ⇒ pass=false（保守，无害）
//
// 即：**单边失败**会放行，**双边失败**会保守拒绝。前者是假阳性来源。
//
// ── 为什么必须显式处理、不能靠"空串自然相似"兜底 ──────────────────────────
// 空串兜底只在双边失败时恰好正确，任一边失败就崩。这属于"靠巧合正确"，
// 换个 payload 顺序（先假后真）结果就反过来。判据必须落在失败标志上，
// 而不是落在被折成空串的 data 上。
//
// ── 为什么不能简单地"失败就 return false" ──────────────────────────────────
// 那是把假阳性修成假阴性 —— 违反"不得降低检出能力"。正确做法是**重发**：
// 失败样本不参与判定，重发一次；重发仍失败才保守拒绝（与同族检测器同口径）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';

const FAIL = { __netErr: { kind: 'timeout', message: 'timeout' } };
const OK = (data) => ({ data, status: 200 });

// 调 _gateInjection 的姿势对齐既有测试 detectors.test.js:237
// （`d._gateInjection(ctx, {}, {}, { originalValue: '1' }, '')`）——
// 门控只用 point.originalValue 与 boundary，不碰 target 的 url/params。
const CTX = { dbms: 'MySQL', config: {} };
const POINT = { originalValue: '1' };

/**
 * 造一个可控的假 httpClient：按脚本依次返回每次请求的结果。
 * send() 调的是 httpClient.request(...)（detectorSupport/egress.js:14）。
 */
function scriptedClient(script) {
  const state = { i: 0 };
  return {
    request: async () => {
      const r = script[Math.min(state.i, script.length - 1)];
      state.i++;
      return r;
    },
    calls: () => state.i,
  };
}

test('缺陷-1) 单边失败不得被当成注入信号（真探针超时 + 假探针正常）', async () => {
  const d = new UnionDetector();
  const c = scriptedClient([FAIL, OK('正常页面内容')]);
  const pass = await d._gateInjection(CTX, c, {}, POINT, '');
  assert.notEqual(pass, true,
    `真探针超时失败、假探针正常时不应直接判定"有注入"（实际 pass=${pass}，`
    + `发出了 ${c.calls()} 次请求）—— 网络抖动被当成了 SQL 真假分化`);
});

test('缺陷-2) 反向单边失败同样不得放行（假探针超时 + 真探针正常）', async () => {
  // 两个方向都要堵：实现若只在第一处判失败，反向仍会漏。
  const d = new UnionDetector();
  const c = scriptedClient([OK('正常页面内容'), FAIL]);
  const pass = await d._gateInjection(CTX, c, {}, POINT, '');
  assert.notEqual(pass, true, `假探针超时失败、真探针正常时不应判定"有注入"（实际 pass=${pass}）`);
});

test('契约-3) 全部失败时必须保守拒绝（pass=false），不得放行', async () => {
  const d = new UnionDetector();
  const c = scriptedClient([FAIL]);
  const pass = await d._gateInjection(CTX, c, {}, POINT, '');
  assert.equal(pass, false, '四次探针全失败时应保守拒绝（与其它检测器同口径）');
});

test('契约-4) 两边都正常时行为不变（不得因加护栏而误伤真阳性）', async () => {
  // 这条最关键：加护栏是为了挡假阳性，绝不能把真阳性也挡掉。
  const d = new UnionDetector();
  const c = scriptedClient([
    OK('<html>用户admin的详细信息页面，共3条记录</html>'),
    OK('<html>无结果，抱歉没有找到匹配的数据</html>'),
  ]);
  const pass = await d._gateInjection(CTX, c, {}, POINT, '');
  assert.equal(pass, true, '真假响应明显不同时门控必须放行（真阳性不得被护栏误伤）');
});

test('契约-5) 反射形态（真假响应相同）仍应拒绝（门控的原始职责不得退化）', async () => {
  const d = new UnionDetector();
  const same = OK('<html>你输入的值是 abc，请检查</html>');
  const c = scriptedClient([same, same, same, same]);
  const pass = await d._gateInjection(CTX, c, {}, POINT, '');
  assert.equal(pass, false, '真假响应完全相同（参数反射）时门控必须拒绝');
});

test('自证-6) 判据本身有效：_similar 对单边失败确实判不相似（这就是缺陷的成因）', () => {
  // 守卫必须能解释"为什么会出这个缺陷"。若 _similar 实际会判相似，
  // 那缺陷-1 就不是真缺陷，守卫的依据也就不成立。
  const d = new UnionDetector();
  assert.equal(d._similar('', ''), true, '双边为空应判相似');
  assert.equal(d._similar('', '正常页面内容'), false,
    '单边为空应判不相似 —— 正是这一点让失败样本被当成注入信号');
});