// ============================================================================
// tests/inlineReflectionGateUnusable.test.js
// InlineQueryDetector 反射门控的失败样本护栏
//
// ── 缺陷（实测确认）──────────────────────────────────────────────────────────
// detect() 的命中判定：
//     if (testBody 含 INLINE_MARKER && baseBody 不含 INLINE_MARKER) {
//       const refl = await this.send(..., REFLECTION_PROBE);
//       const reflBody = String(refl?.data ?? '');
//       if (reflBody.includes(REFLECTION_PROBE)) { 拒绝 }   // ← 反射门控
//       else { 报出 _hit }                                  // ← 失败样本走这里
//     }
// 反射探针**失败**时 reflBody='' ⇒ includes 为 false ⇒ 门控当作"未反射"⇒ 放行。
//
// 方向与 Union/NoSQL 相反：**门控失败反而放行**，正是门控最不该有的行为。
// 实测：base 正常 + test 含标记 + 反射探针超时 ⇒ vulnerable=true，
//       evidence 写「(SELECT '__S__INL__E__') → 子查询结果随响应回显」。
//
// 与前两处同源（未用 unusableOf 判失败样本），是本轮扫描找到的第三处遗漏。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InlineQueryDetector } from '../src/engine/detectors/InlineQueryDetector.js';

const FAIL = { __netErr: { kind: 'timeout', message: 'timeout' } };
const OK = (data) => ({ data, status: 200 });

// 常量取自 InlineQueryDetector 源码（INLINE_MARKER / REFLECTION_PROBE）
const INLINE_MARKER = '__S__INL__E__';
const REFLECTION_PROBE = 'SQLISCANNER_REFL_7QZ4X';

const TARGET = { baseUrl: 'http://x/?id=1', method: 'GET' };
const POINT = { id: 'p1', originalValue: '1', location: 'url', param: 'id' };

function scripted(script) {
  // ⚠️ calls() 必须在 request 内部**先自增再取值**；写成 () => i++（后置自增）
  //    会让 script 下标整体错位一位，导致"正常路径"用例红、
  //    而缺陷用例因两端都退化为兜底响应而侥幸绿 —— 掩盖真实基线。
  let i = 0;
  return {
    request: async () => {
      const r = script[i];
      i++;
      return r ?? OK('<html>兜底页面</html>');
    },
    calls: () => i,
  };
}

const run = async (script) => {
  const d = new InlineQueryDetector();
  const c = scripted(script);
  const r = await d.detect({ httpClient: c, target: TARGET, point: POINT, dbms: 'sqlite', config: {} });
  return { r, n: c.calls() };
};

// 真阳性形态：base 不含标记、test 含标记
const BASE_OK = OK('<html>正常页面，无结果</html>');
const TEST_HIT = OK(`<html>查询结果：${INLINE_MARKER}</html>`);

test('自证-0) 常量取自源码（常量漂移则本组守卫全部失效）', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/engine/detectors/InlineQueryDetector.js', import.meta.url), 'utf8');
  assert.ok(src.includes(`'${INLINE_MARKER}'`), `INLINE_MARKER 已漂移，本组守卫失效`);
  assert.ok(src.includes(`'${REFLECTION_PROBE}'`), `REFLECTION_PROBE 已漂移，本组守卫失效`);
});

test('缺陷-1) 反射门控探针失败时不得放行（不得当作"未反射"）', async () => {
  // ⚠️ 护栏会**重发**。若只让第 3 次失败，重发（第 4 次）会拿到兜底正常响应，
  //    判定依据的是真实成功响应 ⇒ 报出内联注入是**正确**的，不算缺陷。
  //    所以这里给足失败次数（重发也失败），对应"网络故障期间"的真实情形。
  //    脚本长度决定请求总数：base + test + 反射探针 + 重发 = 4 次。
  const { r } = await run([BASE_OK, TEST_HIT, FAIL, FAIL]);
  assert.equal(r.vulnerable, false,
    `反射门控探针超时被当成"未反射"从而放行（evidence=${(r.evidence || '').slice(0, 90)}）`);
});

test('缺陷-2) 反射门控探针持续失败同样不得放行', async () => {
  const { r } = await run([BASE_OK, TEST_HIT, FAIL, FAIL]);
  assert.equal(r.vulnerable, false, '反射门控探针持续失败时不得放行');
});

test('契约-3) 反射门控探针正常回显时必须拒绝（门控原始职责不得退化）', async () => {
  // 对照组：上一版我误写了探针字面量，导致对照也报 ⇒ 结论不可信。
  // 这里用真实 REFLECTION_PROBE 构造，并断言它确实被拒绝。
  const { r } = await run([BASE_OK, TEST_HIT, OK(`<html>你输入的值是 ${REFLECTION_PROBE}</html>`)]);
  assert.equal(r.vulnerable, false, '纯文本探针被回显时应由反射门控拒绝');
  assert.match(r.evidence || '', /反射门控拒绝/, '应给出"被反射门控拒绝"的说明');
});

test('契约-4) 反射门控探针正常且未回显时必须放行（真阳性不得被护栏误伤）', async () => {
  // 最关键：护栏只为挡失败样本，正常不反射的页面必须仍能检出。
  const { r } = await run([BASE_OK, TEST_HIT, OK('<html>正常页面，无结果</html>')]);
  assert.equal(r.vulnerable, true, '探针未回显时应正常报出内联注入（不得降低检出能力）');
});

test('契约-5) base 含标记（页面固有）时不得报出', async () => {
  const { r } = await run([OK(`<html>页面固有 ${INLINE_MARKER} 说明</html>`), TEST_HIT,
    OK('<html>正常页面</html>')]);
  assert.equal(r.vulnerable, false, '基线本就含标记时不应报出内联注入');
});

test('契约-6) test 不含标记时不得报出', async () => {
  const { r } = await run([BASE_OK, OK('<html>无结果</html>'), OK('<html>正常页面</html>')]);
  assert.equal(r.vulnerable, false, '测试响应无标记时不应报出');
});