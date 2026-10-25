// ============================================================================
// fingerprint.function.test.js —— [D167] 函数存在性定库（盲/静默目标第三条通道）
// ============================================================================
// 场景（真机实测 e2e/multi-engine-lab 的 `/blind`）：目标吞掉报错、页面只有「查到/没查到」
// 两态、引擎又没有可用延时原语 ⇒ 报错签名与时间向量都定不出库。判据是三值对照：
//   真基线 `AND 1=1` / 假基线 `AND 1=2` / 探针 `AND <该库独占函数> IS NOT NULL`
//   探针页必须≈真基线且≠假基线；另有负向对照（不存在的函数）自证「报错页≠真页」。
// 这些用例用假 httpClient 把三种响应形态钉死，避免真靶场依赖。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';

// 三态页面刻意**不含回显**：回显场景由真靶场（e2e/multi-engine-lab /blind 会回显 uid）
// 覆盖，这里只钉判据本身；含回显的假页会让 stripEchoedPayload 后的"干净正文"仍残留
// 各探针不同的文本，把相似判定搅浑（测试数据自伤，与实现无关）。
const TRUE_PAGE = `<html><body><p>found</p>${'<div>data</div>'.repeat(20)}</body></html>`;
const FALSE_PAGE = '<html><body><p>not found</p></body></html>';
const ERROR_PAGE = '<html><body><p>not found</p></body></html>';

/**
 * 造一个假 httpClient：按 URL 里的 payload 文本返回三类页面之一。
 * @param {(url: string) => string} classify
 */
function stubClient(classify) {
  return {
    /** @param {any} opts */
    request: async (opts) => ({ status: 200, data: classify(decodeURIComponent(String(opts.url || ''))) }),
  };
}

async function runFp(classify) {
  const target = createTarget({ url: 'http://shop.example.com/blind?uid=1', method: 'GET', config: { level: 1 } });
  const point = createInjectionPoint('url', 'uid', '1');
  point.boundary = '';
  const fp = new DBFingerprinter();
  return fp._fingerprintByFunction({ httpClient: stubClient(classify), config: target.config }, stubClient(classify), target, point, (s) => s);
}

test('[D167] 探针≈真基线且≠假基线 ⇒ 定库（H2 独占函数）', async () => {
  const dbms = await runFp((url) => {
    if (/1=2(?:--|-)?/.test(url) && !/NO_SUCH_FN/.test(url)) return FALSE_PAGE;
    if (/H2VERSION\(\)/.test(url)) return TRUE_PAGE;
    if (/1=1/.test(url)) return TRUE_PAGE;
    return ERROR_PAGE;
  });
  assert.equal(dbms, 'H2');
});

test('[D167] 探针页=假基线（函数不存在）⇒ 不定库', async () => {
  const dbms = await runFp((url) => (/1=1(?:--|-)?/.test(url) && !/H2VERSION/.test(url) ? TRUE_PAGE : FALSE_PAGE));
  assert.equal(dbms, null);
});

test('[D167] 没有布尔差分（真/假基线同页）⇒ 通道不适用，不定库', async () => {
  const dbms = await runFp(() => TRUE_PAGE);
  assert.equal(dbms, null);
});

test('[D167] 负向对照自证失败（报错页≈真基线页）⇒ 不信探针，不定库', async () => {
  const dbms = await runFp((url) => {
    if (/1=2/.test(url)) return FALSE_PAGE;
    // 不存在的函数与真基线同页：说明目标把"函数不存在"渲染成正常页
    return TRUE_PAGE;
  });
  assert.equal(dbms, null);
});
