// ============================================================================
// keyBool.test.js —— 多键拼接形态（键名进 WHERE 布尔位置）判据
// [D169 立（form 载体），D173 扩到 query 载体]
// ============================================================================
// 缺陷实证：`/api/form-filter-blind`（SQL 错误被吞成「没查到」）上，通用布尔通道的
// `{k} AND 1=1-- -` 因 varchar 列名被 MySQL 当数值 0 ⇒ 恒真恒假都 0 行 ⇒ 0 检出；
// orderByKey 的序数差分（`{k}, 1-- -`）在 WHERE 位置只会语法错误 ⇒ 同样 0。
// 判据：把键名换成**自洽布尔式**并用行注释吞掉固定后缀：
//   T = `{k} = 'x' OR 1=1-- `（全部行）/ F = `{k} = 'x' OR 1=2-- `（空）
//   C = 未知列 + 同一后缀（应不分化）
// 下面用假 httpClient 钉住四种形态（命中 / 无分化 / 对照同真 / 非 form 载体）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KeyBoolDetector } from '../src/engine/detectorSupport/keyBool.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';

const ALL_ROWS = `<html><body><table>${'<tr><td>1</td><td>alice</td></tr>'.repeat(3)}</table></body></html>`;
const NO_ROWS = '<html><body><table></table></body></html>';

/**
 * 假 httpClient：从请求里取「注入后的键名」（multipart 报文看 name= / query 载体看 URL）
 * 并交给 classify 决定返回哪种页面。
 * @param {(keyName: string) => string} classify
 */
function stubClient(classify) {
  return {
    request: async (opts) => {
      const raw = String(opts.data || '');
      let key = null;
      // multipart：看 form-data 的 name="…"
      const m = /name="([^"]*)"/i.exec(raw);
      if (m) key = m[1];
      // JSON body：看键名（改名后新键可能排到末尾，故优先取带探针特征的那个键）
      if (key == null && raw.trim().startsWith('{')) {
        try {
          const keys = Object.keys(JSON.parse(raw));
          key = keys.find((k) => /OR 1=\d--\s*$/.test(k)) ?? keys[0] ?? null;
        } catch { /* 非 JSON：落到 URL 分支 */ }
      }
      // query 载体：看 URL 里的键
      if (key == null) {
        try {
          const u = new URL(String(opts.url || ''));
          key = [...u.searchParams.keys()][0] ?? null;
        } catch { /* URL 解析失败：按空键名处理 */ }
      }
      return { status: 200, data: classify(key ?? '') };
    },
  };
}

async function detectWith(classify, carrier = 'form') {
  // query 载体的键名必须**出现在目标 URL 里**（buildParamNameRequest 只改已有键，不新增）
  const url = carrier === 'query'
    ? 'http://shop.example.com/api/query-filter?name=alice&go=1'
    : 'http://shop.example.com/api/form-filter';
  // JSON 载体的键名必须出现在 target.jsonBody 里（buildJsonKeyRequest 沿点路径改名）
  const jsonBody = carrier === 'json' ? { name: 'alice', go: '1' } : null;
  const target = createTarget({
    url,
    method: 'POST',
    bodyParams: carrier === 'json' ? {} : { name: 'alice', go: '1' },
    jsonBody,
    headerParams: carrier === 'json'
      ? { 'Content-Type': 'application/json' }
      : { 'Content-Type': 'multipart/form-data; boundary=----B' },
    config: { level: 3 },
  });
  const point = createInjectionPoint('paramName', 'name', 'name', {
    carrier,
    paramNameValue: 'alice',
    formValues: { name: 'alice', go: '1' },
  });
  const detector = new KeyBoolDetector();
  return detector.detect({ httpClient: stubClient(classify), target, point, config: target.config, dbms: null });
}

test('[D169] 恒真/恒假分化 + 未知列对照不分化 ⇒ 判为注入', async () => {
  const r = await detectWith((name) => (/OR 1=1--\s*$/.test(name) && /(^| )name =/.test(name) ? ALL_ROWS : NO_ROWS));
  assert.equal(r.vulnerable, true);
  assert.equal(r.technique, 'boolean');
  assert.match(r.evidence, /多键拼接/);
});

test('[D169] 盲档无分化（恒真恒假同页）⇒ 不判注入', async () => {
  const r = await detectWith(() => NO_ROWS);
  assert.equal(r.vulnerable, false);
});

test('[D169] 负向对照也同真（键名没进 SQL）⇒ 不判注入', async () => {
  const r = await detectWith(() => ALL_ROWS);
  assert.equal(r.vulnerable, false);
});

test('[D169] XML 载体（元素名）不在本判据范围，零请求跳过', async () => {
  let calls = 0;
  const r = await detectWith(() => { calls += 1; return ALL_ROWS; }, 'xml');
  assert.equal(r.vulnerable, false);
  assert.equal(calls, 0);
});

// ===== [D174] JSON 载体（body 键名进 WHERE 布尔位置）=====

test('[D174] JSON 键名：恒真/恒假分化 + 未知列对照不分化 ⇒ 判为注入', async () => {
  const r = await detectWith(
    (key) => (/OR 1=1--\s*$/.test(key) && /(^| )name =/.test(key) ? ALL_ROWS : NO_ROWS),
    'json'
  );
  assert.equal(r.vulnerable, true);
  assert.match(r.evidence, /JSON 键名/, '证据文案应点明 JSON 载体');
});

test('[D174] JSON 键名：无分化 ⇒ 不判注入', async () => {
  const r = await detectWith(() => NO_ROWS, 'json');
  assert.equal(r.vulnerable, false);
});

// ===== [D173] query 载体（URL 参数名进 WHERE 布尔位置）=====

test('[D173] query 键名：恒真/恒假分化 + 未知列对照不分化 ⇒ 判为注入', async () => {
  const r = await detectWith(
    (key) => (/OR 1=1--\s*$/.test(key) && /(^| )name =/.test(key) ? ALL_ROWS : NO_ROWS),
    'query'
  );
  assert.equal(r.vulnerable, true);
  assert.match(r.evidence, /查询参数名/, '证据文案应点明 query 载体');
});

test('[D173] query 键名：无分化（盲档同页）⇒ 不判注入', async () => {
  const r = await detectWith(() => NO_ROWS, 'query');
  assert.equal(r.vulnerable, false);
});
