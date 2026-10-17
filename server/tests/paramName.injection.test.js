// ============================================================================
// tests/paramName.injection.test.js —— [D93] 参数名注入点三处接缝判据
//
// 背景：后端把 **query 键名**拼进 SQL（`WHERE ${Object.keys(req.query)[0]} = ?`）时，
// 值被参数化 ⇒ 值注入扫不到，只有改键名能打。三个接缝各有一条判据，缺一条就会出现
// 「点位生成了但检测恒判非注入」或「点位被预筛选恒跳过」的静默假阴性：
//   ① TargetParser：opt-in 生成点，originalValue 必须是**键名**（不是键的值）
//   ② buildInjectionRequest：基线保持原键名；注入时改键名、值原样保留
//   ③ boundary：paramName 点不做闭合探测（键名拼接无引号上下文）
// 真靶场判据见 e2e/param-name-lab（vuln 双向 + 开关关闭对照 + 安全白名单）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildParamNameRequest } from '../src/engine/injection.js';
import { probeBoundary } from '../src/engine/detectorSupport/boundary.js';

const makeTarget = (cfg = {}) => ({
  mode: 'http',
  method: 'GET',
  baseUrl: 'http://lab.local/colfilter?name=Keyboard',
  bodyParams: {},
  jsonBody: null,
  xmlBody: null,
  xmlTree: null,
  cookieParams: {},
  headerParams: {},
  config: { level: 1, ...cfg },
});

test('D93-①: testParamNames 关闭时不生成参数名点', async () => {
  const points = await new TargetParser().discover(makeTarget({ testParamNames: false }));
  assert.equal(points.filter((p) => p.location === 'paramName').length, 0);
});

test('D93-①: 开启时为每个 query 参数生成点，且 originalValue 是键名本身', async () => {
  const points = await new TargetParser().discover(makeTarget({ testParamNames: true }));
  const pn = points.filter((p) => p.location === 'paramName');
  assert.equal(pn.length, 1, `应生成 1 个参数名点，实得 ${pn.length}`);
  assert.equal(pn[0].param, 'name');
  assert.equal(pn[0].originalValue, 'name', '原始值必须是键名（检测器以它为基准构造 `name AND 1=1`）');
  // 值注入点仍在（参数名点是**追加**，不是替换）
  assert.ok(points.some((p) => p.location === 'url' && p.param === 'name'));
});

test('D93-②: 基线请求保持原键名，注入请求改键名且值原样保留', () => {
  const target = makeTarget();
  const point = { location: 'paramName', param: 'name', originalValue: 'name' };
  const base = buildParamNameRequest(target, point, 'name');
  assert.match(base.url, /\?name=Keyboard$/, `基线应原样（实得 ${base.url}）`);
  const inj = buildParamNameRequest(target, point, 'name AND 1=1-- -');
  assert.match(inj.url, /^http:\/\/lab\.local\/colfilter\?name%20AND%201%3D1--%20-=Keyboard$/,
    `注入应改键名并保留值（实得 ${inj.url}）`);
  // 其余参数不受影响
  const t2 = { ...target, baseUrl: 'http://lab.local/colfilter?name=Keyboard&x=1' };
  const inj2 = buildParamNameRequest(t2, point, 'name OR 1=1-- -');
  assert.match(inj2.url, /&x=1$/, '伴随参数必须保留');
});

test('D93-③: 参数名点不做闭合探测（直接返回空前缀）', async () => {
  const ctx = {
    point: { location: 'paramName', param: 'name', originalValue: 'name' },
    // 任何请求都不该发出：一旦发出说明跳过逻辑失效
    send: async () => { throw new Error('参数名点不应发出闭合探测请求'); },
  };
  const prefix = await probeBoundary.call(ctx, ctx);
  assert.equal(prefix, '');
});
