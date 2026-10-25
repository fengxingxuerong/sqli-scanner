// ============================================================================
// tests/paramName.multipart.test.js —— [D166] multipart 表单**字段名**注入点判据
//
// 背景：`--test-param-names` 的同族宿主此前是 query 键名（D93）、JSON 键名（D103）、
// XML 元素名（D105）、ORDER BY 固定后缀（D106），multipart 表单没有——而「上传 +
// 排序 + 筛选」的表组页恰恰是 multipart 最常见的形态：后端把表单字段**名**当列名
// 拼 SQL（`SELECT ... ORDER BY ${sort}`，字段值被参数化/忽略）⇒ 值注入扫不到。
//
// 七条判据（缺一条即静默假阴性或挂死）：
//   ① TargetParser：opt-in 为每个**文本字段**建 carrier='form' 点（originalValue=字段名）；
//      文件字段名不建点（改名后目标多半丢弃该 part，改了等于没测）；
//   ② 默认关闭 / 非 multipart 目标不建点（开关与载体双重门）；
//   ③ buildFormNameRequest 基线保值：原字段名、原值、文件段原样、boundary 取声明头；
//   ④ 改名不改值：注入时仅换 name="…"，该字段值原样、其余字段/文件段原样、键序保持；
//   ⑤ buildInjectionRequest **入口分流**：paramName 点不得落到 body 分支产出
//      `data:{}` + 继承 multipart CT（axios 自造另一个 boundary ⇒ 目标等数据到超时，
//      实测整轮指纹 8 次全超时、扫描卡死 60s）；
//   ⑥ query 载体不被 form 分支抢走（入口分流对四种 carrier 各自归位）。
// 真靶场判据见 e2e/detect-surface-lab 的 /api/form-sort 与 /safe/form-sort。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest, buildFormNameRequest } from '../src/engine/injection.js';

const MP_B = '----DSLabFormBoundary7MA4';
const PAYLOAD = "id, 9999-- -";

/** -r 抓包导入后的 multipart 目标形态（两个文本字段 + 一个文件字段）。 */
const mpTarget = (cfg = {}) => ({
  mode: 'http',
  method: 'POST',
  baseUrl: 'http://127.0.0.1:8234/api/form-sort',
  bodyParams: { id: '1', name: 'alice' },
  fileParts: [{ name: 'avatar', filename: 'x.png', contentType: 'image/png' }],
  jsonBody: null,
  xmlBody: null,
  xmlTree: null,
  cookieParams: {},
  headerParams: { 'Content-Type': `multipart/form-data; boundary=${MP_B}` },
  config: { level: 1, ...cfg },
});

test('D166-①: 开启时为每个文本字段建 carrier=form 点，originalValue 是字段名本身', async () => {
  const points = await new TargetParser().discover(mpTarget({ testParamNames: true }));
  const pn = points.filter((p) => p.location === 'paramName' && p.carrier === 'form');
  assert.equal(pn.length, 2, `应生成 2 个表单字段名点，实得 ${pn.length}`);
  assert.deepEqual(pn.map((p) => p.param).sort(), ['id', 'name']);
  for (const p of pn) {
    assert.equal(p.originalValue, p.param, 'originalValue 必须是字段名本身（序数探针以它为基准）');
    assert.equal(p.paramNameValue, p.param === 'id' ? '1' : 'alice', 'paramNameValue 记字段原值（改名时值原样保留）');
  }
  // 文件字段名不建点（D166 明确边界：改名后目标多半直接丢弃该 part）
  assert.ok(!pn.some((p) => p.param === 'avatar'), '文件字段名不得建点');
  // 值注入点仍在（参数名点是**追加**，不是替换）：两个文本字段 + 一个文件字段点
  assert.ok(points.some((p) => p.location === 'body' && p.param === 'id'));
  assert.ok(points.some((p) => p.location === 'body' && p.fileField === true && p.param === 'avatar'));
});

test('D166-①: 声明头只在 -r 抓包的 auth.headers 里时也认（D159 两处都看的教训）', async () => {
  const t = mpTarget({ testParamNames: true });
  delete t.headerParams['Content-Type'];
  t.config.auth = { headers: { 'content-type': `multipart/form-data; boundary=${MP_B}` } };
  const points = await new TargetParser().discover(t);
  assert.equal(points.filter((p) => p.location === 'paramName' && p.carrier === 'form').length, 2);
});

test('D166-②: testParamNames 关闭时不生成表单字段名点', async () => {
  const points = await new TargetParser().discover(mpTarget({ testParamNames: false }));
  assert.equal(points.filter((p) => p.carrier === 'form').length, 0);
});

test('D166-②: 非 multipart 目标（urlencoded）不建点，不被 form 分支误伤', async () => {
  const t = mpTarget({ testParamNames: true });
  t.headerParams['Content-Type'] = 'application/x-www-form-urlencoded';
  t.baseUrl = 'http://127.0.0.1:8234/api/form-sort?page=1';
  const points = await new TargetParser().discover(t);
  assert.equal(points.filter((p) => p.carrier === 'form').length, 0);
  // query 键名点仍可建（carrier='query' 族不依赖 multipart）——本判据只钉
  // form 载体不越界，不削弱既有通道
  assert.ok(points.some((p) => p.location === 'paramName' && p.carrier === 'query'), 'query 键名点不受影响');
});

test('D166-③: 基线保值——原字段名、原值、文件段原样、boundary 取声明头', () => {
  const target = mpTarget();
  const point = { location: 'paramName', param: 'id', originalValue: 'id', carrier: 'form', paramNameValue: '1' };
  const req = buildFormNameRequest(target, point, 'id');

  assert.match(req.headers['Content-Type'], new RegExp(`^multipart/form-data; boundary=${MP_B}$`));
  assert.equal(typeof req.data, 'string');
  assert.ok(req.data.includes(`name="${MP_B}"`) === false, 'boundary 不得出现在字段名位');
  assert.ok(req.data.includes('name="id"'), '基线必须保持原字段名');
  assert.ok(req.data.includes('name="alice"') === false, '基线不得引入不存在的字段');
  assert.ok(req.data.includes('name="name"'), '其余文本字段原样');
  assert.ok(req.data.includes('filename="x.png"'), '文件段原样保留（filename 不丢）');
  // 值原样：id 字段的内容仍是 1（抓包里 `name="id"` 段的内容）
  const idPart = /name="id"\r\n\r\n([^\r]*)/.exec(req.data);
  assert.equal(idPart && idPart[1], '1', '基线字段值必须原样');
});

test('D166-④: 改名不改值——注入只换 name="…"，值/其余字段/文件段原样，键序保持', () => {
  const target = mpTarget();
  const point = { location: 'paramName', param: 'id', originalValue: 'id', carrier: 'form', paramNameValue: '1' };
  const req = buildFormNameRequest(target, point, PAYLOAD);

  assert.match(req.headers['Content-Type'], new RegExp(`^multipart/form-data; boundary=${MP_B}$`));
  // 载荷进字段名（Content-Disposition 的 name 属性）
  assert.ok(req.data.includes(`name="${PAYLOAD}"`), '注入值必须写进字段名');
  // 值原样保留：被改名字段的内容仍是 1
  const injectedPart = new RegExp(`name="${PAYLOAD.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\r\\n\\r\\n([^\\r]*)`).exec(req.data);
  assert.equal(injectedPart && injectedPart[1], '1', '改名不改值：字段内容必须原样');
  // 其余字段与文件段原样
  assert.ok(req.data.includes('name="name"'), '其余文本字段保留');
  assert.ok(req.data.includes('name="alice"') === false || req.data.includes('name="name"\r\n\r\nalice'), 'name 字段的值仍是 alice');
  assert.ok(req.data.includes('filename="x.png"'), '文件段保留');
  // 键序保持：id（改名后）仍排在 name 前面——「取第一个字段名当列名」的后端依赖顺序
  assert.ok(req.data.indexOf(`name="${PAYLOAD}"`) < req.data.indexOf('name="name"'), '改名后字段不得被挪到末尾');
});

test('D166-④: 载荷名内引号转义——不得提前闭合 Content-Disposition', () => {
  const target = mpTarget();
  const point = { location: 'paramName', param: 'id', originalValue: 'id', carrier: 'form' };
  const req = buildFormNameRequest(target, point, 'x" onload="alert(1)');
  assert.ok(req.data.includes('name="x\\" onload=\\"alert(1)"'), '名内引号必须转义');
  assert.ok(!/\r\n\r\n[^\r]*onload/.test(req.data), '不得把属性内容泄进段体');
});

test('D166-⑤: 入口分流——form 点经 buildInjectionRequest 不得产出 data:{}', () => {
  // 指纹/边界路径直接调 buildInjectionRequest（不经 Detector.buildRequest）。
  // 旧行为：paramName 点落到 body 分支 ⇒ data:{} + 继承 multipart CT ⇒ axios
  // 自造另一个 boundary ⇒ 目标等数据到超时（整轮指纹 8 次全超时的根因）。
  const target = mpTarget();
  const point = { location: 'paramName', param: 'id', originalValue: 'id', carrier: 'form', paramNameValue: '1' };
  const req = buildInjectionRequest(target, point, PAYLOAD);

  assert.equal(typeof req.data, 'string', '必须是 multipart 报文字符串，不得是 data:{}');
  assert.notDeepEqual(req.data, {});
  assert.match(req.headers['Content-Type'], new RegExp(`^multipart/form-data; boundary=${MP_B}$`));
  assert.ok(req.data.includes(`name="${PAYLOAD}"`), '载荷必须进字段名');
});

test('D166-⑥: query 载体不被 form 分支抢走（入口分流四种 carrier 各自归位）', () => {
  const target = {
    mode: 'http',
    method: 'GET',
    baseUrl: 'http://lab.local/colfilter?name=Keyboard',
    headerParams: {},
    config: { level: 1 },
  };
  const point = { location: 'paramName', param: 'name', originalValue: 'name', carrier: 'query' };
  const req = buildInjectionRequest(target, point, PAYLOAD);

  // query 键名构造器的合法形态就是 data:{}（注入面在 URL），url 里的键名被换掉
  assert.deepEqual(req.data, {});
  assert.ok(req.url.includes(`?${encodeURIComponent(PAYLOAD)}=Keyboard`), 'query 键名必须被改成载荷');
  // JSON 载体同样归位（回归 D103：入口分流不得只认 form）
  const jTarget = {
    mode: 'http', method: 'POST', baseUrl: 'http://lab.local/api',
    headerParams: { 'Content-Type': 'application/json' },
    jsonBody: { name: 'Keyboard' }, config: { level: 1 },
  };
  const jReq = buildInjectionRequest(jTarget, { location: 'paramName', param: 'name', originalValue: 'name', carrier: 'json' }, PAYLOAD);
  assert.equal(typeof jReq.data, 'string', 'JSON 键名点必须走 JSON 构造器（串化 body）');
  const body = JSON.parse(jReq.data);
  assert.ok(PAYLOAD in body, 'JSON 键名必须被改成载荷');
  assert.equal(body[PAYLOAD], 'Keyboard', 'JSON 键的值原样保留');
});
