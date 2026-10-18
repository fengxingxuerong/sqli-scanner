// ============================================================================
// tests/paramName.injection.test.js —— [D93] 参数名注入点三处接缝判据（[D103] 扩 JSON 键名）
//
// 背景：后端把 **query 键名**拼进 SQL（`WHERE ${Object.keys(req.query)[0]} = ?`）时，
// 值被参数化 ⇒ 值注入扫不到，只有改键名能打。三个接缝各有一条判据，缺一条就会出现
// 「点位生成了但检测恒判非注入」或「点位被预筛选恒跳过」的静默假阴性：
//   ① TargetParser：opt-in 生成点，originalValue 必须是**键名**（不是键的值）
//   ② buildInjectionRequest：基线保持原键名；注入时改键名、值原样保留
//   ③ boundary：paramName 点不做闭合探测（键名拼接无引号上下文）
// 真靶场判据见 e2e/param-name-lab（vuln 双向 + 开关关闭对照 + 安全白名单）。
// [D103 2026-10-18] 同型结构面延伸：JSON body 键名（carrier='json'）——后端
// `Object.keys(req.body)[0]` 当列名拼 SQL，键是合法字符串可承载布尔载荷；判据 D103-*。
// [D105 2026-10-18] XML body 元素名（carrier='xml'，P1-1 余项）——NameChar 不允许空格/引号
// ⇒ 布尔载荷发出即畸形报文，载荷族改为算术位移（`tag-0` 恒等 / `tag-1` 位移），
// 由专用验证器判定；判据 D105-*。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildParamNameRequest, buildJsonKeyRequest, buildXmlKeyRequest } from '../src/engine/injection.js';
import { probeBoundary } from '../src/engine/detectorSupport/boundary.js';
import { XmlParamNameDetector } from '../src/engine/detectorSupport/xmlParamName.js';
import { parseXmlBody, cloneXmlTree, serializeXml, renameXmlTag, isXmlName } from '../src/core/xmlBody.js';

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

// ── [D103] JSON body 键名（carrier='json'）──────────────────────────────────

const makeJsonTarget = (cfg = {}, extra = {}) => ({
  mode: 'http',
  method: 'POST',
  baseUrl: 'http://lab.local/colfilter-json',
  bodyParams: {},
  jsonBody: { name: 'Keyboard' },
  xmlBody: null,
  xmlTree: null,
  cookieParams: {},
  headerParams: { 'Content-Type': 'application/json' },
  config: { level: 1, ...cfg },
  ...extra,
});

test('D103-①: 关闭时不生成 JSON 键名点；开启时每个对象键生成（originalValue=键名, carrier=json）', async () => {
  const body = { name: 'Keyboard', user: { id: 7 }, tags: ['x', 'y'], ok: true, meta: null };
  const off = await new TargetParser().discover(makeJsonTarget({ testParamNames: false }, { jsonBody: body }));
  assert.equal(off.filter((p) => p.location === 'paramName').length, 0);

  const on = await new TargetParser().discover(makeJsonTarget({ testParamNames: true }, { jsonBody: body }));
  const pn = on.filter((p) => p.location === 'paramName');
  const byParam = new Map(pn.map((p) => [p.param, p]));
  // 顶层键 + 嵌套对象键：各一个键名点
  assert.ok(byParam.has('name') && byParam.has('user.id'), `键名点参数：${[...byParam.keys()].join('、')}`);
  assert.equal(byParam.get('name').originalValue, 'name', 'originalValue 必须是键名本身');
  assert.equal(byParam.get('user.id').originalValue, 'id');
  assert.equal(byParam.get('name').carrier, 'json');
  // 数组下标不是"名字"（无法改名）：tags.0/tags.1 不生成键名点；bool/null 不是叶子不给键名点
  assert.ok(!byParam.has('tags.0') && !byParam.has('tags.1'));
  assert.ok(!byParam.has('ok') && !byParam.has('meta'));
  // 值注入点仍在（键名点是**追加**）：body 叶子照旧全覆盖
  assert.ok(on.some((p) => p.location === 'body' && p.param === 'name'));
  assert.ok(on.some((p) => p.location === 'body' && p.param === 'user.id'));
});

test('D103-①: query 键名与 JSON 键名同名不互相去重（carrier 进去重键）', async () => {
  const t = makeJsonTarget({ testParamNames: true });
  const points = await new TargetParser().discover(t);
  const pn = points.filter((p) => p.location === 'paramName');
  // query 无参数，仅 JSON 侧一个 name 点即可通过；此处直接用同名场景验证两份共存：
  const t2 = makeJsonTarget({ testParamNames: true });
  t2.baseUrl = 'http://lab.local/colfilter-json?name=Keyboard';
  const points2 = await new TargetParser().discover(t2);
  const pn2 = points2.filter((p) => p.location === 'paramName');
  assert.equal(pn2.length, 2, `query+JSON 同名键名点应共存，实得 ${pn2.length}`);
  assert.deepEqual(pn2.map((p) => p.carrier || 'query').sort(), ['json', 'query']);
  assert.equal(pn.length, 1);
});

test('D103-②: 基线请求保持原键名/原 body；注入请求改键名且叶子值原样', () => {
  const target = makeJsonTarget();
  const point = {
    location: 'paramName', carrier: 'json', param: 'name', originalValue: 'name', paramNameValue: 'Keyboard',
  };
  const base = buildJsonKeyRequest(target, point, 'name');
  assert.equal(base.data, '{"name":"Keyboard"}', '基线必须原键名原 body');
  assert.equal(base.method, 'POST');
  const inj = buildJsonKeyRequest(target, point, 'name AND 1=1-- -');
  assert.deepEqual(JSON.parse(inj.data), { 'name AND 1=1-- -': 'Keyboard' }, '改键名、叶子值原样保留');
  assert.ok(!inj.data.includes('"name"'), '原键名必须被替换掉');
  assert.match(inj.url, /\/colfilter-json$/);
});

test('D103-②: 嵌套路径（对象+数组下标）改键不伤兄弟键；键含点号的引号段路径互逆', () => {
  const target = makeJsonTarget({}, {
    jsonBody: { user: { id: 7, name: 'Tom' }, items: [{ sku: 'A1' }, { sku: 'B2' }], 'a.b': 'x' },
  });
  const p1 = { location: 'paramName', carrier: 'json', param: 'user.id', originalValue: 'id' };
  const r1 = JSON.parse(buildJsonKeyRequest(target, p1, 'id AND 1=2-- -').data);
  assert.deepEqual(r1.user, { 'id AND 1=2-- -': 7, name: 'Tom' });

  const p2 = { location: 'paramName', carrier: 'json', param: 'items.1.sku', originalValue: 'sku' };
  const r2 = JSON.parse(buildJsonKeyRequest(target, p2, 'sku OR 1=1-- -').data);
  // 数组下标保持数字（不是字符串键）⇒ JSON.parse 后仍是数组
  assert.ok(Array.isArray(r2.items) && r2.items[0].sku === 'A1');
  assert.deepEqual(r2.items[1], { 'sku OR 1=1-- -': 'B2' });

  const p3 = { location: 'paramName', carrier: 'json', param: '"a.b"', originalValue: 'a.b' };
  const r3 = JSON.parse(buildJsonKeyRequest(target, p3, 'a.b AND 1=1-- -').data);
  assert.equal(r3['a.b AND 1=1-- -'], 'x');
  assert.ok(!('a.b' in r3), '点号键必须按引号段互逆规则整体改名');
});

test('D103-②: 路径失效时原样 body（不发坏报文、不抛错）', () => {
  const target = makeJsonTarget();
  const bad = { location: 'paramName', carrier: 'json', param: 'nope.missing', originalValue: 'missing' };
  const r = buildJsonKeyRequest(target, bad, 'missing AND 1=1-- -');
  assert.deepEqual(JSON.parse(r.data), { name: 'Keyboard' }, '路径失效应回落原 body');
});

test('D103-③: JSON 键名点同样跳过闭合探测（boundary 恒空，与载体无关）', async () => {
  const ctx = {
    point: { location: 'paramName', carrier: 'json', param: 'name', originalValue: 'name' },
    send: async () => { throw new Error('JSON 键名点不应发出闭合探测请求'); },
  };
  const prefix = await probeBoundary.call(ctx, ctx);
  assert.equal(prefix, '');
});

// ── [D105] XML body 元素名（carrier='xml'）─────────────────────────────────

const XML_BODY = '<?xml version="1.0" encoding="UTF-8"?><filter><price>499</price></filter>';
const makeXmlTarget = (cfg = {}, extra = {}) => ({
  mode: 'http',
  method: 'POST',
  baseUrl: 'http://lab.local/colfilter-xml',
  bodyParams: {},
  jsonBody: null,
  xmlBody: XML_BODY,
  xmlTree: null,
  cookieParams: {},
  headerParams: {},
  config: { level: 1, ...cfg },
  ...extra,
});

test('D105-①: 关闭时不生成 XML 元素名点；开启时生成（originalValue=元素名, carrier=xml）', async () => {
  const off = await new TargetParser().discover(makeXmlTarget({ testParamNames: false }));
  assert.equal(off.filter((p) => p.location === 'paramName').length, 0);
  const on = await new TargetParser().discover(makeXmlTarget({ testParamNames: true }));
  const pn = on.filter((p) => p.location === 'paramName');
  assert.equal(pn.length, 1, `应生成 1 个元素名点，实得 ${pn.length}`);
  assert.equal(pn[0].param, 'filter.price');
  assert.equal(pn[0].originalValue, 'price', 'originalValue 必须是元素名本身');
  assert.equal(pn[0].carrier, 'xml');
  // 值注入点仍在（元素名点是**追加**）
  assert.ok(on.some((p) => p.location === 'body' && p.xmlPath === true));
});

test('D105-①: 命名空间标签/同名兄弟路径：元素名提取跳过下标段', async () => {
  const xml = '<soap:Envelope><soap:Body><item><sku>A</sku></item><item><sku>B</sku></item></soap:Body></soap:Envelope>';
  const t = makeXmlTarget({ testParamNames: true }, { xmlBody: xml });
  const pn = (await new TargetParser().discover(t)).filter((p) => p.location === 'paramName');
  assert.deepEqual(pn.map((p) => p.originalValue).sort(), ['sku', 'sku']);
  assert.deepEqual(
    pn.map((p) => p.param).sort(),
    ['soap:Envelope.soap:Body.item.0.sku', 'soap:Envelope.soap:Body.item.1.sku']
  );
});

test('D105-②: 基线原报文逐字一致；注入换元素名（开闭标签同改），文本/属性/兄弟原样', async () => {
  const xml = '<?xml version="1.0"?><filter><price currency="CNY">499</price><note>hi</note></filter>';
  const t = makeXmlTarget({ testParamNames: true }, { xmlBody: xml });
  await new TargetParser().discover(t); // 填充 xmlTree（生产链路同此）
  const point = { location: 'paramName', carrier: 'xml', param: 'filter.price', originalValue: 'price' };
  const base = buildXmlKeyRequest(t, point, 'price');
  assert.equal(base.data, xml, '基线必须与调用方原报文逐字一致');
  const inj = buildXmlKeyRequest(t, point, 'price-0');
  // 注入报文经解析树重序列化：XML 声明不保留（与既有 XML **值**通道 setXmlLeaf 同源行为，
  // 解析时声明已被剥离；基线仍逐字原样）——本条断言钉住该既有口径，变动即红。
  assert.equal(
    inj.data,
    '<filter><price-0 currency="CNY">499</price-0><note>hi</note></filter>'
  );
  assert.equal(inj.headers['Content-Type'], 'application/xml');
});

test('D105-②: 非法元素名（空格/引号载荷）/路径失效一律回退原报文——绝不发畸形 XML', async () => {
  const t = makeXmlTarget({ testParamNames: true });
  await new TargetParser().discover(t);
  const point = { location: 'paramName', carrier: 'xml', param: 'filter.price', originalValue: 'price' };
  for (const bad of ['price AND 1=1-- -', 'price=1', '1price', 'price OR 1=1']) {
    assert.equal(buildXmlKeyRequest(t, point, bad).data, XML_BODY, `非法名 ${JSON.stringify(bad)} 必须原样回退`);
  }
  const miss = { ...point, param: 'nope.missing' };
  assert.equal(buildXmlKeyRequest(t, miss, 'price-0').data, XML_BODY, '路径失效应回落原报文');
  // 合法性判定的正/反例（renameXmlTag 的单点守卫）
  assert.ok(isXmlName('price-0') && isXmlName('soap:Body') && isXmlName('a.b-c'));
  assert.ok(!isXmlName('a b') && !isXmlName('9a') && !isXmlName("x'"));
});

test('D105-②: renameXmlTag 改命名空间标签；非法名拒绝', () => {
  const parsed = parseXmlBody('<soap:Envelope><soap:Body><id>1</id></soap:Body></soap:Envelope>');
  assert.ok(parsed.ok);
  const tree = cloneXmlTree(parsed.tree);
  assert.equal(renameXmlTag(tree, 'soap:Envelope.soap:Body.id', 'id-1'), true);
  assert.match(serializeXml(tree), /<id-1>1<\/id-1>/);
  assert.equal(renameXmlTag(tree, 'soap:Envelope.soap:Body.id', 'bad name'), false);
});

// —— D105-③ 专用验证器：模拟端点（真/安全/静态/网络失败）——

const xmlPage = (rows) => `<html><body>${rows}</body></html>`;
const ROW = '<p>1 | Mechanical Keyboard | 499.00</p>';
const NO_ROWS = '<p>NO_ROWS</p>';

function makeXmlClient(kind) {
  const reqs = [];
  return {
    reqs,
    async request(opts) {
      if (kind === 'netfail') return { status: 0, data: '', __netErr: { kind: 'timeout' } };
      const data = String(opts.data || '');
      reqs.push(data);
      // 取「直接含文本的叶子元素」的标签名（根元素无直接文本，不会误取）
      const m = /<([A-Za-z_][\w.:-]*)(?:[^>]*)?>([^<]*)<\/\1>/.exec(data);
      const tag = m ? m[1] : '';
      if (kind === 'vuln') return { status: 200, data: xmlPage(tag === 'price-1' ? NO_ROWS : ROW) };
      if (kind === 'safe') return { status: 200, data: xmlPage(tag === 'price' ? ROW : NO_ROWS) };
      return { status: 200, data: xmlPage('STATIC') };
    },
  };
}

function xmlCtx(client) {
  const parsed = parseXmlBody(XML_BODY);
  const target = makeXmlTarget({}, { xmlTree: parsed.ok ? parsed.tree : null });
  return {
    httpClient: client,
    target,
    point: { id: 'x1', location: 'paramName', carrier: 'xml', param: 'filter.price', originalValue: 'price' },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0 },
  };
}

test('D105-③: 真端点命中（-0 恒等 / -1 位移），5 请求含复核轮', async () => {
  const client = makeXmlClient('vuln');
  const r = await new XmlParamNameDetector().detect(xmlCtx(client));
  assert.equal(r.vulnerable, true);
  assert.equal(r.technique, 'boolean');
  assert.deepEqual(r.payloads, ['price-0', 'price-1']);
  assert.equal(client.reqs.length, 5, 'B/P0/P1 + B复核/P1复核');
  assert.match(r.evidence, /price-0 响应与基线一致/);
});

test('D105-③: 白名单端点零误报（恒等不成立）；静态端点零误报（位移无差）', async () => {
  const safeClient = makeXmlClient('safe');
  const rSafe = await new XmlParamNameDetector().detect(xmlCtx(safeClient));
  assert.equal(rSafe.vulnerable, false);
  assert.equal(safeClient.reqs.length, 2, 'B/P0 即止（P0 已 ≠ B，无需求 P1）');

  const staticClient = makeXmlClient('static');
  const rStatic = await new XmlParamNameDetector().detect(xmlCtx(staticClient));
  assert.equal(rStatic.vulnerable, false);
  assert.equal(staticClient.reqs.length, 3, 'B/P0/P1 后即止（P1==B）');
});

test('D105-③: 网络不可用 → inconclusive（记未决，不写阴性结论）', async () => {
  const r = await new XmlParamNameDetector().detect(xmlCtx(makeXmlClient('netfail')));
  assert.equal(r.vulnerable, false);
  assert.equal(r.inconclusive, true);
  assert.match(String(r.inconclusiveReason), /不可用/);
});
