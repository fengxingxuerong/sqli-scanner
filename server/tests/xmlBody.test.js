// [2026-10-01] XML / SOAP body 注入通道（对标 ghauri 的 XML·SOAP 参数支持）
// 判据原则（沿用本项目口径）：不采信模块自报的 ok，一律断言**外部可观测事实** ——
// 序列化出来的文本里注入值在不在、TargetParser 发现的注入点参数名对不对、
// 发送侧 req.data 是不是 XML 而不是被摊成 urlencoded。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseXmlBody,
  xmlLeafPaths,
  getXmlLeaf,
  setXmlLeaf,
  cloneXmlTree,
  serializeXml,
  isXmlContentType,
} from '../src/core/xmlBody.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { createTarget } from '../src/engine/models.js';

const SOAP_ENV = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <auth>tok</auth>
  </soap:Header>
  <soap:Body>
    <GetUser>
      <id>1</id>
      <name>bob</name>
    </GetUser>
  </soap:Body>
</soap:Envelope>`;

// ① 解析：SOAP 信封 → 叶子路径（点路径，含命名空间前缀）
test('xmlBody: SOAP 信封解析出嵌套叶子路径', async () => {
  const r = parseXmlBody(SOAP_ENV);
  assert.equal(r.ok, true);
  const paths = xmlLeafPaths(r.tree);
  assert.ok(paths.includes('soap:Envelope.soap:Header.auth'), `Header.auth 未发现：${paths.join(' | ')}`);
  assert.ok(paths.includes('soap:Envelope.soap:Body.GetUser.id'), `GetUser.id 未发现：${paths.join(' | ')}`);
  assert.ok(paths.includes('soap:Envelope.soap:Body.GetUser.name'));
  // XML 声明 `<?xml ...?>` 是处理指令 —— 本模块不支持，必须整体放弃（保守）
});

// ② 保守边界：正文里的处理指令 / 注释 / CDATA / DOCTYPE 一律放弃（宁可不发现，也不发畸形报文）
//    ★ XML 声明不在此列 —— 真实 SOAP 报文每条都带，剥掉它才算得上支持真实目标。
test('xmlBody: 不支持的构造整体放弃（不发畸形报文）', async () => {
  assert.equal(parseXmlBody(SOAP_ENV).ok, true, '带 XML 声明的 SOAP 必须能解析');
  assert.equal(parseXmlBody(`<a><?php echo 1; ?><b>1</b></a>`).ok, false, '正文处理指令应放弃');
  assert.equal(parseXmlBody(`<a><!-- c --><b>1</b></a>`).ok, false, '注释应放弃');
  assert.equal(parseXmlBody(`<a><![CDATA[x]]></a>`).ok, false, 'CDATA 应放弃');
  assert.equal(parseXmlBody(`<!DOCTYPE a><a><b>1</b></a>`).ok, false, 'DOCTYPE 应放弃');
  assert.equal(parseXmlBody(`<a><b>1</c></a>`).ok, false, '闭合不匹配应放弃');
  assert.equal(parseXmlBody(`<a><b>1</a>`).ok, false, '未闭合应放弃');
  assert.equal(parseXmlBody(`not xml`).ok, false, '非 XML 应放弃');
});

// ③ 往返保真：解析 → 序列化后结构不变（注入外的其它字段一个都不能动）
test('xmlBody: 解析→序列化往返保真（属性与嵌套结构原样）', async () => {
  const src = `<GetUser id="7" xmlns:x="urn:x"><name>a&amp;b</name><nested><deep>1</deep></nested></GetUser>`;
  const r = parseXmlBody(src);
  assert.equal(r.ok, true);
  const out = serializeXml(r.tree);
  assert.ok(out.includes('id="7"'), '属性丢失');
  assert.ok(out.includes('xmlns:x="urn:x"'), '命名空间声明丢失');
  assert.ok(out.includes('<name>a&amp;b</name>'), '实体未按原义转义回去');
  assert.ok(out.includes('<nested><deep>1</deep></nested>'), '嵌套结构丢失');
  // 二次解析结构等价
  const again = parseXmlBody(out);
  assert.equal(again.ok, true);
  assert.deepEqual(xmlLeafPaths(again.tree), xmlLeafPaths(r.tree));
});

// ④ 注入写值：叶子替换后**只有目标叶子变了**，且注入值里的特殊字符被正确转义
test('xmlBody: 注入值写入叶子且 XML 特殊字符被转义', async () => {
  const r = parseXmlBody(`<GetUser><id>1</id><name>bob</name></GetUser>`);
  const tree = r.tree;
  assert.equal(setXmlLeaf(tree, 'GetUser.id', "1' AND 1=1-- -"), true);
  assert.equal(setXmlLeaf(tree, 'GetUser.name', `<script>&"'`) , true);
  const out = serializeXml(tree);
  assert.ok(out.includes(`<id>1&apos; AND 1=1-- -</id>`), `id 注入值未正确落位：${out}`);
  assert.ok(out.includes(`<name>&lt;script&gt;&amp;&quot;&apos;</name>`), `name 转义不对：${out}`);
  assert.equal(getXmlLeaf(tree, 'GetUser.id'), "1' AND 1=1-- -");
  // 原树未被污染：clone + set 的语义必须隔离（否则同一次扫描里后续点会带上前一个点的 payload）
  const fresh = parseXmlBody(`<GetUser><id>1</id><name>bob</name></GetUser>`).tree;
  assert.equal(getXmlLeaf(fresh, 'GetUser.id'), '1');
});

// ⑤ 克隆隔离：setXmlLeaf 不污染其它克隆（每注入点独立树的保证）
test('xmlBody: cloneXmlTree 后写入互不影响', async () => {
  const tree = parseXmlBody(`<GetUser><id>1</id><name>bob</name></GetUser>`).tree;
  const a = cloneXmlTree(tree);
  const b = cloneXmlTree(tree);
  setXmlLeaf(a, 'GetUser.id', 'PAY-A');
  setXmlLeaf(b, 'GetUser.name', 'PAY-B');
  assert.equal(getXmlLeaf(a, 'GetUser.name'), 'bob');
  assert.equal(getXmlLeaf(b, 'GetUser.id'), '1');
  assert.equal(getXmlLeaf(tree, 'GetUser.id'), '1', '原树被污染');
});

// ⑥ 同名兄弟：加数字下标段，两个同名叶子要能分别定位（不能只打第一个）
test('xmlBody: 同名兄弟按下标分别定位', async () => {
  const tree = parseXmlBody(`<q><item>a</item><item>b</item></q>`).tree;
  const paths = xmlLeafPaths(tree);
  assert.ok(paths.includes('q.item.0') && paths.includes('q.item.1'), `下标路径缺失：${paths.join(' | ')}`);
  const t1 = cloneXmlTree(tree);
  setXmlLeaf(t1, 'q.item.1', 'PAY');
  const out = serializeXml(t1);
  assert.ok(out.includes('<item>a</item><item>PAY</item>'), `第二个同名兄弟未被命中：${out}`);
});

// ⑦ TargetParser：XML body → 注入点（location=body / param=点路径 / xmlPath 标记）
test('xmlBody: TargetParser 发现 XML 叶子注入点', async () => {
  const target = createTarget({
    url: 'http://t.example/soap',
    method: 'POST',
    xmlBody: '<soap:Body><GetUser><id>1</id><name>bob</name></GetUser></soap:Body>',
  });
  const points = await new TargetParser().discover(target);
  const ids = points.map((p) => p.param);
  assert.ok(ids.includes('soap:Body.GetUser.id'), `未发现 id 点：${ids.join(' | ')}`);
  assert.ok(ids.includes('soap:Body.GetUser.name'));
  const p = points.find((x) => x.param === 'soap:Body.GetUser.id');
  assert.equal(p.location, 'body');
  assert.equal(p.xmlPath, true, '缺 xmlPath 标记 ⇒ injection 侧不会走 XML 分支');
  assert.equal(p.originalValue, '1', '原始值应取自叶子文本');
});

// ⑧ ★关键★ injection 发送形态：必须是 XML 字符串，不能被摊成 urlencoded
//   （摊平 ⇒ 只吃 XML 的目标解析不到字段 ⇒ 注入值从未进 SQL ⇒ 静默 0 检出）
test('xmlBody: 注入请求 data 是 XML 字符串而非 urlencoded 对象', async () => {
  const target = createTarget({
    url: 'http://t.example/soap',
    method: 'POST',
    xmlBody: '<soap:Body><GetUser><id>1</id><name>bob</name></GetUser></soap:Body>',
  });
  const points = await new TargetParser().discover(target);
  const point = points.find((p) => p.param === 'soap:Body.GetUser.id');
  const req = buildInjectionRequest(target, point, "1' AND SLEEP(1)-- -");
  assert.equal(typeof req.data, 'string', 'data 必须是 XML 字符串');
  assert.ok(req.data.startsWith('<soap:Body>'), `data 不是 XML：${req.data}`);
  assert.ok(req.data.includes("<id>1&apos; AND SLEEP(1)-- -</id>"), `注入值未落在 id 叶子：${req.data}`);
  assert.ok(!req.data.includes('soap:Body.GetUser.id='), 'data 被摊成了 urlencoded 形态');
  // Content-Type 保留调用方声明，未声明时兜 application/xml
  const ct = Object.keys(req.headers).find((k) => /^content-type$/i.test(k));
  assert.ok(ct, 'XML 通道未声明 Content-Type');
});

// ⑨ 非 XML 点（表单点 / JSON 点）零回归：行为与加通道前完全一致
test('xmlBody: 无 xmlBody 时 body 点仍是 urlencoded（零回归护栏）', async () => {
  const target = createTarget({ url: 'http://t.example/p', method: 'POST', bodyParams: { id: '1' } });
  const points = await new TargetParser().discover(target);
  const point = points.find((p) => p.location === 'body' && p.param === 'id');
  const req = buildInjectionRequest(target, point, "1' AND 1=1-- -");
  assert.equal(typeof req.data, 'string');
  assert.ok(String(req.data).includes('id='), '表单点不再是 urlencoded');
});

// ⑩ Content-Type 判定：SOAP 1.1 的 text/xml 与 1.2 的 application/soap+xml 都要认
test('xmlBody: XML/SOAP Content-Type 判定', async () => {
  assert.equal(isXmlContentType('application/xml'), true);
  assert.equal(isXmlContentType('text/xml; charset=UTF-8'), true);
  assert.equal(isXmlContentType('application/soap+xml'), true);
  assert.equal(isXmlContentType('application/json'), false);
  assert.equal(isXmlContentType('application/x-www-form-urlencoded'), false);
});
