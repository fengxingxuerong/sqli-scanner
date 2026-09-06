// [B-perf] sanitizeStart 白名单补漏测试
// 覆盖：skipStatic / matchString / notString / oob.dnsDomain / oob.dnsPort 的透传与校验
// （这些字段由引擎消费：ScanManager._skipStaticPoints、Detector.matchAnchors、
//   oobReceiver._startDns；此前不在白名单被 sanitizeStart 静默丢弃）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const base = (config) => sanitizeStart({ url: 'http://x.test/?id=1', config });

test('skipStatic：boolean 化透传，缺省不写入 config（引擎沿用 defaults false）', () => {
  assert.equal(base({ skipStatic: true }).config.skipStatic, true);
  assert.equal(base({ skipStatic: false }).config.skipStatic, false);
  assert.equal(base({ skipStatic: 1 }).config.skipStatic, true);
  assert.equal('skipStatic' in base({}).config, false, '缺省不写入（零行为变化）');
});

test('matchString / notString：透传 + 500 截断 + 空值丢弃', () => {
  const out = base({ matchString: 'WELCOME_ADMIN', notString: 'ERROR_BLOCK' }).config;
  assert.equal(out.matchString, 'WELCOME_ADMIN');
  assert.equal(out.notString, 'ERROR_BLOCK');
  // 超长截断到 500
  const long = 'x'.repeat(600);
  const out2 = base({ matchString: long }).config;
  assert.equal(out2.matchString.length, 500);
  // 空串 = 未配置 → 不写入（Detector.matchAnchors 视空串为无锚点）
  const out3 = base({ matchString: '', notString: '' }).config;
  assert.equal('matchString' in out3, false);
  assert.equal('notString' in out3, false);
  // 缺省不写入
  const out4 = base({}).config;
  assert.equal('matchString' in out4, false);
  assert.equal('notString' in out4, false);
});

test('oob.dnsDomain / dnsPort：透传到 config.oob（oobReceiver._startDns 消费）', () => {
  const out = base({
    oob: { enabled: true, dnsDomain: 'attacker.example', dnsPort: 5353 },
  }).config;
  assert.equal(out.oob.enabled, true);
  assert.equal(out.oob.dnsDomain, 'attacker.example');
  assert.equal(out.oob.dnsPort, 5353);
});

test('oob.dnsPort：clamp 到 [1,65535]，非法回退默认 53', () => {
  assert.equal(base({ oob: { dnsPort: 99999 } }).config.oob.dnsPort, 65535);
  assert.equal(base({ oob: { dnsPort: 0 } }).config.oob.dnsPort, 1);
  assert.equal(base({ oob: { dnsPort: 'abc' } }).config.oob.dnsPort, 53);
});

test('oob.dnsDomain：截断到 253（RFC 域名长度上限），缺省回退默认空串', () => {
  const out = base({ oob: { dnsDomain: 'a'.repeat(300) } }).config;
  assert.equal(out.oob.dnsDomain.length, 253);
  assert.equal(base({ oob: { enabled: true } }).config.oob.dnsDomain, '');
  // 非 string 缺省 → defaults
  assert.equal(base({ oob: { dnsDomain: 123 } }).config.oob.dnsDomain, '');
});

test('oob.dnsOob：DNS OOB 轮开关透传（OobDetector DNS 轮消费，boolean 化）', () => {
  const out = base({ oob: { enabled: true, dnsOob: true } }).config;
  assert.equal(out.oob.dnsOob, true);
  assert.equal(base({ oob: { dnsOob: 1 } }).config.oob.dnsOob, true);
  assert.equal(base({ oob: { enabled: true } }).config.oob.dnsOob, false, '缺省关闭');
});

// [主代理收尾] 盲注响应匹配多指标白名单补漏
// （Detector.matchText/_matchByCode/_matchByRegexp/_matchByTitle 消费，
//   此前不在白名单被 sanitizeStart 静默丢弃）
test('matchText / matchTitle：布尔化透传，缺省不写入', () => {
  assert.equal(base({ matchText: true }).config.matchText, true);
  assert.equal(base({ matchText: 1 }).config.matchText, true);
  assert.equal(base({ matchTitle: true }).config.matchTitle, true);
  assert.equal('matchText' in base({}).config, false);
  assert.equal('matchTitle' in base({}).config, false);
});

test('matchCode：true 弱信号透传；对象形态 clamp 到 [100,599] 并丢非法字段', () => {
  assert.equal(base({ matchCode: true }).config.matchCode, true);
  const out = base({ matchCode: { true: 200, false: 500 } }).config;
  assert.deepEqual(out.matchCode, { true: 200, false: 500 });
  // 越界 clamp
  const out2 = base({ matchCode: { true: 999, false: 0 } }).config;
  assert.deepEqual(out2.matchCode, { true: 599, false: 100 });
  // 空对象/数组/字符串 → 不透传
  assert.equal('matchCode' in base({ matchCode: {} }).config, false);
  assert.equal('matchCode' in base({ matchCode: [200] }).config, false);
  assert.equal('matchCode' in base({ matchCode: 'yes' }).config, false);
  assert.equal('matchCode' in base({}).config, false);
});

test('matchRegexp / trueRegexp / falseRegexp：透传 + 500 截断 + 空值丢弃', () => {
  const out = base({ matchRegexp: 'Welcome\\s+Admin', trueRegexp: '^OK', falseRegexp: '^ERR' }).config;
  assert.equal(out.matchRegexp, 'Welcome\\s+Admin');
  assert.equal(out.trueRegexp, '^OK');
  assert.equal(out.falseRegexp, '^ERR');
  const out2 = base({ matchRegexp: 'x'.repeat(600) }).config;
  assert.equal(out2.matchRegexp.length, 500);
  const out3 = base({ matchRegexp: '' }).config;
  assert.equal('matchRegexp' in out3, false);
  assert.equal('matchRegexp' in base({}).config, false);
});

// [sqlmap 对标] autoDynamicBlock / predictOutput 透传（此前不在白名单被静默丢弃，
// ctx.config 永远缺字段 → Detector.buildDynamicSimilar / Extractor.extractBoolean
// 对标能力形同虚设）。autoDynamicBlock 缺省写入 defaults 值（默认 true，对标 sqlmap
// 动态内容感知默认开启）；predictOutput 缺省不写入（引擎回落 defaults true）。
test('autoDynamicBlock：boolean 化透传，缺省回退 defaults（默认开启）', () => {
  assert.equal(base({ autoDynamicBlock: true }).config.autoDynamicBlock, true);
  assert.equal(base({ autoDynamicBlock: false }).config.autoDynamicBlock, false);
  assert.equal(base({ autoDynamicBlock: 1 }).config.autoDynamicBlock, true);
  // 缺省必须显式写入 defaults.autoDynamicBlock（默认 true）——否则 ctx.config 缺字段，
  // 检测器 treat 为未启用（buildDynamicSimilar 返回 null），动态块排除永远不生效。
  assert.equal(base({}).config.autoDynamicBlock, true);
});

test('predictOutput：boolean 化透传（Extractor 常见值缓存开关），缺省不写入', () => {
  assert.equal(base({ predictOutput: false }).config.predictOutput, false);
  assert.equal(base({ predictOutput: 0 }).config.predictOutput, false);
  assert.equal('predictOutput' in base({}).config, false, '缺省不写入（提取器回落 defaults true）');
});
