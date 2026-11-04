// ============================================================================
// [D203] LDAP / XPath 注入检测器回归（守卫类，进 gate:close 的 wiring 集合）
//
// 覆盖四层：判定层（真/假差异 + 二次确认 + 误报防线）、配置层（CLI 旗标 / 档案 / REST
// 白名单）、编排层（补充趟按 kind 分派）、重构回归（NoSQL 通道行为不因抽骨架而改变）。
//
// ⚠ 全部是**单元级模拟靶场**（桩 httpClient），不是 LDAP 目录服务 / XPath 真机 A/B。
// 这里只能证明「判据按设计工作」，不能证明真实后端上的检出率 —— 对外结论须带该边界。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LdapXpathInjectionDetector } from '../src/engine/detectors/LdapXpathInjectionDetector.js';
import { NoSqlInjectionDetector } from '../src/engine/detectors/NoSqlInjectionDetector.js';
import { _runNoSql } from '../src/engine/scan/supplementalRuns.js';
import { guardNoSql } from '../src/api/scanGuard/objectGroups.js';
import { parseArgs } from '../bin/cli/args.js';
import { buildConfig } from '../bin/cli/config.js';

const TARGET = { baseUrl: 'http://x/?q=1', method: 'GET' };
const point = () => ({ id: 'p1', param: 'q', originalValue: '1', location: 'url' });
const URL0 = 'http://example.test/p?id=1';

function extractValue(req) {
  try {
    const vals = [...new URL(req.url || '').searchParams.values()];
    if (vals.length) return vals[0];
  } catch {}
  if (req.params && Object.keys(req.params).length) return Object.values(req.params)[0];
  if (req.data && Object.keys(req.data).length) return Object.values(req.data)[0];
  return '';
}

const BASE = 'baseline-neutral-response';
const LONG = 'injection-matched-many-entries-with-a-much-longer-response-body';
const FAIL = { __netErr: { kind: 'timeout', message: 'timeout' } };

/** mode: none | ldap | xpath | jitter | fail | errorSig */
function makeClient(mode = 'none') {
  const calls = [];
  return {
    calls,
    async request(req) {
      const v = String(extractValue(req) || '');
      calls.push(v);
      if (mode === 'fail') return FAIL;
      let data = BASE;
      // 真侧 payload 用**逐字清单**识别，不用宽松正则：payload 里的引号极易让正则
      // 悄悄失配（写第一版时 /1='1/ 就匹配不上 "'1'='1"，测出的是恒绿而非判据）。
      const XPATH_TRUE = ["' or '1'='1", "' or 1=1 or 'a'='", "'] | //*[1=1", "'] | //*[2>1"];
      if (mode === 'ldap' && /(?:objectClass|uid|cn)=\*|!\(/.test(v)) data = LONG;
      if (mode === 'xpath' && XPATH_TRUE.some((m) => v.includes(m))) data = LONG;
      // 只让 primary 真侧出现差异、confirm 侧回到基线 ⇒ 二次确认必须拦下
      if (mode === 'jitter' && v.includes("' or '1'='1")) data = LONG;
      // 注入串让后端抛解析异常，但真/假两侧回的是**同一段错误文本** ⇒ 无任何布尔差异。
      if (mode === 'errorSig' && /' or |objectClass|\]\s*\|/.test(v)) {
        data = 'javax.xml.xpath.XPathExpressionException: Invalid expression';
      }
      return { status: 200, headers: {}, data };
    },
  };
}

const ctxOf = (client, kind, p = point()) => ({
  httpClient: client, target: TARGET, point: p, config: {}, noSqlKind: kind,
});

// ---------- 判定层 ----------

test('D203: LDAP 过滤器真/假差异 + 二次确认 → 命中', async () => {
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(makeClient('ldap'), 'ldap'));
  assert.equal(r.vulnerable, true);
  assert.equal(r.noSqlKind, 'ldap');
  assert.match(r.evidence, /LDAP 过滤器注入/);
  assert.equal(r.payloads.length, 4, 'primary 真/假 + confirm 真/假');
  assert.equal(r.dbms, null, '非 SQL 通道不编造关系型 DBMS');
});

test('D203: XPath 表达式真/假差异 + 二次确认 → 命中', async () => {
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(makeClient('xpath'), 'xpath'));
  assert.equal(r.vulnerable, true);
  assert.equal(r.noSqlKind, 'xpath');
  assert.match(r.evidence, /XPath 表达式注入/);
  assert.equal(r.payloads.length, 4);
});

test('D203: 真/假无差异 → 两类均不误报', async () => {
  const d = new LdapXpathInjectionDetector();
  for (const kind of ['ldap', 'xpath']) {
    const r = await d.detect(ctxOf(makeClient('none'), kind));
    assert.equal(r.vulnerable, false, `${kind} 无差异不应误报`);
  }
});

test('D203: 首次有差异但二次确认不一致 → 视为抖动，不报', async () => {
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(makeClient('jitter'), 'xpath'));
  assert.equal(r.vulnerable, false, '二次确认是硬防线，单次抖动不得报漏洞');
});

test('D203: 网络失败（重发仍失败）→ 不把超时折成空串参与判定', async () => {
  const c = makeClient('fail');
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(c, 'ldap'));
  assert.equal(r.vulnerable, false, '失败样本不得污染结论');
  assert.ok(c.calls.length > 1, '不可用响应应触发重发');
});

test('D203: 响应含 XPath/LDAP 解析错误签名但无布尔差异 → 不报', async () => {
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(makeClient('errorSig'), 'xpath'));
  assert.equal(r.vulnerable, false, '解析报错只证明语法被拒，不证明查询语义可控');
});

test('D203: 未知类别 → 零请求不投', async () => {
  const c = makeClient('ldap');
  const r = await new LdapXpathInjectionDetector().detect(ctxOf(c, 'bogus'));
  assert.equal(r.vulnerable, false);
  assert.equal(c.calls.length, 0, '未知类别连基线都不该发');
});

test('D203: 抽出的布尔判定骨架与 NoSQL 旧行为等价（重构回归）', async () => {
  const client = {
    async request(req) {
      const v = String(extractValue(req) || '');
      return { status: 200, headers: {}, data: v.includes('$gt') ? LONG : BASE };
    },
  };
  const r = await new NoSqlInjectionDetector().detect(ctxOf(client, 'nosql'));
  assert.equal(r.vulnerable, true);
  assert.equal(r.noSqlKind, 'nosql');
  assert.match(r.evidence, /NoSQL 运算符注入/);
});

// ---------- 配置层 ----------

const configOf = (flags, preset) => buildConfig(parseArgs(['-u', URL0, ...flags], preset));

test('D203: --ldap / --xpath 收窄 noSql.kinds', () => {
  assert.deepEqual(configOf(['--ldap']).noSql.kinds, ['ldap']);
  assert.deepEqual(configOf(['--xpath']).noSql.kinds, ['xpath']);
  assert.deepEqual(configOf(['--ldap', '--xpath']).noSql.kinds, ['ldap', 'xpath']);
  assert.equal(configOf(['--ldap']).noSql.enabled, true);
});

test('D203: 与 --no-sql 同给时以显式选中类别为准', () => {
  assert.deepEqual(configOf(['--no-sql', '--ldap']).noSql.kinds, ['ldap']);
});

test('D203: 无旗标时不开通道、--no-sql 仍用原三类（默认行为零侵入）', () => {
  // buildConfig 不会凭空生成 noSql 组（引擎侧回落 defaults）；只有显式开关才 patchGroup。
  assert.equal(configOf([]).noSql?.enabled ?? false, false);
  const c = configOf(['--no-sql']);
  assert.deepEqual(c.noSql.kinds, ['nosql', 'graphql', 'ssti']);
  assert.equal(c.noSql.concurrency, 2, 'patchGroup 带底合并不得抹掉子键');
});

test('D203: --config 档案布尔键与整组对象形态均可达', () => {
  assert.deepEqual(configOf([], { ldap: true }).noSql.kinds, ['ldap']);
  assert.deepEqual(configOf([], { noSql: { enabled: true, kinds: ['xpath'] } }).noSql.kinds, ['xpath']);
});

test('D203: REST guardNoSql 白名单接受两类、剔除未知类别', () => {
  const config = {};
  guardNoSql(config, { noSql: { enabled: true, kinds: ['ldap', 'xpath', 'bogus'], concurrency: 99 } });
  assert.deepEqual(config.noSql.kinds, ['ldap', 'xpath']);
  assert.equal(config.noSql.enabled, true);
  assert.ok(config.noSql.concurrency <= 16, 'concurrency 仍受 clampInt 约束');
});

// ---------- 编排层 ----------

test('D203: 补充趟 kinds=[ldap] 分派到新探测器并产出 vuln', async () => {
  const client = makeClient('ldap');
  const fakeSm = {
    noSqlDetector: new NoSqlInjectionDetector(),
    _wrapWithSignal: (_id, c) => c,
    getScanClient: () => client,
    reportGen: { riskOf: () => 'Medium' },
    _mapPool: async (items, fn) => { for (const it of items) await fn(it); },
    _maybeClose: async () => {},
  };
  const target = { ...TARGET, config: { noSql: { enabled: true, kinds: ['ldap'], concurrency: 1 } } };
  const vulns = await _runNoSql.call(fakeSm, 'd203-test', target, [point()], null);
  assert.equal(vulns.length, 1);
  assert.equal(vulns[0].noSqlKind, 'ldap');
  assert.equal(vulns[0].dbms, null);
});

test('D203: 未启用通道时补充趟零请求', async () => {
  const client = makeClient('ldap');
  const fakeSm = { _wrapWithSignal: (_id, c) => c, getScanClient: () => client };
  const target = { ...TARGET, config: { noSql: { enabled: false } } };
  const vulns = await _runNoSql.call(fakeSm, 'd203-off', target, [point()], null);
  assert.deepEqual(vulns, []);
  assert.equal(client.calls.length, 0);
});
