// 子句位置感知 payload（对标 sqlmap clause 属性体系）+ payload 扩容合法性 + 布尔判定 content-length 短路
// 覆盖：
//   1) CLAUSE_PAYLOADS 结构与有界约定（clause 元数据 / 真假对 / 每库每 clause 每技术 ≤3 / 与主模板无重复）
//   2) level 门控：level=1（默认）完全不投放子句变体且请求数不变；level=2 主模板未命中才追加（有界）
//   3) 扩容 payload 合法性：含 {ORIG}、fillPayload 后无未替换占位符、主数组无重复模板
//   4) BooleanBlindDetector._lengthDiffer：content-length 差异超容差直接判「不同」，跳过 body 全扫
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOADS,
  CLAUSE_PAYLOADS,
  DBMS_LIST,
  fillPayload,
  getClauseTemplates,
  getClausePairs,
  buildClausePayloads,
  buildClausePairs,
} from '../src/engine/payloads.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';

const CLAUSE_KEYS = new Set(['where', 'orderby', 'groupby', 'having', 'limit']);
const MAIN5 = ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite'];

// ============ 1) CLAUSE_PAYLOADS 结构 ============

test('CLAUSE_PAYLOADS 覆盖五大库，clause 键合法（含 where 补充变体）', () => {
  for (const db of MAIN5) {
    assert.ok(CLAUSE_PAYLOADS[db], `缺少 ${db} 子句模板`);
    for (const clause of Object.keys(CLAUSE_PAYLOADS[db])) {
      assert.ok(CLAUSE_KEYS.has(clause), `${db} 出现未知 clause: ${clause}`);
    }
  }
  // 克隆库（与 PAYLOADS 克隆策略一致）
  assert.equal(CLAUSE_PAYLOADS.MariaDB, CLAUSE_PAYLOADS.MySQL);
  assert.equal(CLAUSE_PAYLOADS.TiDB, CLAUSE_PAYLOADS.MySQL);
  assert.equal(CLAUSE_PAYLOADS.DM8, CLAUSE_PAYLOADS.Oracle);
});

test('子句模板均含 {ORIG}；boolean 为 [真模板, 假模板] 对；每库每 clause 每技术 ≤3 条（有界）', () => {
  for (const db of MAIN5) {
    const allTpls = new Set();
    for (const [clause, techs] of Object.entries(CLAUSE_PAYLOADS[db])) {
      for (const [tech, list] of Object.entries(techs)) {
        assert.ok(Array.isArray(list) && list.length > 0, `${db}.${clause}.${tech} 应为非空数组`);
        assert.ok(list.length <= 3, `${db}.${clause}.${tech} 超出每 clause 每技术 3 条上界: ${list.length}`);
        for (const item of list) {
          if (tech === 'boolean') {
            assert.ok(Array.isArray(item) && item.length === 2, `${db}.${clause}.boolean 条目应为真假对`);
            const [t, f] = item;
            assert.ok(typeof t === 'string' && typeof f === 'string', `${db}.${clause}.boolean 对成员应为字符串`);
            assert.ok(t.includes('{ORIG}') && f.includes('{ORIG}'), `${db}.${clause}.boolean 对缺 {ORIG}`);
            assert.notEqual(t, f, `${db}.${clause}.boolean 真假模板不应相同`);
            assert.ok(!allTpls.has(t), `${db}.${clause} 真模板重复: ${t}`);
            assert.ok(!allTpls.has(f), `${db}.${clause} 假模板重复: ${f}`);
            allTpls.add(t);
            allTpls.add(f);
          } else {
            assert.ok(typeof item === 'string' && item.includes('{ORIG}'), `${db}.${clause}.${tech} 缺 {ORIG}: ${item}`);
            assert.ok(!allTpls.has(item), `${db}.${clause}.${tech} 模板重复: ${item}`);
            allTpls.add(item);
          }
        }
      }
    }
  }
});

// 深度扩容（对标 sqlmap boundary/clause 体系）让部分 ORDER BY 表达式模板同时存在于
// 主数组（深度轮直接迭代）与子句位置表（level>=2 门控），属有意复用的等价向量，允许重复。
const KNOWN_DEPTH_DUPLICATES = new Set([
  '{ORIG},(SELECT 1)-- -', // MySQL/PG orderby 真条件 —— 主数组深度扩容 + 子句表共存
  '{ORIG},(SELECT SLEEP({SLEEP}))-- -', // MySQL orderby 时间变体 —— 主数组 + 子句表共存
  '{ORIG},(SELECT pg_sleep({SLEEP}))-- -', // PG orderby 时间变体 —— 主数组 + 子句表共存
  '{ORIG} AND 1=1-- -', // Oracle/PG having 真条件 —— 主数组深度扩容（DELETE USING）+ having 子句表共存
  '{ORIG} AND 1=2-- -', // Oracle/PG having 假条件 —— 主数组深度扩容（DELETE USING）+ having 子句表共存
  '{ORIG} HAVING 1=1-- -', // MySQL groupby 真条件 —— 主 error 深度扩容（HAVING 报错载体）+ groupby 子句表共存
  '{ORIG}") AND 1=1-- -', // Oracle where 双引号闭合真条件 —— 主库深度扩容（boundary 闭合矩阵）+ where 子句表共存
  '{ORIG}") AND 1=2-- -', // Oracle where 双引号闭合假条件 —— 同上
]);

test('子句模板与主库模板无重复（同库内不投放等价向量；深度扩容有意共享除外）', () => {
  for (const db of MAIN5) {
    const main = new Set();
    for (const arr of Object.values(PAYLOADS[db])) for (const p of arr) main.add(p);
    for (const [clause, techs] of Object.entries(CLAUSE_PAYLOADS[db])) {
      for (const [tech, list] of Object.entries(techs)) {
        for (const item of list) {
          for (const tpl of tech === 'boolean' ? item : [item]) {
            assert.ok(!main.has(tpl) || KNOWN_DEPTH_DUPLICATES.has(tpl), `${db}.${clause}.${tech} 与主库重复: ${tpl}`);
          }
        }
      }
    }
  }
});

test('五大库均覆盖 ORDER BY / GROUP BY / HAVING 布尔变体；LIMIT 仅 MySQL/PG（MSSQL/Oracle 无 LIMIT 子句）', () => {
  for (const db of MAIN5) {
    assert.ok(Array.isArray(CLAUSE_PAYLOADS[db].orderby?.boolean), `${db} 缺 orderby boolean`);
    assert.ok(Array.isArray(CLAUSE_PAYLOADS[db].groupby?.boolean), `${db} 缺 groupby boolean`);
    assert.ok(Array.isArray(CLAUSE_PAYLOADS[db].having?.boolean), `${db} 缺 having boolean`);
  }
  assert.ok(CLAUSE_PAYLOADS.MySQL.limit.error.length > 0, 'MySQL LIMIT 应有 PROCEDURE ANALYSE 报错变体');
  assert.ok(CLAUSE_PAYLOADS.PostgreSQL.limit.boolean.length > 0, 'PG LIMIT 应有表达式布尔变体');
  assert.ok(!CLAUSE_PAYLOADS['SQL Server'].limit, 'MSSQL 不应有 limit 子句变体（用 TOP）');
  assert.ok(!CLAUSE_PAYLOADS.Oracle.limit, 'Oracle 不应有 limit 子句变体（用 ROWNUM）');
});

test('getClauseTemplates/getClausePairs 有界截断并保留 clause 元数据；fill 后无残留占位符', () => {
  // error：MySQL = orderby 2 + limit 2（maxPerClause=2/maxTotal=4 全量）
  const err = getClauseTemplates('MySQL', 'error', { maxPerClause: 2, maxTotal: 4 });
  assert.equal(err.length, 4);
  assert.ok(err.every((t) => CLAUSE_KEYS.has(t.clause) && typeof t.tpl === 'string'));
  // maxTotal 截断生效
  assert.ok(getClauseTemplates('MySQL', 'error', { maxTotal: 2 }).length === 2);
  // boolean 走 pairs（templates 通道不返回 boolean 对）
  assert.equal(getClauseTemplates('MySQL', 'boolean').length, 0);
  // pairs：截断至 maxTotal 且已填充
  const pairs = buildClausePairs('MySQL', { orig: '1' }, { maxTotal: 3 });
  assert.ok(pairs.length === 3);
  for (const p of pairs) {
    assert.ok(CLAUSE_KEYS.has(p.clause));
    assert.ok(p.truePayload.includes('1') && !p.truePayload.includes('{ORIG}'), 'truePayload 应已填充');
    assert.ok(!p.falsePayload.includes('{ORIG}'), 'falsePayload 应已填充');
  }
  // buildClausePayloads 填充 {SLEEP}
  const times = buildClausePayloads('MySQL', 'time', { orig: '1', sleep: 5 });
  assert.ok(times.length >= 1);
  assert.ok(times.every((t) => !t.payload.includes('{SLEEP}') && t.payload.includes('SLEEP(5)')));
  // 未知库返回空
  assert.equal(getClauseTemplates('DB2', 'error').length, 0);
  assert.equal(getClausePairs('DB2').length, 0);
});

// ============ 2) 扩容 payload 合法性（PAYLOADS 全库）============

test('PAYLOADS 总量 ≥700 且全库模板含 {ORIG}、主数组无重复', () => {
  let total = 0;
  for (const db of DBMS_LIST) {
    for (const [tech, arr] of Object.entries(PAYLOADS[db])) {
      const seen = new Set();
      for (const p of arr) {
        total++;
        assert.ok(typeof p === 'string' && p.includes('{ORIG}'), `${db}.${tech} 缺 {ORIG}: ${p}`);
        assert.ok(!seen.has(p), `${db}.${tech} 存在重复模板: ${p}`);
        seen.add(p);
      }
    }
  }
  assert.ok(total >= 700, `模板总量应 ≥700，实际 ${total}`);
});

test('fillPayload 后无未替换占位符（全库 + 子句模板）', () => {
  const vars = { orig: '1', sleep: 2, num: 7, sep: '# ' };
  const check = (tpl, where) => {
    const filled = fillPayload(tpl, vars);
    assert.ok(!/\{(?:ORIG|SLEEP|NUM|SEP|CALLBACK|MARKERS)\}/.test(filled), `${where} 填充后残留占位符: ${filled}`);
  };
  for (const db of DBMS_LIST) {
    for (const [tech, arr] of Object.entries(PAYLOADS[db])) arr.forEach((p) => check(p, `${db}.${tech}`));
  }
  for (const db of MAIN5) {
    for (const [clause, techs] of Object.entries(CLAUSE_PAYLOADS[db])) {
      for (const [tech, list] of Object.entries(techs)) {
        for (const item of list) {
          for (const tpl of tech === 'boolean' ? item : [item]) check(tpl, `${db}.${clause}.${tech}`);
        }
      }
    }
  }
});

test('五大库 boolean 主模板保持 ≥8 条（[6,7] 为 OR 变体，零回归约束；MySQL 深度扩容后 >8）', () => {
  for (const db of MAIN5) {
    assert.ok(PAYLOADS[db].boolean.length >= 8);
    assert.ok(PAYLOADS[db].boolean[6].includes("OR '1'='1"));
    assert.ok(PAYLOADS[db].boolean[7].includes("OR '1'='2"));
  }
});

test('时间模板延迟关键字约束（扩容后仍满足）：MySQL=SLEEP / PG=pg_sleep / MSSQL=WAITFOR / SQLite=sqlite_master|RANDOMBLOB', () => {
  const kw = { MySQL: 'SLEEP', PostgreSQL: 'pg_sleep', 'SQL Server': 'WAITFOR' };
  for (const [db, k] of Object.entries(kw)) {
    for (const p of PAYLOADS[db].time) {
      assert.ok(p.includes(k), `${db} time 缺 ${k}: ${p}`);
    }
  }
  // SQLite 无原生 SLEEP：sqlite_master 重查询 或 LIKE(HEX(RANDOMBLOB)) 重运算均为合法延迟向量
  for (const p of PAYLOADS.SQLite.time) {
    assert.ok(p.includes('sqlite_master') || p.includes('RANDOMBLOB') || p.includes('LIKE('), `SQLite time 缺延迟向量: ${p}`);
  }
});

// ============ 3) level 门控（level=1 零变化 / level=2 有界追加）============

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, timeThresholdMs: 800 },
    ...overrides,
  };
}

// 记录全部注入值的 mock（恒不命中：所有响应一致）
function makeCountingMock() {
  const calls = [];
  return {
    calls,
    async request(opts) {
      calls.push(extractInjected(opts));
      return { data: 'same', status: 200 };
    },
  };
}

test('BooleanBlindDetector：level=1（默认）不投放子句变体，请求数与历史一致', async () => {
  const mock = makeCountingMock();
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock));
  assert.equal(res.vulnerable, false);
  // legacy 路径：2 基线 + 3 对真假 AND + 1 对空基线兜底 OR（[P1-FIX 2026-09-10]）
  // 兜底对排最后，仅当 AND 对全部失败才轮到；关闭方式 config.booleanOrFallback=false
  assert.equal(mock.calls.length, 10);
  // 未配置 level（undefined）同样不投放
  const mock2 = makeCountingMock();
  await d.detect(buildCtx(mock2, { config: { timeoutMs: 5000, level: 1 } }));
  assert.equal(mock2.calls.length, 10);
  // 无任何子句位置变体标记
  const markers = [/HAVING 1=/, /,\(SELECT 1 UNION SELECT 2\)/, /,\(SELECT 1\)-- -/, /\) AND 1=1-- -/];
  for (const q of mock.calls) {
    for (const re of markers) assert.ok(!re.test(q), `level=1 不应投放子句变体: ${q}`);
  }
});

test('BooleanBlindDetector：level=2 主模板未命中时追加有界子句轮（2 基线 + ≤6 对真假）', async () => {
  const mock = makeCountingMock();
  const d = new BooleanBlindDetector();
  const res = await d.detect(buildCtx(mock, { config: { timeoutMs: 5000, level: 2 } }));
  assert.equal(res.vulnerable, false);
  const pairs = buildClausePairs('MySQL', { orig: '1' }, { maxTotal: 6 });
  // 主轮 10 = 2 基线 + 3 对 AND + 1 对空基线兜底 OR（[P1-FIX 2026-09-10]）
  const expected = 10 + 2 + pairs.length * 2;
  assert.equal(mock.calls.length, expected, `level=2 请求数应为 10 主轮 + 2 基线 + ${pairs.length}×2 子句对`);
  // 子句变体确实投放
  assert.ok(mock.calls.some((q) => q.includes(' HAVING 1=1-- -')), '应投放 groupby 变体');
  assert.ok(mock.calls.some((q) => q.includes(',(SELECT 1)-- -')), '应投放 orderby 变体');
});

test('BooleanBlindDetector：level=2 经子句轮检出 GROUP BY 位置注入点（evidence 标注 clause）', async () => {
  // 仅 HAVING 假条件改变响应（ORDER BY/GROUP BY 位置的注入语义），主模板轮全部无差异
  const havingOnly = {
    async request(opts) {
      const q = extractInjected(opts);
      if (q.includes('HAVING 1=2')) return { data: 'NO_RESULTS', status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const d = new BooleanBlindDetector();
  const low = await d.detect(buildCtx(havingOnly, { config: { timeoutMs: 5000, level: 1 } }));
  assert.equal(low.vulnerable, false, 'level=1 主模板轮应漏检（零回归：不投放子句变体）');
  const high = await d.detect(buildCtx(havingOnly, { config: { timeoutMs: 5000, level: 2 } }));
  assert.equal(high.vulnerable, true, 'level=2 子句轮应检出');
  assert.ok(high.evidence.includes('clause=groupby'), `evidence 应标注子句位置: ${high.evidence}`);
  assert.ok(high.payloads.some((p) => p.includes('HAVING 1=2')));
});

test('ErrorDetector：level=1 仅主模板轮（请求数 = 1 基线 + 主模板数，零回归）；level=2 追加子句报错变体', async () => {
  const run = async (config) => {
    const calls = [];
    const mock = {
      async request(opts) {
        calls.push(extractInjected(opts));
        return { data: 'all good', status: 200 };
      },
    };
    const res = await new ErrorDetector().detect(buildCtx(mock, { config }));
    return { res, calls };
  };
  const low = await run({ timeoutMs: 5000, level: 1 });
  assert.equal(low.res.vulnerable, false);
  assert.equal(low.calls.length, 1 + PAYLOADS.MySQL.error.length);
  // 主 error 数组现含 LIMIT PROCEDURE ANALYSE 变体（深度扩容），level=1 会合法投放它；
  // 子句门控区分改为 clause-only 签名 `PROCEDURE ANALYSE(1,1)`（仅 CLAUSE_PAYLOADS.limit.error 有）。
  assert.ok(!low.calls.some((q) => q.includes('PROCEDURE ANALYSE(1,1)')), 'level=1 不应投放子句专属 LIMIT 变体');

  const high = await run({ timeoutMs: 5000, level: 2 });
  assert.equal(high.res.vulnerable, false);
  const clauseErr = getClauseTemplates('MySQL', 'error', { maxPerClause: 2, maxTotal: 4 });
  assert.equal(high.calls.length, 1 + PAYLOADS.MySQL.error.length + clauseErr.length);
  assert.ok(high.calls.some((q) => q.includes('PROCEDURE ANALYSE(1,1)')), 'level=2 应投放 MySQL LIMIT 子句变体');
  assert.ok(high.calls.some((q) => q.includes(',(extractvalue(') || q.includes(',(updatexml(')), 'level=2 应投放 ORDER BY 变体');
});

test('TimeBlindDetector：level=2 未命中时追加扩展轮（主 time 变体 + ORDER BY 子句延迟）', async () => {
  const run = async (config) => {
    const calls = [];
    const mock = {
      async request(opts) {
        calls.push(extractInjected(opts));
        return { data: '', status: 200 };
      },
    };
    const res = await new TimeBlindDetector().detect(buildCtx(mock, { config }));
    return { res, calls };
  };
  const low = await run({ timeoutMs: 5000, timeThresholdMs: 800, level: 1 });
  assert.equal(low.res.vulnerable, false);
  // legacy：5 基线 + 5 注入（仅 templates[0]）
  assert.equal(low.calls.length, 10);

  const high = await run({ timeoutMs: 5000, timeThresholdMs: 800, level: 2 });
  assert.equal(high.res.vulnerable, false);
  const extraTpls =
    PAYLOADS.MySQL.time.slice(1, 3).length +
    getClauseTemplates('MySQL', 'time', { maxPerClause: 2, maxTotal: 2 }).length;
  assert.equal(high.calls.length, 10 + 3 + extraTpls * 3, '扩展轮 = 3 基线 + 每变体 3 采样');
  // 子句位置延迟变体已投放（ORDER BY 逗号拼接 SLEEP）
  assert.ok(high.calls.some((q) => q.includes(',(SELECT SLEEP(')), '应投放 ORDER BY 子句延迟变体');
});

// ============ 4) 布尔判定 content-length 短路 ============

test('_lengthDiffer：content-length 差异超容差判「不同」；容差内/缺头回落 false', () => {
  const d = new BooleanBlindDetector();
  const h = (n) => ({ headers: { 'content-length': String(n) } });
  // 超容差（容差 = max(24, 较小者 12%)）
  assert.equal(d._lengthDiffer(h(1000), h(1200)), true);
  assert.equal(d._lengthDiffer(h(1000), h(880)), true);
  assert.equal(d._lengthDiffer(h(1), h(100)), true);
  // 容差内
  assert.equal(d._lengthDiffer(h(1000), h(1010)), false);
  assert.equal(d._lengthDiffer(h(1000), h(1080)), false);
  // 缺头 / 非数值 / 数组头
  assert.equal(d._lengthDiffer({ status: 200 }, h(1000)), false);
  assert.equal(d._lengthDiffer(h(1000), { status: 200 }), false);
  assert.equal(d._lengthDiffer({ headers: {} }, { headers: {} }), false);
  assert.equal(d._lengthDiffer({ headers: { 'content-length': 'abc' } }, h(1000)), false);
  assert.equal(d._lengthDiffer({ headers: { 'content-length': ['1000'] } }, { headers: { 'content-length': ['1500'] } }), true);
  assert.equal(d._lengthDiffer({ headers: { 'Content-Length': '1000' } }, { headers: { 'Content-Length': '1200' } }), true);
});

test('content-length 短路：头差异超容差时跳过 _isMeaningfulDiff 全扫仍正确判定', async () => {
  const T = 'A'.repeat(10000);
  const F = 'B'.repeat(12000);
  const mkMock = (withHeaders) => ({
    async request(opts) {
      const q = extractInjected(opts);
      const isFalse = /1=2|'1'='2|"1"="2/.test(q);
      const body = isFalse ? F : T;
      return {
        data: body,
        status: 200,
        ...(withHeaders ? { headers: { 'content-length': String(body.length) } } : {}),
      };
    },
  });

  // 有 content-length 头：短路生效，_isMeaningfulDiff 不被调用
  const d1 = new BooleanBlindDetector();
  const origDiff = d1._isMeaningfulDiff.bind(d1);
  let scanCalls = 0;
  d1._isMeaningfulDiff = (a, b) => {
    scanCalls++;
    return origDiff(a, b);
  };
  const res1 = await d1.detect(buildCtx(mkMock(true)));
  assert.equal(res1.vulnerable, true);
  assert.equal(scanCalls, 0, 'content-length 差异超容差应跳过 body 全扫');

  // 无头（mock/老网关）：回落 body 比对，判定不变（零回归）
  const d2 = new BooleanBlindDetector();
  const origDiff2 = d2._isMeaningfulDiff.bind(d2);
  let scanCalls2 = 0;
  d2._isMeaningfulDiff = (a, b) => {
    scanCalls2++;
    return origDiff2(a, b);
  };
  const res2 = await d2.detect(buildCtx(mkMock(false)));
  assert.equal(res2.vulnerable, true);
  assert.ok(scanCalls2 >= 1, '无头时应回落 body 精细比对');
});
