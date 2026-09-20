// ============================================================================
// configReachability.guard.test.js —— 「CLI 能设、引擎真读、REST 收不到」守卫
// ============================================================================
// 为什么单独有这支测试（而不是继续靠 configWhitelist.guard.test.js）：
// 那支守卫的正向真值来源是 **defaults.js 顶层键**，于是有一条结构性漏检——
// 一个键可以完全不在 defaults.js 里，却同时被 CLI 写进 config、被引擎读走。
// testPath / testHeaders / unionCols / paramDel / dumpWhere / noCast / flushSession
// 就是这么漏过去的：REST 传了 → sanitizeStart 白名单滤掉 → 只在 logger.debug 留一行
// → 调用方拿到 200 + scanId，跑完得到一句「未检出」。
// 这不是崩溃型 bug，是**静默假阴性**，而假阴性对扫描器是最贵的一类错。
//
// 本仓已有 6 处注释写着「此前不在白名单被静默丢弃」——每次都是人工发现一个补一个。
// 这支测试把那件事机械化：以后再加 CLI 可设键忘了同步，当场红。
//
// 判据取「两端交叉」而不是单端 grep，是为了把误报压到能长期挂着不豁免：
//   CLI 侧 `config.X =`（证明这是用户可配键，不是内部字段）
//   ∩ 引擎侧 `config.X` / `ctx.config?.X` / `target.config.X`（证明真被消费）
//   − KNOWN_CFG_KEYS（REST 可达）
//   − 下方 CLI_ONLY_KEYS（有意的 CLI 专属，须写理由）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const HERE = fileURLToPath(import.meta.url);
const SERVER = path.resolve(HERE, '..', '..'); // .../server

const read = (rel) => readFileSync(path.join(SERVER, rel), 'utf8');

const walkJs = (dir, out = []) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkJs(p, out);
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
};

/** 从源码里的 `new Set([...])` 字面量抓字符串成员（与既有守卫同口径） */
const setMembers = (src, varName) => {
  const m = src.match(new RegExp(`const ${varName} = new Set\\(\\[([\\s\\S]*?)\\]\\)`));
  assert.ok(m, `应能在 scanRoutes.js 里定位 ${varName}`);
  return new Set(Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1]));
};

const ROUTES_SRC = read('src/api/scanRoutes.js');
const KNOWN = setMembers(ROUTES_SRC, 'KNOWN_CFG_KEYS');
const BACKFILL = setMembers(ROUTES_SRC, 'BACKFILL_SCALAR_KEYS');

// 有意的 CLI 专属键：REST 不该收到，必须写理由，否则等于把守卫又开回空转。
// 这一条豁免清单是「引擎侧读取点逐个 grep 验证过为 0」之后才留下的——
// 我最初在这里顺手写了 unionFrom，理由是"大概由别处覆盖"，实测它被
// blindExtractor/DBFingerprinter/Extractor/injection **四处**读取，属于真缺口，已移除豁免。
const CLI_ONLY_KEYS = new Map([
  ['destructiveSuppressed', 'server/src 内 0 个读取点：CLI 报表期状态位，不进引擎配置'],
  ['randomUA', '顶层 config.randomUA 在 server/src 内 0 个读取点；活路径是 wafEvasion.randomUA'
    + '（sanitizeStart 从 we 上取）。CLI 的 --random-agent 同时写了这两个，顶层那个是空转冗余，'
    + '已记入 TODO 待清（不是 REST 缺口，所以此处豁免）'],
]);

const cliWritten = new Set();
for (const f of walkJs(path.join(SERVER, 'bin', 'cli'))) {
  for (const m of readFileSync(f, 'utf8').matchAll(/\bconfig\.([A-Za-z_][A-Za-z0-9_]*)\s*=/g)) {
    cliWritten.add(m[1]);
  }
}

const engineRead = new Set();
for (const dir of ['src/engine', 'src/core']) {
  for (const f of walkJs(path.join(SERVER, dir))) {
    const t = readFileSync(f, 'utf8');
    // config.X / ctx.config?.X / target.config.X —— 可选链与属性访问一起覆盖
    for (const m of t.matchAll(/\bconfig\??\.([A-Za-z_][A-Za-z0-9_]*)/g)) engineRead.add(m[1]);
  }
}

test('守卫前提：判据本身要有信号（CLI 写入集与引擎读取集都不能为空）', () => {
  // 抓空集会让下面所有断言静默全绿——那是比红更糟的结果，所以先自证。
  assert.ok(cliWritten.size >= 30, `CLI 写入键只抓到 ${cliWritten.size} 个，正则或目录假设已失效`);
  assert.ok(engineRead.size >= 40, `引擎读取键只抓到 ${engineRead.size} 个，正则或目录假设已失效`);
  assert.ok(cliWritten.has('testPath'), 'CLI 侧应能抓到 testPath（config.js 明确写它）');
  assert.ok(engineRead.has('unionCols'), '引擎侧应能抓到 unionCols（UnionDetector 读它）');
  assert.ok(KNOWN.size >= 50, `KNOWN_CFG_KEYS 解析出 ${KNOWN.size} 条，解析失败？`);
});

test('守卫：CLI 可设 ∧ 引擎真读的键必须进 REST 白名单（防静默假阴性）', () => {
  const missing = [...cliWritten]
    .filter((k) => engineRead.has(k))
    .filter((k) => !KNOWN.has(k))
    .filter((k) => !CLI_ONLY_KEYS.has(k))
    .sort();
  assert.deepEqual(
    missing,
    [],
    `以下键 CLI 能设、引擎真读，但 REST 传了会被静默丢弃：${missing.join(', ')}\n` +
    `→ 加进 scanRoutes.js 的 KNOWN_CFG_KEYS（并确认 BACKFILL_SCALAR_KEYS 或有 bespoke 分支），` +
    `或在本测试的 CLI_ONLY_KEYS 里注明「为什么 REST 不该收到」。`
  );
});

// ── 真调 sanitizeStart 的端到端契约（不靠读源码猜行为）──
const START_URL = 'http://127.0.0.1:8273/products/list.php?id=1';
const cfgOf = (config) => sanitizeStart({ url: START_URL, config }).config;

test('契约：9 个曾经不可达的键，现在真能落到引擎收到的 config 上', () => {
  const cases = [
    ['testPath', true],
    ['testHeaders', true],
    ['noCast', true],
    ['flushSession', true],
    ['hex', true],
    ['unionFrom', 'dual'],
    ['dumpWhere', 'id>1'],
    ['unionCols', '3'],
    ['paramDel', ';'],
  ];
  for (const [k, v] of cases) {
    const out = cfgOf({ [k]: v });
    assert.ok(k in out, `${k} 传了 ${JSON.stringify(v)} 却没进 config —— 白名单/透传断了一环`);
    assert.equal(out[k], v, `${k} 透传后值变形：期望 ${JSON.stringify(v)}，实际 ${JSON.stringify(out[k])}`);
  }
});

test('契约：非法值必须被丢掉而不是带病进引擎（unionCols 会被 Number() 用、paramDel 会进 URL）', () => {
  // unionCols：引擎 Number(cfg.unionCols) 当固定列数用，NaN / 超宽都会坏事
  for (const bad of ['abc', '0', '-5', '99999', '3.5', '']) {
    assert.ok(!('unionCols' in cfgOf({ unionCols: bad })), `unionCols=${JSON.stringify(bad)} 不该被接受`);
  }
  assert.equal(cfgOf({ unionCols: 3 }).unionCols, '3', '数字入参应归一成字符串（与 CLI 口径一致）');
  assert.equal(cfgOf({ unionCols: ' 12 ' }).unionCols, '12', '两侧空白应被 trim');

  // paramDel：单字符 + 窄白名单。这几个会改写 URL 结构，历史上 CLI 只截长度不校验形态
  for (const bad of ['#', '?', '/', '&', '=', '&&', ' ', '\n', '\t', '%%', '+', 'ab']) {
    assert.ok(!('paramDel' in cfgOf({ paramDel: bad })), `paramDel=${JSON.stringify(bad)} 不该被接受`);
  }
  for (const okc of [';', '|', '^', ',', '~']) {
    assert.equal(cfgOf({ paramDel: okc }).paramDel, okc, `paramDel=${okc} 应被接受`);
  }

  // dumpWhere：原样拼进提取 SQL 的 WHERE 位，分号=堆叠查询那一步；空串按「不配置」
  assert.ok(!('dumpWhere' in cfgOf({ dumpWhere: 'id>1; DROP TABLE x' })), 'dumpWhere 带分号不该被接受');
  assert.ok(!('dumpWhere' in cfgOf({ dumpWhere: '   ' })), '全空白 dumpWhere 不该被接受');
  assert.equal(cfgOf({ dumpWhere: ' id>1 ' }).dumpWhere, 'id>1', 'dumpWhere 应 trim');
  assert.equal(cfgOf({ dumpWhere: 'a'.repeat(3000) }).dumpWhere.length, 2000, 'dumpWhere 应截到 2000');

  // hex / flushSession 必须是真布尔：引擎按 `config.hex === true` 判定（Extractor.js:618,697），
  // 收下单纯 1 会得到「API 成功、引擎不生效」——那是本批要消灭的同一个 bug 形状。
  for (const k of ['hex', 'flushSession']) {
    for (const bad of [1, 0, 'true', '', {}, []]) {
      assert.ok(!(k in cfgOf({ [k]: bad })), `${k}=${JSON.stringify(bad)} 不该被接受（引擎按严格 true 判定）`);
    }
    assert.equal(cfgOf({ [k]: true })[k], true, `${k}: true 应透传`);
    assert.equal(cfgOf({ [k]: false })[k], false, `${k}: false 应作为显式关闭透传`);
  }
});

test('契约：未知键仍然忽略（不能因为改成 warn 就变成接受）', () => {
  const out = cfgOf({ definitelyNotARealOption: true, testPath: true });
  assert.ok(!('definitelyNotARealOption' in out));
  assert.equal(out.testPath, true, '同一请求里的合法键不能被未知键带崩');
});

test('一致性：BACKFILL 里的键必须都在白名单内（否则透传是死代码）', () => {
  const orphans = [...BACKFILL].filter((k) => !KNOWN.has(k)).sort();
  assert.deepEqual(
    orphans,
    [],
    `这些键在 BACKFILL_SCALAR_KEYS 里却不在 KNOWN_CFG_KEYS，会在更早一步被当未知字段忽略：${orphans.join(', ')}`
  );
});
