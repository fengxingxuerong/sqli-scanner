// S11 sqlmapBridge.buildArgs 参数透传补齐单测：
//  - timeoutMs → --timeout <ms>（>0 且 ≤600000 生效，非法值忽略）
//  - retry → --retries <n>（>0 时透传，0/负/越界忽略）
//  - randomUA → --random-agent（true 才透传）
//  - prefix/suffix（ScanConfig 层）→ --prefix / --suffix（trim 非空才透传，长度 clamp ≤200）
//  - 既有参数（level/risk/techniques/proxy/threads 等）不受影响
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildArgs } from '../src/engine/sqlmapBridge.js';
import { setAuthEnabled, isAuthEnabled } from '../src/core/apiAuthState.js';

// 构造最小入参：sqlmap = config.sqlmap，extra 挂到 config 顶层（如 prefix/suffix）
const mkInput = (sqlmap = {}, extra = {}) => ({
  target: { url: 'http://target.local/app?id=1' },
  config: { sqlmap, ...extra },
});

// 取 url 之后的参数并剥离末尾固定追加的 --batch（buildArgs 尾部恒追加）
const tail = (sqlmap = {}, extra = {}) => {
  const a = buildArgs(mkInput(sqlmap, extra)).slice(2);
  assert.equal(a.pop(), '--batch');
  return a;
};

test('buildArgs: 目标 URL 缺失或非 http/https 时报错', () => {
  assert.throws(() => buildArgs({ target: {} }), /目标 URL/);
  assert.throws(() => buildArgs(mkInput({}, {}).target && { target: { url: 'ftp://x' } }), /目标 URL/);
});

test('buildArgs: timeoutMs 有效值透传为 --timeout <ms>，非法值忽略', () => {
  assert.deepEqual(tail({ timeoutMs: 30000 }), ['--timeout', '30000']);
  assert.deepEqual(tail({ timeoutMs: 1 }), ['--timeout', '1']);
  // 0 / 负 / NaN / 超上限（600000）→ 不生成 --timeout
  for (const bad of [0, -1, NaN, 600001, 'abc']) {
    const args = buildArgs(mkInput({ timeoutMs: bad }));
    assert.ok(!args.includes('--timeout'), `timeoutMs=${bad} 不应透传`);
  }
});

test('buildArgs: retry >0 透传为 --retries <n>，0/负/越界忽略', () => {
  assert.deepEqual(tail({ retry: 3 }), ['--retries', '3']);
  // 0 表示不重试 → 不生成
  for (const bad of [0, -2, NaN, 11]) {
    const args = buildArgs(mkInput({ retry: bad }));
    assert.ok(!args.includes('--retries'), `retry=${bad} 不应透传`);
  }
});

test('buildArgs: randomUA 为 true 才透传 --random-agent', () => {
  assert.deepEqual(tail({ randomUA: true }), ['--random-agent']);
  assert.ok(!buildArgs(mkInput({ randomUA: false })).includes('--random-agent'));
  assert.ok(!buildArgs(mkInput({})).includes('--random-agent'));
});

test('buildArgs: prefix/suffix 非空（trim 后）透传 --prefix / --suffix', () => {
  const args = tail({}, { prefix: "  '))  ", suffix: ' -- -  ' });
  assert.deepEqual(args, ['--prefix', "'))", '--suffix', '-- -']);
  // 空串 / 纯空白 / 缺失 → 不生成
  for (const empty of ['', '   ', undefined]) {
    const a = buildArgs(mkInput({}, { prefix: empty, suffix: empty }));
    assert.ok(!a.includes('--prefix'), `prefix=${empty} 不应透传`);
    assert.ok(!a.includes('--suffix'), `suffix=${empty} 不应透传`);
  }
});

test('buildArgs: prefix/suffix 超长（>200）时 clamp 到 200', () => {
  const long = `'${'a'.repeat(250)}'`;
  const args = buildArgs(mkInput({}, { prefix: long, suffix: long }));
  const prefixVal = args[args.indexOf('--prefix') + 1];
  const suffixVal = args[args.indexOf('--suffix') + 1];
  assert.equal(prefixVal.length, 200);
  assert.equal(suffixVal.length, 200);
});

test('buildArgs: 全部新参数与既有参数共存且映射正确', () => {
  const args = buildArgs(
    mkInput(
      { level: 3, risk: 2, techniques: ['B', 'U', 'T'], tamper: ['space2comment'], proxy: 'http://127.0.0.1:8080', threads: 4, timeoutMs: 30000, retry: 2, randomUA: true },
      { prefix: "')", suffix: '-- -' }
    )
  );
  // 既有参数不受影响
  assert.ok(args.includes('--level') && args[args.indexOf('--level') + 1] === '3');
  assert.ok(args.includes('--risk') && args[args.indexOf('--risk') + 1] === '2');
  assert.ok(args.includes('--technique') && args[args.indexOf('--technique') + 1] === 'BUT');
  assert.ok(args.includes('--tamper'));
  assert.ok(args.includes('--proxy'));
  assert.ok(args.includes('--threads') && args[args.indexOf('--threads') + 1] === '4');
  // 新参数
  assert.ok(args.includes('--timeout') && args[args.indexOf('--timeout') + 1] === '30000');
  assert.ok(args.includes('--retries') && args[args.indexOf('--retries') + 1] === '2');
  assert.ok(args.includes('--random-agent'));
  assert.ok(args.includes('--prefix') && args[args.indexOf('--prefix') + 1] === "')");
  assert.ok(args.includes('--suffix') && args[args.indexOf('--suffix') + 1] === '-- -');
  // 数组形式参数（禁用 shell 拼接），每对参数位置正确
  assert.equal(args[0], '-u');
});

test('buildArgs: technique 白名单含 A（sqlmap AND/OR 变体）', () => {
  const args = buildArgs(
    mkInput({ level: 1, risk: 1, techniques: ['A', 'B', 'U'] })
  );
  assert.equal(args[args.indexOf('--technique') + 1], 'ABU');
});

test('buildArgs: technique 含非法字母被过滤', () => {
  const args = buildArgs(
    mkInput({ level: 1, risk: 1, techniques: ['B', 'X', 'U', '9'] })
  );
  assert.equal(args[args.indexOf('--technique') + 1], 'BU');
});

test('buildArgs: flushSession / freshQueries / unionCols 透传', () => {
  const args = buildArgs(
    mkInput({ level: 1, risk: 1, flushSession: true, freshQueries: true, unionCols: '1-15' })
  );
  assert.ok(args.includes('--flush-session'), 'flush-session 应透传');
  assert.ok(args.includes('--fresh-queries'), 'fresh-queries 应透传');
  assert.ok(args.includes('--union-cols') && args[args.indexOf('--union-cols') + 1] === '1-15', 'union-cols 应透传');
});

test('buildArgs: unionCols 格式非法被拒绝（不透传）', () => {
  for (const bad of ['', 'abc', '999-', '0-9999', '1;2']) {
    const args = buildArgs(mkInput({ level: 1, risk: 1, unionCols: bad }));
    assert.ok(!args.includes('--union-cols'), `unionCols="${bad}" 不应透传`);
  }
});

test('buildArgs: flushSession/freshQueries 假值不透传（默认关闭）', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1 }));
  assert.ok(!args.includes('--flush-session'));
  assert.ok(!args.includes('--fresh-queries'));
});

test('buildArgs: 新增对标参数 timeSec / ignoreCode / excludeSysdbs / verbose 透传', () => {
  const args = buildArgs(
    mkInput({
      level: 1, risk: 1,
      timeSec: 2,
      ignoreCode: 403,
      excludeSysdbs: true,
      verbose: 3,
    })
  );
  assert.ok(args.includes('--time-sec') && args[args.indexOf('--time-sec') + 1] === '2', 'time-sec 应透传');
  assert.ok(args.includes('--ignore-code') && args[args.indexOf('--ignore-code') + 1] === '403', 'ignore-code 应透传');
  assert.ok(args.includes('--exclude-sysdbs'), 'exclude-sysdbs=true 应透传');
  assert.ok(args.includes('-v') && args[args.indexOf('-v') + 1] === '3', '-v 应透传');
});

test('buildArgs: 新增参数边界校验（越界/非法忽略，默认不追加）', () => {
  // 默认（未设置）→ 不追加新增参数（excludeSysdbs 未显式 true 不加，对齐 sqlmap CLI opt-in）
  const base = buildArgs(mkInput({ level: 1, risk: 1 }));
  for (const flag of ['--time-sec', '--ignore-code', '--exclude-sysdbs', '-v']) {
    assert.ok(!base.includes(flag), `${flag} 默认不追加`);
  }
  // 非法值忽略
  for (const bad of [0, -5, 999, 'abc']) {
    const args = buildArgs(mkInput({ level: 1, risk: 1, timeSec: bad, ignoreCode: bad, verbose: bad }));
    assert.ok(!args.includes('--time-sec'), `timeSec=${bad} 不应透传`);
    assert.ok(!args.includes('--ignore-code'), `ignoreCode=${bad} 不应透传`);
  }
  assert.ok(!buildArgs(mkInput({ level: 1, risk: 1, excludeSysdbs: false })).includes('--exclude-sysdbs'), 'excludeSysdbs=false 不透传');
});

// ── unionChar 透传 ──────────────────────────────────────────────────────────
test('buildArgs: unionChar 合法单字符透传为 --union-char', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1, unionChar: 'a' }));
  assert.ok(args.includes('--union-char') && args[args.indexOf('--union-char') + 1] === 'a', '字母 a 透传');
  const args2 = buildArgs(mkInput({ level: 1, risk: 1, unionChar: '1' }));
  assert.ok(args2.includes('--union-char') && args2[args2.indexOf('--union-char') + 1] === '1', '数字 1 透传');
  const args3 = buildArgs(mkInput({ level: 1, risk: 1, unionChar: 'Z' }));
  assert.ok(args3.includes('--union-char') && args3[args3.indexOf('--union-char') + 1] === 'Z', '大写字母 Z 透传');
});

test('buildArgs: unionChar 非法值/空值不透传', () => {
  for (const bad of ['', 'ab', '??', ' ', null, undefined]) {
    const args = buildArgs(mkInput({ level: 1, risk: 1, unionChar: bad }));
    assert.ok(!args.includes('--union-char'), `unionChar="${bad}" 不应透传`);
  }
});

// ── unionFrom 透传 ──────────────────────────────────────────────────────────
test('buildArgs: unionFrom 合法表名透传为 --union-from', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1, unionFrom: 'information_schema.tables' }));
  assert.ok(args.includes('--union-from') && args[args.indexOf('--union-from') + 1] === 'information_schema.tables', 'information_schema.tables 透传');
  const args2 = buildArgs(mkInput({ level: 1, risk: 1, unionFrom: 'dual' }));
  assert.ok(args2.includes('--union-from') && args2[args2.indexOf('--union-from') + 1] === 'dual', 'dual 透传');
});

test('buildArgs: unionFrom 非法表名不透传', () => {
  for (const bad of ['', '123abc', 'a b', 'a-b', null, undefined]) {
    const args = buildArgs(mkInput({ level: 1, risk: 1, unionFrom: bad }));
    assert.ok(!args.includes('--union-from'), `unionFrom="${bad}" 不应透传`);
  }
});

test('buildArgs: unionFrom 超长 clamp 到 128 字符', () => {
  const long = 'a_' + 'b'.repeat(200) + '.c';
  const args = buildArgs(mkInput({ level: 1, risk: 1, unionFrom: long }));
  assert.ok(args.includes('--union-from'), 'unionFrom 应透传');
  const val = args[args.indexOf('--union-from') + 1];
  assert.ok(val.length <= 128, `unionFrom 被 clamp 到 128 字符（实际 ${val.length}）`);
});

// ── smart 透传 ──────────────────────────────────────────────────────────────
test('buildArgs: smart=true 透传 --smart', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1, smart: true }));
  assert.ok(args.includes('--smart'), 'smart=true 透传 --smart');
});

test('buildArgs: smart=false/undefined 不透传 --smart', () => {
  assert.ok(!buildArgs(mkInput({ level: 1, risk: 1, smart: false })).includes('--smart'), 'smart=false 不透传');
  assert.ok(!buildArgs(mkInput({ level: 1, risk: 1 })).includes('--smart'), 'smart 缺省不透传');
});

// ── v24 sqlmap 对标：补齐缺失 CLI 参数透传 ─────────────────────────────────
test('buildArgs: 请求形态类布尔参数透传（mobile/parseErrors/identifyWaf/skipUrlencode/skipStatic/keepAlive/nullConnection/predictOutput）', () => {
  const flags = {
    mobile: '--mobile',
    parseErrors: '--parse-errors',
    identifyWaf: '--identify-waf',
    skipUrlencode: '--skip-urlencode',
    skipStatic: '--skip-static',
    keepAlive: '--keep-alive',
    nullConnection: '--null-connection',
    predictOutput: '--predict-output',
  };
  for (const [key, flag] of Object.entries(flags)) {
    assert.deepEqual(tail({ [key]: true }), [flag], `${key}=true 应透传 ${flag}`);
    assert.ok(!buildArgs(mkInput({ [key]: false })).includes(flag), `${key}=false 不透传 ${flag}`);
  }
  assert.ok(!buildArgs(mkInput({})).includes('--mobile'), '缺省不透传');
});

test('buildArgs: delay 有效值透传 --delay，非法值忽略', () => {
  assert.deepEqual(tail({ delay: 1.5 }), ['--delay', '1.5']);
  for (const bad of [0, -1, NaN, 31, 'abc']) {
    assert.ok(!buildArgs(mkInput({ delay: bad })).includes('--delay'), `delay=${bad} 不应透传`);
  }
});

test('buildArgs: safeUrl/safeFreq 透传（safeUrl 必须 http/https，safeFreq 1-100）', () => {
  assert.deepEqual(
    tail({ safeUrl: 'http://target.local/health', safeFreq: 5 }),
    ['--safe-url', 'http://target.local/health', '--safe-freq', '5']
  );
  // 非法 safeUrl（非 http/https）不透传
  assert.ok(!buildArgs(mkInput({ safeUrl: 'ftp://x' })).includes('--safe-url'));
  // 非法 safeFreq（0 / 101）不透传
  for (const bad of [0, -1, 101, NaN]) {
    assert.ok(!buildArgs(mkInput({ safeFreq: bad })).includes('--safe-freq'), `safeFreq=${bad} 不应透传`);
  }
});

test('buildArgs: csrfUrl/csrfToken 透传（csrfUrl 必须 http/https，csrfToken clamp 256）', () => {
  assert.deepEqual(
    tail({ csrfUrl: 'http://target.local/login', csrfToken: 'csrftoken' }),
    ['--csrf-url', 'http://target.local/login', '--csrf-token', 'csrftoken']
  );
  assert.ok(!buildArgs(mkInput({ csrfUrl: 'javascript:alert(1)' })).includes('--csrf-url'));
  const longToken = 't'.repeat(300);
  const args = buildArgs(mkInput({ csrfToken: longToken }));
  const val = args[args.indexOf('--csrf-token') + 1];
  assert.ok(val.length <= 256, `csrfToken clamp 到 256（实际 ${val.length}）`);
});

test('buildArgs: 只读枚举参数透传（currentUser/currentDb/hostname/isDba）', () => {
  const flags = {
    currentUser: '--current-user',
    currentDb: '--current-db',
    hostname: '--hostname',
    isDba: '--is-dba',
  };
  for (const [key, flag] of Object.entries(flags)) {
    assert.ok(buildArgs(mkInput({ [key]: true })).includes(flag), `${key}=true 应透传 ${flag}`);
    assert.ok(!buildArgs(mkInput({})).includes(flag), `${key} 缺省不透传 ${flag}`);
  }
});

test('buildArgs: evalCode 走破坏性 opt-in 通道（门控通过后透传 --eval 且 clamp 4096）', () => {
  // [A4 2026-09-18] --eval 现为**双条件门控**：SQLMAP_ALLOW_EVAL=1 且引擎已启用鉴权。
  // 旧断言「默认就透传」正是被修掉的行为，这里改为在门控满足的前提下验证透传与 clamp。
  const savedEnv = process.env.SQLMAP_ALLOW_EVAL;
  const savedAuth = isAuthEnabled();
  process.env.SQLMAP_ALLOW_EVAL = '1';
  setAuthEnabled(true);
  try {
    const args = buildArgs(mkInput({ evalCode: "import hashlib; pwd='x'" }));
    assert.ok(args.includes('--eval'), '门控通过时 evalCode 应透传 --eval');
    const val = args[args.indexOf('--eval') + 1];
    assert.ok(val.length <= 4096);
    assert.ok(!buildArgs(mkInput({})).includes('--eval'), 'evalCode 缺省不透传');
  } finally {
    if (savedEnv === undefined) delete process.env.SQLMAP_ALLOW_EVAL;
    else process.env.SQLMAP_ALLOW_EVAL = savedEnv;
    setAuthEnabled(savedAuth);
  }
});

// ── noCast / hex / noEscape 透传 ─────────────────────────────────────────────
test('buildArgs: noCast/hex/noEscape 透传为 --no-cast / --hex / --no-escape', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1, noCast: true, hex: true, noEscape: true }));
  assert.ok(args.includes('--no-cast'), 'no-cast 应透传');
  assert.ok(args.includes('--hex'), 'hex 应透传');
  assert.ok(args.includes('--no-escape'), 'no-escape 应透传');
});

test('buildArgs: noCast/hex/noEscape 默认关闭（不透传）', () => {
  const args = buildArgs(mkInput({ level: 1, risk: 1 }));
  assert.ok(!args.includes('--no-cast'), 'no-cast 默认不透传');
  assert.ok(!args.includes('--hex'), 'hex 默认不透传');
  assert.ok(!args.includes('--no-escape'), 'no-escape 默认不透传');
  const args2 = buildArgs(mkInput({ level: 1, risk: 1, noCast: false, hex: false, noEscape: false }));
  assert.ok(!args2.includes('--no-cast'), 'no-cast=false 不透传');
  assert.ok(!args2.includes('--hex'), 'hex=false 不透传');
  assert.ok(!args2.includes('--no-escape'), 'no-escape=false 不透传');
});
