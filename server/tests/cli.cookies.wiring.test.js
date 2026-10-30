// ============================================================================
// server/tests/cli.cookies.wiring.test.js —— cookie 文件会话（[D198]）的接线守卫
//
// 单元测试（cookieFile.test.js / liveCookies.test.js）验的是**模块语义**；本文件验的是
// 「这条能力从入口到引擎真的连上了」——本仓反复栽在「有能力没入口 / 有入口没消费方」：
//   · CLI：`--load-cookies` 落进 auth.cookie（含主机过滤与显式优先），`--live-cookies`
//     落进 config.liveCookiesFile，两个旗标**不带值时必须硬拒**（收参数不生效是红线）；
//   · REST：`liveCookiesFile` 既要在白名单里（把 config 交给引擎），又必须在
//     scanGuard/bespokeKeys 里过与 sessionFile **同一套路径白名单** —— 这个键让服务端
//     按调用方给的路径读文件并把内容当 cookie 发出，放开绝对路径＝任意文件读取原语；
//   · 引擎：包装必须在 scanClient 的装配链里、且**在 safeUrl 之前**（内层自发请求——
//     保活取页/CSRF 取页/登录提交——也要带上最新会话），并把 cookieParams 作为排除集传入
//     （否则 cookie 型注入的 payload 会被每请求重读顶回原值）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, buildAuth } from '../bin/cli/args.js';
import { buildConfig } from '../bin/cli/config.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel) => readFileSync(join(REPO, rel), 'utf8');

const tmp = mkdtempSync(join(tmpdir(), 'sqli-cookie-wiring-'));
process.on('exit', () => {
  try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
});
const writeTmp = (name, body) => {
  const p = join(tmp, name);
  writeFileSync(p, body, 'utf8');
  return p;
};

test('CLI-1) --load-cookies → auth.cookie：主机过滤 + 显式 --cookie 同名优先', () => {
  const file = writeTmp('ns.txt', [
    '.example.com\tTRUE\t/\tFALSE\t0\tsid\tFROMFILE',
    '.example.com\tTRUE\t/\tFALSE\t0\tscope\tS1',
    'other.test\tTRUE\t/\tFALSE\t0\tleak\tNO',
  ].join('\n'));
  const args = parseArgs(['-u', 'http://www.example.com/api/item?id=1', '--load-cookies', file, '--cookie', 'sid=EXPLICIT']);
  assert.equal(args.loadCookies, file);
  const auth = buildAuth(args);
  assert.match(auth.cookie, /sid=EXPLICIT/, '显式 --cookie 同名必须优先（显式优先是本仓既有纪律）');
  assert.match(auth.cookie, /scope=S1/, '文件里其余匹配条目必须补齐');
  assert.doesNotMatch(auth.cookie, /leak=NO/, 'cookie 是凭据：别的主机的条目不得带上');

  // 反向：只给文件（无 --cookie）时，文件值直接生效
  const only = buildAuth(parseArgs(['-u', 'https://www.example.com/x', '--load-cookies', file]));
  assert.match(only.cookie, /sid=FROMFILE/);
});

test('CLI-2) 两个旗标不带值/文件不存在必须硬拒（不得「收参数不生效」）', () => {
  const noVal = parseArgs(['-u', 'http://e.test/?id=1', '--load-cookies']);
  assert.equal(noVal.loadCookies, true);
  assert.throws(() => buildAuth(noVal), /需要一个 cookie 文件路径/);

  const missing = parseArgs(['-u', 'http://e.test/?id=1', '--load-cookies', join(tmp, 'nope.txt')]);
  assert.throws(() => buildAuth(missing), /读取失败/);

  const liveNoVal = parseArgs(['-u', 'http://e.test/?id=1', '--live-cookies']);
  assert.throws(() => buildConfig(liveNoVal), /需要一个 cookie 文件路径/);
  const liveMissing = parseArgs(['-u', 'http://e.test/?id=1', '--live-cookies', join(tmp, 'nope.txt')]);
  assert.throws(() => buildConfig(liveMissing), /文件不存在/);

  // 格式识别不了也必须拒绝启动（静默空 = 使用者以为加载成功）
  const junk = writeTmp('junk.txt', '这不是 cookie 也不是 JSON');
  assert.throws(() => buildAuth(parseArgs(['-u', 'http://e.test/?id=1', '--load-cookies', junk])), /格式无法识别/);
});

test('CLI-3) --live-cookies → config.liveCookiesFile（合法文件才放行）', () => {
  const file = writeTmp('live.txt', '.example.com\tTRUE\t/\tFALSE\t0\tsid\tV1');
  const cfg = buildConfig(parseArgs(['-u', 'http://www.example.com/x', '--live-cookies', file]));
  assert.equal(cfg.liveCookiesFile, file);
  // 默认关：不传旗标时不得凭空打开（否则等于给所有用户每请求读盘）
  const off = buildConfig(parseArgs(['-u', 'http://www.example.com/x']));
  assert.ok(!off.liveCookiesFile, `未传旗标时 config.liveCookiesFile 必须为空，实际 ${off.liveCookiesFile}`);
});

test('REST-1) liveCookiesFile 进白名单，且在 bespokeKeys 里过 sessionFile 同一套路径白名单', () => {
  const routes = read('server/src/api/scanRoutes.js');
  assert.match(routes, /'liveCookiesFile'/, 'KNOWN_CFG_KEYS 缺 liveCookiesFile ⇒ REST 传了会被静默丢弃');
  const bespoke = read('server/src/api/scanGuard/bespokeKeys.js');
  assert.match(bespoke, /liveCookiesFile/, 'bespokeKeys 未校验 liveCookiesFile 路径');
  assert.match(bespoke, /isSafeSessionPath/, 'liveCookiesFile 必须复用 sessionFile 的路径白名单（唯一真源）');
  // 白名单键与 defaults 顶层键的一致性由 configWhitelist.guard 兜底，这里只钉住「本键确实在 defaults」
  assert.match(read('server/src/config/defaults.js'), /liveCookiesFile:\s*null/);
});

test('引擎-1) 装配链：withLiveCookies 在 scanClient 里、且在 safeUrl 之前，并排除 cookieParams', () => {
  const src = read('server/src/engine/scan/scanClient.js');
  assert.match(src, /core\/liveCookies\.js/, 'scanClient 没有 import liveCookies ⇒ 旗标永远不生效');
  const iLive = src.indexOf('withLiveCookies(');
  const iSafe = src.indexOf('withSafeUrl(');
  assert.ok(iLive > 0, 'scanClient 里没有调用 withLiveCookies');
  assert.ok(iSafe > 0 && iLive < iSafe, 'live cookie 层必须在 safeUrl **之前**（内层自发请求也要带最新会话）');
  // [D205] 排除集必须是 **target.cookieParams**：cfg 是 `target.config`，`cookieParams` 在 target 上。
  // 旧断言钉的是 `cfg.cookieParams` —— 那个写法恒为 undefined ⇒ 排除清单永远为空，
  // 等于把「注入点 cookie 被 live 文件顶回原值」这个 bug 当成了契约。
  assert.match(src, /excludeNames:\s*Object\.keys\(\(target && target\.cookieParams\)/, '未把 cookieParams 作为排除集传入 ⇒ cookie 型注入会被顶回原值');
  // 回收面：与 scope/变换/续期同一处（防长驻进程 Map 泄漏）
  assert.match(read('server/src/engine/scan/lifecycle.js'), /releaseLiveCookies\(scanId\)/);
});

test('引擎-2) cookie 文件内容的键名与默认值只在一处定义（防两份口径漂移）', () => {
  const cookieFile = read('server/src/core/cookieFile.js');
  const live = read('server/src/core/liveCookies.js');
  assert.match(cookieFile, /export function parseCookieFile/);
  assert.match(live, /from '\.\/cookieFile\.js'/, 'liveCookies 必须复用 cookieFile 的解析（不要第二份解析器）');
  assert.doesNotMatch(live, /split\('\\t'\)/, 'liveCookies 里出现了第二份 Netscape 切分 ⇒ 两份口径必然漂移');
});
