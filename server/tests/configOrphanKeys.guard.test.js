// ============================================================================
// tests/configOrphanKeys.guard.test.js —— 「引擎真读、任何入口都设不了」的机器判据
// ============================================================================
// 为什么必须有：本仓这类缺陷已经吃过六批（P1 白名单漂移 / CFG-REACH 九键 / E2 extractScope /
// P0-REACH secondUrl / 2026-09-24 的 http2+disableKeepAlive+xpAutoEnable+noSql.concurrency
// 与这批八键），**每一批都是人肉交叉比对抓出来的**，而既有的
// configReachability.guard.test.js 只交叉「CLI 能写的键 ∩ 引擎读的键」——
// 于是**没有 CLI 旋钮的键天然不在它的分母里**（http2 就是这么漏的：它的注释甚至写着
// "已补白名单+透传"，而白名单里根本没有）。
//
// 本守卫把判据换成不依赖 CLI 的版本：
//   可达 = KNOWN_CFG_KEYS ∪ defaults ∪ CLI 写入 ∪ 前端声明 ∪ 同文件内部字段
//   孤儿 = 引擎读取点里所有不在"可达"里的键
//   断言 = 孤儿集合**逐个实名豁免 + 写理由**；出现新孤儿即红；豁免项不再是孤儿也即红
//        （与 README/契约测试里 KNOWN_MISSING_UI_KEYS 同一套防腐烂口径）。
//
// 「同文件内部字段」这条是刻意窄的：`model` / `role` / `apiKey` 属于 ReportAI 自己的配置对象，
// `windowSize` 等 7 个属于 scanValidityGuard 的常量组（现已经 config.scanValidity 可达），
// 它们在**读取点所在文件里就有写入者**，不是用户旋钮。跨文件的内部字段（onlyPoint）
// 必须走显式豁免，好让每次新增都有人写一句为什么。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';

const SERVER = fileURLToPath(new URL('..', import.meta.url));
const ROOT = fileURLToPath(new URL('../..', import.meta.url));

const jsFiles = [];
const walk = (dir) => {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith('.js')) jsFiles.push(p);
  }
};
walk(join(SERVER, 'src'));

const readSource = (f) => readFileSync(f, 'utf8');

// ── 入口侧：四个能"写进 config"的地方各算一份键集 ──────────────────────────
const routesSrc = readSource(join(SERVER, 'src/api/scanRoutes.js'));
const WL_BLOCK = routesSrc.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/);
assert.ok(WL_BLOCK, '定位不到 KNOWN_CFG_KEYS，本守卫会退化成空判据');
const WHITELIST = new Set(Array.from(WL_BLOCK[1].matchAll(/'([^']+)'/g)).map((x) => x[1]));

const { defaults } = await import(pathToFileURL(join(SERVER, 'src/config/defaults.js')).href);

const cliSrc = ['bin/cli/config.js', 'bin/cli.js', 'bin/cli/args.js']
  .map((f) => readSource(join(SERVER, f))).join('\n');
const cliWritten = new Set(Array.from(cliSrc.matchAll(/\bconfig\.([A-Za-z_][A-Za-z0-9_]*)\s*=[^=]/g)).map((m) => m[1]));

const feSrc = ['src/shared/constants.ts', 'src/shared/scanConfig.ts', 'src/components/ScanConfigPanel.tsx']
  .map((f) => { try { return readSource(join(ROOT, f)); } catch { return ''; } }).join('\n');
const feWritten = new Set([
  ...Array.from(feSrc.matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)(\??):\s/gm)).map((m) => m[1]),
  ...Array.from(feSrc.matchAll(/'([A-Za-z_][A-Za-z0-9_]*)'/g)).map((m) => m[1]),
]);

// ── 读取侧：引擎/核心里所有 `config.X` / `cfg.X` / `ctx.config?.X` 形态 ──────
// 先把**字符串字面量**抠掉再匹配：给使用者的建议文案里写着
// 「重新登录并携带有效 Cookie（config.cookie 或 requestFile 原始包）」，
// 那是一条**给人看的说明**，不是读取点 —— 不抠掉的话本守卫会把它当成孤儿键，
// 而"为了让守卫变绿去改文案"是最糟糕的修法（模板串里的 ${config.X} 插值必须保留，
// 它是真读取点）。
const READ_RE = /\b(?:config|cfg|scanConfig|target\.config|ctx\.config)\??\.([A-Za-z_][A-Za-z0-9_]*)\b/g;
const stripLiterals = (line) =>
  line
    .replace(/'[^']*'/g, "''")
    .replace(/"[^"]*"/g, '""')
    .replace(/`[^`]*`/g, (m) => (m.match(/\$\{[^}]*\}/g) || []).join(' '));
const reads = new Map(); // key -> [{file, line}]
for (const f of jsFiles) {
  const rel = relative(SERVER, f).replace(/\\/g, '/');
  if (rel === 'src/api/scanRoutes.js' || rel === 'src/config/defaults.js') continue; // 入口与默认值本体
  readSource(f).split(/\r?\n/).forEach((line, i) => {
    if (/^\s*(\/\/|\*|\/\*)/.test(line)) return; // 注释里的"读取"不算
    for (const m of stripLiterals(line).matchAll(READ_RE)) {
      if (!reads.has(m[1])) reads.set(m[1], []);
      reads.get(m[1]).push({ file: rel, line: i + 1 });
    }
  });
}

// 同文件内既有读取点又有写入者 ⇒ 内部字段（不是用户旋钮）
const writesByFile = new Map(); // `${file}#${key}` -> true
for (const f of jsFiles) {
  const rel = relative(SERVER, f).replace(/\\/g, '/');
  const src = readSource(f);
  for (const m of src.matchAll(/\bconfig\.([A-Za-z_][A-Za-z0-9_]*)\s*=[^=]/g)) writesByFile.set(`${rel}#${m[1]}`, true);
  for (const m of src.matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)(\??):\s/gm)) writesByFile.set(`${rel}#${m[1]}`, true);
  for (const m of src.matchAll(/[,{\s]([A-Za-z_][A-Za-z0-9_]*)(\??):\s/gm)) writesByFile.set(`${rel}#${m[1]}`, true);
}

// ── 显式豁免（每条必须有理由；不再成立时必须删掉，否则本文件红） ─────────────
// 注：ReportAI 的 apiKey/model/role/keyIdx 与复测路由的 onlyPoint、tamper 的 _postpon
// 都**不需要**列在这里 —— 它们在读取点所在文件里就有写入者，属于"同文件内部字段"，
// 由上面的规则自动排除。豁免清单只留真正跨文件、且刻意不经 REST 的东西。
const EXEMPT = {
  // 直连模式（-d）：sanitizeStart 的直连分支原样带底透传 config，不过白名单，
  // 所以这个键在直连模式下**可达**；HTTP 模式没有直连查询概念，不进白名单是刻意的。
  queryTimeout: '仅直连模式消费；该模式 config 不经白名单（scanRoutes 直连分支），已可达',
  // OOB 接收端**自己那份** options（由 ScanManager 从 config.oob 组里挑字段构造），
  // 不是顶层扫描 config —— config.oob.dnsPort / dnsDomain 的可达性由
  // configWhitelist.passthrough.test.js 的嵌套组守卫钉（那边的分母是 defaults.oob）。
  dnsPort: 'oobReceiver 自有 options（源自 config.oob 组，组内键由嵌套组守卫覆盖）',
  // sqlmap 互操作层的子配置组：外部执行文件的路径/参数**刻意不由网络调用方指定**
  // （走 env SQLMAP_PATH / SQLMAP_PYTHON / SQLMAP_ALLOW_EVAL，且 eval 默认关）。
  sqlmap: 'sqlmapBridge 自有子配置组；外部二进制参数刻意不经 REST（见 env SQLMAP_*）',
};

test('自证：判据真的扫到了东西（正则/路径失效时不得空转全绿）', () => {
  assert.ok(reads.size >= 100, `只扫到 ${reads.size} 个引擎读取键 —— 判据正则或扫描目录失效了`);
  assert.ok(WHITELIST.size >= 90, `白名单只解析出 ${WHITELIST.size} 个键 —— KNOWN_CFG_KEYS 提取失效`);
  assert.ok(cliWritten.size >= 20, `CLI 写入键只解析出 ${cliWritten.size} 个 —— 判据失效`);
});

test('孤儿配置键必须逐个实名豁免（新键没有入口就红；豁免过期也红）', () => {
  const orphans = [];
  for (const [k, sites] of reads) {
    if (WHITELIST.has(k) || k in defaults || cliWritten.has(k) || feWritten.has(k)) continue;
    // 同文件有写入者 ⇒ 内部字段
    if (sites.every((s) => writesByFile.has(`${s.file}#${k}`))) continue;
    orphans.push([k, sites]);
  }
  const unexpected = orphans.filter(([k]) => !(k in EXEMPT));
  assert.deepEqual(
    unexpected.map(([k, s]) => `${k} ← ${s[0].file}:${s[0].line}`),
    [],
    `这些键引擎真读、但 defaults / REST 白名单 / CLI / 面板四处都没有 —— 传了会拿到 200 + 一个` +
      `正常跑完的扫描，只是设置**根本没生效**（假阴性）。要么接上入口，要么删掉读取点，` +
      `要么在本文件 EXEMPT 里写清它为什么不是用户旋钮。\n  ` +
      unexpected.map(([k, s]) => `${k} ← ${s.map((x) => `${x.file}:${x.line}`).join(', ')}`).join('\n  ')
  );
  // 反向：豁免清单不得腐烂
  const orphanKeys = new Set(orphans.map(([k]) => k));
  const stale = Object.keys(EXEMPT).filter((k) => !orphanKeys.has(k));
  assert.deepEqual(
    stale,
    [],
    `这些豁免项已经不是孤儿键（键被删了 / 已接上入口 / 变成了同文件内部字段），请把 EXEMPT 里对应条目删掉：${stale.join(', ')}`
  );
});
