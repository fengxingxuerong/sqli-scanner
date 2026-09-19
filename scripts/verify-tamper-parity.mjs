// ============================================================================
// scripts/verify-tamper-parity.mjs —— 我们的 tamper 插件集 vs sqlmap 官方 tamper 清单
//
// 为什么：README 的门面话是「228 个 tamper 插件，覆盖 sqlmap 官方 tamper 全集（84/84）」。
// 这句话今天是**自报的**——数自己目录里的文件个数，没有任何外部对照。跟 CRS 规则原文一样，
// 这类"对齐上游全集"的说法要么可核验、要么不许写。本脚本让它可核验：
//   1) 取 sqlmap 官方 tamper/ 目录（钉死 tag，逐字节可复核）的文件名清单；
//   2) 与我们 server/src/core/tamper/plugins/ 下的插件名做集合差；
//   3) 报「缺失清单」+「我们多出的数量」，并把缺失集合作为基线（只减不增）。
//
// 用法：
//   node scripts/verify-tamper-parity.mjs              # 校验（离线时用已入库的清单快照）
//   node scripts/verify-tamper-parity.mjs --refresh    # 重新抓上游清单
// 退出码：官方有、我们没有，且不在基线里 → 1
// ============================================================================
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SQLMAP_TAG = '1.9.11'; // 钉死版本：升级时改这里并复核对齐率
const SNAPSHOT = resolve(ROOT, 'server/src/core/tamper/upstream-sqlmap-tamper.json');
const BASELINE = resolve(ROOT, 'server/src/core/tamper/tamper-parity-baseline.json');
const PLUGINS_DIR = resolve(ROOT, 'server/src/core/tamper/plugins');

async function fetchUpstream() {
  const url = `https://api.github.com/repos/sqlmapproject/sqlmap/contents/tamper?ref=${SQLMAP_TAG}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'sqli-scanner-tamper-parity', Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(45000) });
  if (!res.ok) throw new Error(`上游清单获取失败：HTTP ${res.status}`);
  const names = (await res.json())
    .filter((f) => f.type === 'file' && f.name.endsWith('.py') && !name_is_init(f.name))
    .map((f) => f.name.replace(/\.py$/, ''))
    .sort();
  writeFileSync(SNAPSHOT, JSON.stringify({ tag: SQLMAP_TAG, at: new Date().toISOString(), count: names.length, names }, null, 2));
  return names;
}
const name_is_init = (n) => /^(__init__|api|utils)\.py$/.test(n);

const ours = () =>
  readdirSync(PLUGINS_DIR)
    .filter((f) => f.endsWith('.js'))
    .map((f) => f.replace(/\.js$/, ''))
    .sort();

const refresh = process.argv.includes('--refresh');
let upstream;
if (refresh || !existsSync(SNAPSHOT)) upstream = await fetchUpstream();
else upstream = JSON.parse(readFileSync(SNAPSHOT, 'utf8')).names;

const mine = new Set(ours());
const missing = upstream.filter((n) => !mine.has(n));
const extra = [...mine].filter((n) => !upstream.includes(n));

const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : null;
const known = new Set(baseline?.missing || []);
const unexpected = missing.filter((n) => !known.has(n));
const fixed = (baseline?.missing || []).filter((n) => !missing.includes(n));

console.log(`=== tamper 插件对齐 sqlmap 官方（tag ${SQLMAP_TAG}，清单日期 ${JSON.parse(readFileSync(SNAPSHOT, 'utf8')).at?.slice(0, 10)}）===`);
console.log(`  官方 ${upstream.length} 个｜本仓 ${mine.size} 个（其中本仓独有 ${extra.length} 个：${extra.slice(0, 12).join(', ')}${extra.length > 12 ? '…' : ''}）`);
console.log(`  官方有而本仓没有：${missing.length} 个${baseline ? `（基线已点名 ${known.size}）` : ''}`);
if (missing.length) console.log(`  ${missing.join(', ')}`);
if (fixed.length) console.log(`  ↻ 已补齐、可收紧基线：${fixed.join(', ')}`);
if (unexpected.length) console.log(`  ❌ 未点名的缺失：${unexpected.join(', ')}`);

if (!baseline) {
  writeFileSync(
    BASELINE,
    JSON.stringify({ _comment: '官方有、本仓没有的 tamper：逐条点名（只减不增）。新增缺失 = 门禁 FAIL。空数组表示当前覆盖上游全集；一旦上游加了新 tamper，要么实现、要么在这里写明"为什么对本工具无意义"。', sqlmapTag: SQLMAP_TAG, missing }, null, 2)
  );
  console.log(`\n[基线] 已生成 ${BASELINE}（${missing.length} 条）——请逐条补理由后提交`);
  process.exitCode = 0;
} else {
  console.log(unexpected.length ? '\n❌ 出现未点名的缺失 —— 要么实现它，要么在基线里写明为什么不实现' : '\n✅ 缺失集合与基线一致（或更小）');
  process.exitCode = unexpected.length ? 1 : 0;
}
