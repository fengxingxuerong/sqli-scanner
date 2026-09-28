// ============================================================================
// inject-check.mjs —— 真机对拍链路的**缺陷注入复验**（本地工具，非 CI 门禁）
//
// 为什么留着：这一条链上每个判据都曾经「读起来对、实则空转」，本仓的纪律是
// 「改完要注入复验」——把判据改坏，测试必须红；不红说明断言没真正盯着那个行为。
// 四个注入点对应四类死法，逐条列出便于下次改动后一键复跑：
//   A 放宽报错判据（去掉注入标记要求）      → 应红 ④b
//   B 对拍脚本硬编码 /num?id=（ctx 作废）   → 应红 ⑦b（上界 1/8 的直接成因）
//   C 删掉 in 上下文的全部样本              → 应红 ⑭
//   D 取数样本去掉注入标记                  → 应红 ⑮
//
// 用法：node e2e/waf-real/inject-check.mjs       （跑完自动还原源文件）
// ⚠️ 它会临时改写 samples.mjs / pwnVerdict.mjs / modsec-live.mjs 再还原，
//    跑之前确保工作区没有未保存的改动（git status 干净）。
// ============================================================================
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const SERVER = resolve(ROOT, 'server');
const FILES = ['tests/modsecLive.wiring.test.js', 'tests/wafSamples.guard.test.js']; // cwd = server/

/** 跑一遍守卫；node --test 一次只收一个位置参数（多个会被当成含逗号的文件名） */
function run() {
  let fails = [];
  for (const f of FILES) {
    try {
      execFileSync(process.execPath, ['--test', f], { cwd: SERVER, encoding: 'utf8' });
    } catch (e) {
      const out = `${e.stdout || ''}${e.stderr || ''}`;
      fails = fails.concat([...out.matchAll(/not ok \d+ - (.+)/g)].map((m) => m[1].trim()));
    }
  }
  return { fails };
}

const cases = [
  {
    name: 'A 放宽报错判据（去掉注入标记要求）',
    file: 'e2e/waf-real/pwnVerdict.mjs',
    from: 'EXFIL_ERROR.test(b) && EXFIL_MARK.test(b)',
    to: 'EXFIL_ERROR.test(b)',
  },
  {
    name: 'B 对拍脚本硬编码 /num?id=（样本 ctx 作废）',
    file: 'e2e/waf-real/modsec-live.mjs',
    from: 'const url = sampleUrl(base, payload);',
    to: 'const url = `${base}/num?id=${encodeURIComponent(payload.payload || payload)}`;',
  },
  {
    name: 'C 删掉 in 上下文的全部样本',
    file: 'e2e/waf-real/samples.mjs',
    from: `{ ctx: 'in', exfil: true, payload: "1) UNION SELECT 'SQLISCANNER0','SQLISCANNER1','SQLISCANNER2','SQLISCANNER3'-- -", note: 'union（需闭合右括号）' },`,
    to: '',
    extra: [
      [`{ ctx: 'in', exfil: true, payload: "1) UNION SELECT 1,CONCAT('__S__',version(),'__E__'),3,4-- -", note: 'union 取数（需闭合右括号）' },`, ''],
      [`{ ctx: 'in', exfil: true, payload: "1) AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))-- -", note: '报错取数（需闭合右括号）' },`, ''],
    ],
  },
  {
    name: 'D 取数样本去掉注入标记',
    file: 'e2e/waf-real/samples.mjs',
    from: `"1 UNION SELECT 1,CONCAT('__S__',version(),'__E__'),3,4"`,
    to: `"1 UNION SELECT 1,version(),3,4"`,
  },
];

const base = run();
console.log(`基线：失败 ${base.fails.length} 条 ${base.fails.join(' | ')}`);

let killed = 0;
for (const c of cases) {
  const p = resolve(ROOT, c.file);
  const orig = readFileSync(p, 'utf8');
  if (!orig.includes(c.from)) {
    console.log(`❌ ${c.name} —— 注入点没匹配上（源码变了，本脚本需同步）`);
    continue;
  }
  let next = orig.replace(c.from, c.to);
  for (const [f, t] of c.extra || []) {
    if (!next.includes(f)) { console.log(`❌ ${c.name} —— extra 注入点没匹配上`); next = null; break; }
    next = next.replace(f, t);
  }
  if (next === null) continue;
  writeFileSync(p, next, 'utf8');
  const r = run();
  writeFileSync(p, orig, 'utf8');
  const restored = readFileSync(p, 'utf8') === orig;
  if (r.fails.length > 0) killed++;
  console.log(
    `${r.fails.length > 0 ? '✅' : '❌'} ${c.name} → 红 ${r.fails.length} 条：${r.fails.join(' | ') || '（无 = 断言空转）'} · 已还原=${restored}`
  );
}

const after = run();
console.log(`\n${killed}/${cases.length} 注入被杀 · 收尾失败 ${after.fails.length} 条（应为 0）`);
process.exit(killed === cases.length && after.fails.length === 0 ? 0 : 1);
