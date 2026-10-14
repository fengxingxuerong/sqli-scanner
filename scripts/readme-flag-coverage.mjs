// ============================================================================
// readme-flag-coverage.mjs —— ⑯/⑰ CLI 旗标双向核对（[D68]/[D69]，2026-10-14）
//
// 为什么独立成文件：这两条判据加进 readme-consistency 的 checkConsistency 后，
// 它自身的函数体/圈复杂度立刻顶到基线（185 行/45 圈 vs 基线 176/41）——
// **门禁自己因为判据变多而欠了技术债**，方向反了。独立成模块后主门禁零增长。
//
// 两条判据：
//   ⑯ README 必须收录解析器的每一个 CLI 旗标（能力清单不能只藏在 --help 里）
//   ⑰ --help 文本同样必须收录（用户第一眼看到的地方）
//
// 真实源 = `server/bin/cli/args.js` 的**解析分支**（`a === '--xxx'` / `case '--xxx':`），
// 不是 help 文本：实测解析器 168 个旗标、help 原本只覆盖 157 个 ⇒ 拿 help 当清单
// 等于「拿不完整的当完整」。
// ============================================================================
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HELP_TEXT } from '../server/bin/cli/help.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * 从 CLI 解析器源码提取旗标清单（保持出现序、去重）。
 * ⚠️ 口径只认**解析分支** `a === '--xxx'` / `case '--xxx':`——说明文字、错误信息、
 * 注释里出现的 `--xxx` 一律不算，避免把描述当能力。
 * @param {string} argsSource args.js 源码
 * @returns {string[]}
 */
function parseCliFlags(argsSource) {
  const out = [];
  const re = /(?:a\s*===\s*|case\s+)'(--[a-z0-9][a-z0-9-]*)'/g;
  let m;
  while ((m = re.exec(String(argsSource))) !== null) if (!out.includes(m[1])) out.push(m[1]);
  return out;
}

/**
 * 文本里是否**作为完整旗标**出现（词边界）。
 * ⚠️ 不能用 `includes`：那会让 `--max` 被 `--max-requests` 满足、`--user` 被别的词命中
 * —— D69 实测：子串口径 0 缺失（假绿），词边界口径 4 缺失（真值）。
 * @param {string} text
 * @param {string} flag 含前导 `--`
 * @returns {boolean}
 */
function mentionsFlag(text, flag) {
  const esc = String(flag).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\w-])${esc}(?![\\w-])`, 'm').test(String(text));
}

/**
 * 算两条判据各自的缺失清单。
 * @param {string} [readmeText] README 全文（默认读仓库里的）
 * @returns {{cliFlags:string[], missingCliFlags:string[], missingHelpFlags:string[]}}
 */
export function measureFlagCoverage(readmeText = readFileSync(resolve(ROOT, 'README.md'), 'utf8')) {
  const cliFlags = parseCliFlags(readFileSync(resolve(ROOT, 'server/bin/cli/args.js'), 'utf8'));
  return {
    cliFlags,
    missingCliFlags: cliFlags.filter((f) => !mentionsFlag(readmeText, f)),
    missingHelpFlags: cliFlags.filter((f) => !mentionsFlag(HELP_TEXT, f)),
  };
}

/**
 * ⑯/⑰ 判定（fails 原地追加）。
 * @param {{cliFlags?:string[], missingCliFlags?:string[], missingHelpFlags?:string[]}} input
 * @param {string[]} fails
 */
export function judgeFlagCoverage(input, fails) {
  const flags = input.cliFlags || [];
  if (!flags.length) return;
  const missReadme = input.missingCliFlags || [];
  if (missReadme.length) {
    fails.push(
      `⑯ CLI 有 ${flags.length} 个旗标，README 漏写 ${missReadme.length} 个（能力清单只存在于 --help，客户与新读者看不到）：` +
      `${missReadme.slice(0, 20).join('、')}${missReadme.length > 20 ? ` …等 ${missReadme.length} 个` : ''} — ` +
      `修法：在 README「CLI 能力速查」里按用途分组补齐`,
    );
  }
  const missHelp = input.missingHelpFlags || [];
  if (missHelp.length) {
    fails.push(
      `⑰ CLI 有 ${flags.length} 个旗标，--help 文本缺 ${missHelp.length} 个（用户第一眼看不到这些能力）：` +
      `${missHelp.slice(0, 20).join('、')}${missHelp.length > 20 ? ` …等 ${missHelp.length} 个` : ''} — ` +
      `修法：在 server/bin/cli/help.js 的 HELP_TEXT 补对应条目`,
    );
  }
}

// ── 自证（判据不得空转 / 不得过宽）────────────────────────────────────────────
function selftest() {
  const bad = [];
  const ok = (v, m) => { if (!v) bad.push(m); };

  // ① 解析器口径：只认解析分支
  const src = [
    "if (a === '--alpha') args.alpha = true;",
    "else if (a === '--beta') args.beta = 1;",
    "switch (x) { case '--gamma': break; }",
    "// 说明里提到 --not-a-flag 不算",
    "throw new Error('未知参数 --norway');",
  ].join('\n');
  const got = parseCliFlags(src);
  ok(JSON.stringify(got) === JSON.stringify(['--alpha', '--beta', '--gamma']),
    `parseCliFlags 应只提取解析分支旗标，实际 ${JSON.stringify(got)}`);

  // ② 词边界：`--max` 不被 `--max-requests` 满足；独立出现要命中；`xx--maxx` 不算
  ok(!mentionsFlag('命令里有 --max-requests 上限', '--max'), '`--max` 不该被 `--max-requests` 满足');
  ok(mentionsFlag('参数 --max 与 --max-requests 不同义', '--max'), '文本里独立出现的 `--max` 应命中');
  ok(!mentionsFlag('前缀 xx--maxx', '--max'), '`xx--maxx` 不该算作 `--max`');

  // ③ ⑯/⑰ 判据：缺一个报一个；齐全不报
  const f1 = [];
  judgeFlagCoverage({ cliFlags: ['--alpha', '--beta'], missingCliFlags: ['--beta'], missingHelpFlags: [] }, f1);
  ok(f1.length === 1 && /⑯/.test(f1[0]), `README 缺旗标应报 ⑯，实际 ${JSON.stringify(f1)}`);
  const f2 = [];
  judgeFlagCoverage({ cliFlags: ['--alpha'], missingCliFlags: [], missingHelpFlags: ['--alpha'] }, f2);
  ok(f2.length === 1 && /⑰/.test(f2[0]), `--help 缺旗标应报 ⑰，实际 ${JSON.stringify(f2)}`);
  const f3 = [];
  judgeFlagCoverage({ cliFlags: ['--alpha', '--beta'], missingCliFlags: [], missingHelpFlags: [] }, f3);
  ok(f3.length === 0, `齐全时不应报错，实际 ${JSON.stringify(f3)}`);

  if (bad.length) {
    console.error('[readme-flags] ✗ 自证失败：');
    for (const b of bad) console.error('    · ' + b);
    process.exit(1);
  }
  console.log('[readme-flags] ✓ 自证通过：解析器口径 / 词边界 / ⑯⑰ 正反例（判据不空转、不过宽）');
}

if (process.argv.includes('--selftest')) selftest();

export { HELP_TEXT };