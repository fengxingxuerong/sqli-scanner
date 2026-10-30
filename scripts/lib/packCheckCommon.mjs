// ============================================================================
// packCheckCommon.mjs —— pack 体检脚本的公共件（D184）
//
// 为什么有它：pack-check.mjs（门禁：包内容体检）与 pack-install-check.mjs（发版前
// registry 式安装体检）此前各写了一份逐字同构的 run() 与 selftest 跑法，被重复代码
// 门禁当场抓红（两个 100+ token 克隆）。抽到这里，判据同源、改动单点。
// ============================================================================
import { execFileSync } from 'node:child_process';

/**
 * 跑一条命令并取 stdout（失败时把 stderr 尾部带出来，避免只有 exit code）。
 * Windows 上 npm/npx 是 .cmd 垫片，execFileSync 直跑会 ExitCode=null（不是真的失败）。
 * @param {string} cmd
 * @param {string[]} args
 * @param {object} [opts] 透传给 execFileSync 的额外选项（如 cwd）
 * @returns {string} stdout
 */
export function run(cmd, args, opts = {}) {
  const needsShell = process.platform === 'win32' && /^(npm|npx)$/.test(cmd);
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: 'pipe', shell: needsShell, ...opts });
  } catch (e) {
    const out = `${e.stdout || ''}\n${e.stderr || ''}`.trim().split(/\r?\n/).slice(-8).join('\n');
    throw new Error(`${cmd} ${args.join(' ')} 失败（exit=${e.status}）：\n${out}`, { cause: e });
  }
}

/**
 * pack 体检脚本共用的 selftest 跑法：合格样本不误判 + 每种违规各自被检出（判据必须有牙）。
 * @param {(sample) => string[]} assertFn 断言函数（入参为样本，返回违规说明数组，空数组 = 通过）
 * @param {object} good 合格样本
 * @param {Array<{name:string, sample:object, expect:RegExp}>} cases 违规用例（判据必须能红）
 * @param {string} tag 日志前缀（如 'pack-check' / 'pack-install'）
 * @param {string} goodLabel 合格样本的展示名（用于通过/误判文案）
 * @returns {void} 直接设置 process.exitCode
 */
export function selftestCases(assertFn, good, cases, tag, goodLabel) {
  const failures = [];
  const goodErrs = assertFn(good);
  if (goodErrs.length) failures.push(`${goodLabel}被误判：${goodErrs.join(' | ')}`);
  for (const c of cases) {
    const errs = assertFn(c.sample);
    if (!errs.length) failures.push(`「${c.name}」未被检出（判据空转）`);
    else if (!errs.some((e) => c.expect.test(e))) failures.push(`「${c.name}」文案不符：${errs.join(' | ')}`);
  }
  if (failures.length) {
    console.error(`[${tag}] ✗ selftest 失败：`);
    for (const f of failures) console.error('  · ' + f);
    process.exitCode = 1;
    return;
  }
  console.log(`[${tag}] ✓ selftest 通过：${goodLabel}不误判 + ${cases.length} 种违规各自被检出`);
  process.exitCode = 0;
}
