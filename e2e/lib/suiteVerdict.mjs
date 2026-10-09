// e2e/lib/suiteVerdict.mjs
// 验收套件的「失败标签」判定 —— 从 e2e/acceptance.mjs 抽出，为的是可单测。
//
// 为什么必须可单测：这套判据的核心价值是**分清"环境坏了"与"代码坏了"**。
// 判错了的代价不对称：把环境问题记成 FAIL，下一个人会去查被测代码（§G/§S 都栽在这上面）；
// 把真回归记成 BLOCKED，则会放过一个真实的红。两种错都必须能被测试钉住。
//
// 判据只用 **ASCII 稳定标记**（python 文件名 / Traceback / 错误码），
// 因为 [mysql-sandbox] 那些行在本机 cp936 控制台下是乱码，按中文匹配必失效。

/** 隔离沙箱「没起来」的三种形态 —— 都属环境条件不满足，不是被测代码失败。 */
const SANDBOX_DEAD_PATTERNS = [
  // ① 沙箱内部抛错（超时 / mysqld 起不来）—— 有完整 traceback，且栈顶在 mysql_sandbox.py
  (out) => /mysql_sandbox\.py", line \d+, in /m.test(out)
    && /Traceback \(most recent call last\)/.test(out),
  // ② 启动器自身在 import/查找阶段就失败（缺模块、python 版本不对）
  //    —— traceback 在 run-with-sandbox.py，不在 mysql_sandbox.py
  (out) => /run-with-sandbox\.py", line \d+, in /m.test(out)
    && /Traceback \(most recent call last\)/.test(out),
  // ③ 连 python 都没起来（容器缺 python / 缺 mysqld 二进制）：无 traceback，
  //    只剩启动器的前缀 + 非零退出。
  //
  //    ⚠️ **判据必须收紧到「沙箱从未就绪」**，不能只认 `[sandbox-run]` 前缀 ——
  //    实测（2026-09-22）第一版就是这样写的，随后用**真实回归样本**打回：
  //    沙箱正常起来、靶场正常、但断言真失败时，输出里同样有 `[sandbox-run]` 且同样没有
  //    `[PASS]`/`[SKIP]` → 被误判成 BLOCKED → **真回归被掩盖**（放水方向，比漏报更坏）。
  //    正解：要求「就绪」这行**不存在**。就绪过 = 沙箱没问题，失败在下游，不该贴环境标签。
  (out) => /\[sandbox-run\]/.test(out)
    && !/\[sandbox-run\]\s*沙箱就绪/.test(out)
    && !/mysql-sandbox\]\s*已就绪/.test(out),
];

/**
 * 输出是否表明「验证装置（隔离沙箱）根本没起来」。
 * @param {string} out 子进程的合并输出
 * @returns {boolean}
 */
export function isSandboxDead(out) {
  const s = String(out ?? '');
  return SANDBOX_DEAD_PATTERNS.some((p) => p(s));
}

/**
 * 把「断言结果 + 原始输出」归成最终状态。
 * 三态语义（与 acceptance.mjs 顶部汇总一致）：
 *   · PASS     —— 断言通过
 *   · SKIP     —— 环境常态（如 secure_file_priv=NULL），**未执行断言**，不进 failed
 *   · FAIL     —— 断言未通过（真正的红）
 *   · BLOCKED  —— 验证装置没起来，**未执行断言**，但**进 failed**（与 FAIL 一样非零退出）
 *
 * BLOCKED 与 FAIL 的区别只在**标签**，在于让人知道该查环境还是查代码 —— 不是放水。
 *
 * @param {{pass:boolean, skipped?:boolean, reason?:string|null}} verdict 断言函数的返回
 * @param {string} out 子进程输出
 * @param {number|null} code 子进程退出码
 */
export function classifySuite(verdict, out, code) {
  const skippedOnly = verdict.skipped === true;
  if (skippedOnly) {
    return { status: 'SKIP', reason: verdict.skipReason || verdict.reason || '环境不满足，未执行断言' };
  }
  if (verdict.pass) return { status: 'PASS', reason: null };
  if (isSandboxDead(out)) {
    return {
      status: 'BLOCKED',
      reason: '隔离 MySQL 沙箱未能启动（环境条件不满足，本套件一条断言都没执行；不是被测代码失败）',
    };
  }
  return { status: 'FAIL', reason: verdict.reason || `断言未通过（退出码 ${code}）` };
}

/**
 * 「本轮必须真跑到」清单的判定（acceptance 的 `--expect=id1,id2`）。
 *
 * 危害（2026-09-27 全栈审计实证）：optional 套件缺依赖时只打 SKIP，而收尾是
 * `process.exit(failed.length ? 1 : 0)` ⇒ fileRead / fileWrite / oob-real 这类
 * **头条能力可以整轮不测而门禁仍然绿**。CI 里 PG 与红队靶场正是用 continue-on-error
 * 拉起的 —— 起不来就落进这条静默通道。本函数把"调用方声明必须跑到"变成非零退出。
 *
 * 判据含反向一道：`--expect` 里出现未知 id 直接判违规。否则一次套件重命名就会把要求
 * 变成永不兑现的空转（本仓同类守卫的"不空转"判据是同一个道理）。
 *
 * @param {string[]} expectIds 要求本轮真跑到的套件 id
 * @param {Array<{id:string,status:string,facts?:object}>} results 本轮各套件结果
 * @param {Array<{id:string}>} suites SUITES 全表（判"未知 id"用）
 * @returns {string[]} 违规说明（空数组 = 全部兑现）
 */
export function evaluateExpect(expectIds, results, suites) {
  const bad = [];
  const known = new Set((suites || []).map((s) => s.id));
  const byId = new Map((results || []).map((r) => [r.id, r]));
  for (const id of expectIds || []) {
    if (!known.has(id)) {
      bad.push(`--expect 里的「${id}」不是已知套件 id —— 拼错或套件已删 ⇒ 这条要求永不兑现`);
      continue;
    }
    const r = byId.get(id);
    if (!r) {
      bad.push(`要求「${id}」真跑，但它没进本轮结果（带 --only 跑子集时不该同时用 --expect）`);
      continue;
    }
    if (r.status !== 'PASS') {
      const why = (r.facts && (r.facts.原因 || r.facts.缺失依赖)) || '未记录原因';
      bad.push(`要求「${id}」真跑，实际 ${r.status}：${why}`);
    }
  }
  return bad;
}

/**
 * 「这个套件本轮根本没执行断言」判定 —— e2e/run-all.mjs 的汇总用它。
 *
 * 起因（2026-10-09 D29 实测）：run-all 原来写的是 `code === 0 && /\bSKIP\b/i.test(out)`，
 * 于是 detection-runner 自己打的汇总行
 *     [runner] 统计：19 PASS / 0 FAIL / 0 SKIP / 0 WARN
 * 里的 "0 SKIP" 也算命中 —— **跑了 19 条断言的套件被标成「跳过（按设计）」**，
 * 汇总横幅还跟着说「本套件未执行任何断言」：一句假话进了门禁输出，且把真实覆盖面报少了。
 * 反方向同样要防：只喊了"跳过"、一条断言都没跑的套件不能算通过。
 *
 * 判据（两档，都偏保守）：
 *   ① 有统计行 ⇒ 只有「PASS=0 且 FAIL=0 且 SKIP>0」才算没执行；
 *   ② 没有统计行 ⇒ 要求「出现 SKIP 字样且完全没有 PASS 字样」才算没执行
 *     （有 PASS 就当它执行过 —— 宁可少报跳过，不可把真跑过的套件说成没跑）。
 * 只用 ASCII 标记，理由与本文件顶部一致（cp936 控制台下中文会成乱码）。
 */
export function executedNothing(out) {
  const s = String(out ?? '');
  const stats = /(\d+)\s*PASS[^\d]*?(\d+)\s*FAIL[^\d]*?(\d+)\s*SKIP/i.exec(s);
  if (stats) {
    const [, pass, fail, skip] = stats;
    return Number(pass) === 0 && Number(fail) === 0 && Number(skip) > 0;
  }
  return /\bSKIP\b/i.test(s) && !/\bPASS\b/i.test(s);
}
