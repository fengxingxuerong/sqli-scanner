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
