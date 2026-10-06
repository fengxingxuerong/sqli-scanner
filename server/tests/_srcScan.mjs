// ============================================================================
// tests/_srcScan.mjs —— 测试用源码扫描工具
//
// ── 为什么要抽出来 ─────────────────────────────────────────────────────────────
// 本仓的守卫测试经常要"扫源码里有没有某形态"。而这类判据反复踩同一个坑：
// **判据把自己也判进去了**。原因几乎总是同一个——
//   为了解释一次历史改造，我们会在注释里**引用被禁掉的旧形态**（例如
//   "`/** @type {any} */ (em)._replayBuffer`" 这段文字本身就在注释里）。
//   于是判据命中自己的说明文字 ⇒ 恒红的假失败 ⇒ 要么被误当成真缺陷去"修"代码，
//   要么被加个例外绕过 —— 后者更糟，因为它同时废掉了这道守卫。
//
// 本轮已在 extractorLimitHit 与 eventBus.replayBuffer 两处各踩一次，
// 故抽成共享工具：**剥注释是所有源码形态判据的默认前置**，不该每处各写一遍
// （各写一遍就会各错一遍）。
//
// 约定：所有"扫源码判形态"的守卫都应先用 stripComments() 再判；
//       若确实需要连注释一起扫（如"注释里也不许提某个键"），显式传 { keepComments: true }。
// ============================================================================
import { readFileSync } from 'node:fs';

/**
 * 去掉块注释与行注释，保留真实代码。
 * 注意：字符串字面量里的 // 或 /* 不做处理——本仓源码不含此类内容，
 *       若将来引入含 URL 的字符串字面量，需改用更精细的词法扫描。
 * @param {string} src
 * @returns {string}
 */
export function stripComments(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

/**
 * 读取文件并（默认）剥掉注释。
 * @param {string} path
 * @param {{keepComments?: boolean}} [opts]
 * @returns {string}
 */
export function readCode(path, { keepComments = false } = {}) {
  const raw = readFileSync(path, 'utf8');
  return keepComments ? raw : stripComments(raw);
}