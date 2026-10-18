// ============================================================================
// literalWalk.js — SQL 字面量遍历的**单一抽象**（design §2.2.2 / spec 5.2.2）
//
// ── 为什么要有这个 ────────────────────────────────────────────────────────
// 73 个 tamper 插件各自手写 inSingle/inDouble/inLine 主循环，逐字重复。
// 判据漂移（如 isQuoteEscaped 的奇偶性 vs 前一字符）已在 23 个文件中出过事。
// 本模块把遍历逻辑抽为一处，插件只需提供 onText/onLiteral/onAbort 回调。
//
// ── 两类语义 ──────────────────────────────────────────────────────────────
// · 引号外变换（space2*）：只提供 onText，引号内原样透传
// · 引号内变换（rot13/caesar 等）：只提供 onLiteral，引号外原样透传
//
// ── 关键契约 ──────────────────────────────────────────────────────────────
// 未闭合字面量（closed=false）时必须调用 onAbort，回调放弃编码并原样输出。
// 继承 quoteScan.js:63-67 契约：绝不能把未闭合的剩余内容当字面量编码掉。
// ============================================================================
import { readSqlLiteral } from './quoteScan.js';

/**
 * 遍历 SQL 源串，按「文本 / 字面量」分段回调，重组结果。
 *
 * @param {string} src - 源串
 * @param {object} [handlers]
 * @param {(text:string)=>string} [handlers.onText] - 文本段回调（引号外 + 行注释外）
 * @param {(body:string, quote:'"'|"'" )=>string} [handlers.onLiteral] - 字面量段回调（body 不含引号）
 * @param {(remaining:string, quote:'"'|"'" )=>string} [handlers.onAbort] - 未闭合字面量回调
 * @returns {string} 重组后的串
 */
export function walkLiterals(src, handlers = {}) {
  const { onText, onLiteral, onAbort } = handlers;
  const s = String(src ?? '');
  let out = '';
  let i = 0;
  let textBuf = '';

  const flushText = () => {
    if (textBuf) {
      out += onText ? onText(textBuf) : textBuf;
      textBuf = '';
    }
  };

  while (i < s.length) {
    const ch = s[i];

    // 行注释 -- ... \n：原样透传（引号在注释内不触发字面量扫描）
    if (ch === '-' && s[i + 1] === '-') {
      flushText();
      let j = i + 2;
      while (j < s.length && s[j] !== '\n') j++;
      if (j < s.length) j++;
      out += s.slice(i, j);
      i = j;
      continue;
    }

    // 单引号字面量
    if (ch === "'") {
      const lit = readSqlLiteral(s, i, "'");
      if (!lit.closed) {
        flushText();
        out += onAbort ? onAbort(s.slice(i), "'") : s.slice(i);
        return out;
      }
      flushText();
      out += onLiteral ? onLiteral(lit.body, "'") : `'${lit.body}'`;
      i = lit.end + 1;
      continue;
    }

    // 双引号字面量
    if (ch === '"') {
      const lit = readSqlLiteral(s, i, '"');
      if (!lit.closed) {
        flushText();
        out += onAbort ? onAbort(s.slice(i), '"') : s.slice(i);
        return out;
      }
      flushText();
      out += onLiteral ? onLiteral(lit.body, '"') : `"${lit.body}"`;
      i = lit.end + 1;
      continue;
    }

    textBuf += ch;
    i++;
  }

  flushText();
  return out;
}

/**
 * [D107] 长度保持的**字面量打码**：把每个字面量（含引号本身）逐字符替换为 maskChar，
 * 输出与输入**等长**且下标一一对应 —— 供「需要全局切片定位、又要屏蔽字面量内标点」
 * 的插件使用（if2case / ifnull2casewhenisnull 的括号深度扫描）。
 *
 * 打码串仅保证：合法 SQL 文本中不会出现的 maskChar 不会伪造出 `IF(` 等针、逗号、
 * 括号、引号；调用方仍应从**原串**用打码串的下标取切片（两串等长）。
 * 未闭合字面量按契约整体打码（其后不存在代码层）。
 *
 * @param {string} src
 * @param {string} [maskChar] 单字符，默认 \u0001（合法 SQL 文本不含）
 * @returns {string}
 */
export function maskLiterals(src, maskChar = '\u0001') {
  return walkLiterals(src, {
    onLiteral: (body) => maskChar.repeat(body.length + 2), // 引号一并打码，保持等长
    onAbort: (remaining) => maskChar.repeat(remaining.length),
  });
}