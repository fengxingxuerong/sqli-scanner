// [T3 对齐 sqlmap between] 两条重写分支（上游 between.py 也是这两条）：
//   - 裸 >  转 NOT BETWEEN 0 AND
//   - 裸 =  转 BETWEEN 右值 AND 右值（x = y ⟺ x BETWEEN y AND y，严格等价、无边界损失）
//     ⇒ 此前这条分支整体缺失，`A = B` / `LAST_INSERT_ROWID()=LAST_INSERT_ROWID()` 原样发出
//   - >= 转 NOT BETWEEN 0 AND 会丢等值语义（a>=b ⟺ NOT BETWEEN 0 AND b 仅当 a>b）→ 跳过复合运算符
//   - <  转 BETWEEN 0 AND 引入错误下界且含相等分支（a<b ⟺ a BETWEEN 0 AND b-1 才严格）→ 不改写 <
//   - <> 是不等号，不可拆坏 → 跳过
// 空白：两侧 `\s*` 一并消费后再补单空格 ⇒ 不会在 `A > B` 上叠出双空格（上游同口径）
export const between = {
  name: 'between',
  description: '将裸 > 转 NOT BETWEEN 0 AND、裸 = 转 BETWEEN y AND y（跳过 >=/<=/<> 复合运算符，不改写 <，对齐 sqlmap）',
  doctests: [
    { input: 'a>1', output: 'a NOT BETWEEN 0 AND 1' },
    { input: 'a>=1', output: 'a>=1' },
    { input: 'a<2', output: 'a<2' }, // 不改写 <
    { input: 'a<>1', output: 'a<>1' },
    // ↓ 三条取自上游官方 doctest（verify-tamper-upstream-examples 逐字比对）
    { input: '1 AND A > B--', output: '1 AND A NOT BETWEEN 0 AND B--' },
    { input: '1 AND A = B--', output: '1 AND A BETWEEN B AND B--' },
    { input: '1 AND LAST_INSERT_ROWID()=LAST_INSERT_ROWID()', output: '1 AND LAST_INSERT_ROWID() BETWEEN LAST_INSERT_ROWID() AND LAST_INSERT_ROWID()' },
    { input: 'a!=1', output: 'a!=1' }, // 复合运算符保护（!= 里的 = 不动）
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const s = String(payload ?? '');
    const gt = s.replace(/\s*(?<![<>!=])>(?!=)\s*/g, ' NOT BETWEEN 0 AND ');
    if (gt !== s) return gt;
    // = 分支：两侧只认标识符/数字/带括号函数调用 ⇒ 引号内的 = 天然不参与
    return s.replace(
      /([\w.]+(?:\([^()]*\))?)\s*(?<![<>!=])=(?!=)\s*([\w.]+(?:\([^()]*\))?)(?![\w.])/g,
      '$1 BETWEEN $2 AND $2'
    );
  },
};

export default between;
