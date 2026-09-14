// [T3 对齐 sqlmap between] 仅重写裸 >：
//   - >= 转 NOT BETWEEN 0 AND 会丢等值语义（a>=b ⟺ NOT BETWEEN 0 AND b 仅当 a>b）→ 跳过复合运算符
//   - < 转 BETWEEN 0 AND 引入错误下界且含相等分支（a<b ⟺ a BETWEEN 0 AND b-1 才严格）→ 不改写 <
//   - <> 是不等号，不可拆坏 → 跳过
export const between = {
  name: 'between',
  description: '将裸 > 转 NOT BETWEEN 0 AND（跳过 >=/<=/<> 复合运算符，不改写 <，对齐 sqlmap）',
  doctests: [
    { input: 'a>1', output: 'a NOT BETWEEN 0 AND 1' },
    { input: 'a>=1', output: 'a>=1' },
    { input: 'a<2', output: 'a<2' }, // 不改写 <
    { input: 'a<>1', output: 'a<>1' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/(?<![<>!=])>(?![>=])/g, ' NOT BETWEEN 0 AND ');
  },
};

export default between;
