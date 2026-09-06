// 空格 -> +（部分 WAF / 参数解析会把 + 还原为空格）
// 与 space2comment 互补：当目标不接受注释语法时，+ 是更轻量的空格替代。
export const space2plus = {
  name: 'space2plus',
  description: '将空格替换为 +（部分 WAF/参数解析会还原为空格）',
  doctests: [
    { input: 'a AND b', output: 'a+AND+b' },
  ],
  transform(payload) {
    return payload.replace(/ /g, '+');
  },
};

export default space2plus;
