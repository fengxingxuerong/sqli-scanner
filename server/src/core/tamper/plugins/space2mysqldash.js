// 空格转 -- + 随机串 + %0A 换行终止（MySQL 行注释风格），绕过空格过滤
// [T6 对齐 sqlmap space2mysqldash] 注释必须以换行终止：%20 在注释内部不产生换行，
// 第一个空格后整段 payload 被行注释吞掉 → %20 改 %0A。
export const space2mysqldash = {
  name: 'space2mysqldash',
  description: '将空格替换为 --<随机串>%0A（MySQL 行注释风格，注释以换行终止），绕过空格过滤',
  doctests: [
    { input: 'a b', match: '^a--[0-9a-z]{4}%0Ab$' },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  transform(payload) {
    return payload.replace(/ /g, '--' + Math.random().toString(36).slice(2, 6) + '%0A');
  },
};
export default space2mysqldash;
