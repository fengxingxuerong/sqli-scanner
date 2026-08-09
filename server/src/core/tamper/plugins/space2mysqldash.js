// 空格转 -- + 随机串 + %20（MySQL 行注释风格），绕过空格过滤
export const space2mysqldash = {
  name: 'space2mysqldash',
  description: '将空格替换为 --<随机串>%20（MySQL 行注释风格），绕过空格过滤',
  compat: { dbms: ['MySQL', 'MariaDB'] },
  transform(payload) {
    return payload.replace(/ /g, '--' + Math.random().toString(36).slice(2, 6) + '%20');
  },
};
export default space2mysqldash;
