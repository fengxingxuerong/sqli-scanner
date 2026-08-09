// 将整个 payload 转为 MySQL CHAR() 拼接（CONCAT(CHAR(n),...)）（类名 hex2char）
// 用途：绕过引号过滤——把注入串表示为一串 CHAR() 调用，避免在 SQL 中出现字面引号。
// 仅对 MySQL / MariaDB 生效（CHAR() 为 MySQL 系函数）；其余库原样返回以免破坏语义。
// 注意：该 tamper 适用于"字符串字面量上下文"的注入串（与 sqlmap hex2char 语义一致），
//       通常需要配合 union/error 等在具体字符串位置投放，单独对整句使用会改变 SQL 结构。
export const hex2char = {
  name: 'hex2char',
  description: '将整个 payload 转为 MySQL CHAR() 拼接（CONCAT(CHAR(n),...)），绕过引号过滤（仅 MySQL 系）',
  transform(payload, ctx) {
    const dbms = ctx && ctx.dbms;
    if (dbms && dbms !== 'MySQL' && dbms !== 'MariaDB') return payload;
    const parts = [];
    for (const ch of payload) {
      const code = ch.codePointAt(0);
      if (code <= 0xff) parts.push(`CHAR(${code})`);
      else parts.push(`CHAR(${(code >> 8) & 0xff},${code & 0xff})`);
    }
    return `CONCAT(${parts.join(',')})`;
  },
};

export default hex2char;
