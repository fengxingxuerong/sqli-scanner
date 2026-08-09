// SLEEP(n) 转 PostgreSQL 的 PG_SLEEP(n)，适配不同 DBMS 的时间盲注
export const sleep2pg = {
  name: 'sleep2pg',
  description: '将 SLEEP(n) 改写为 PostgreSQL 的 PG_SLEEP(n)',
  compat: { dbms: ['PostgreSQL'] },
  transform(payload) {
    return payload.replace(/SLEEP\((\d+)\)/gi, 'PG_SLEEP($1)');
  },
};
export default sleep2pg;
