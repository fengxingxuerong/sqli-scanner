// IFNULL(a, b) 转 CASE WHEN ISNULL(a) THEN b ELSE a END，变换函数形态
export const ifnull2casewhenisnull = {
  name: 'ifnull2casewhenisnull',
  description: '将 IFNULL(a, b) 改写为 CASE WHEN ISNULL(a) THEN b ELSE a END',
  transform(payload) {
    return payload.replace(/IFNULL\(([^,]+),\s*([^)]+)\)/gi,
      'CASE WHEN ISNULL($1) THEN $2 ELSE $1 END');
  },
};
export default ifnull2casewhenisnull;
