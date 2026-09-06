// IFNULL(a,b) 改写为 IF(ISNULL(a),b,a)（绕过基于 IFNULL 的 WAF/IDS 规则）
export const ifnull2ifisnull = {
  name: 'ifnull2ifisnull',
  description: '将 IFNULL(a,b) 改写为 IF(ISNULL(a),b,a)，绕过函数名过滤',
  doctests: [
    { input: 'IFNULL(a,1)', output: 'IF(ISNULL(a),1,a)' },
  ],
  transform(payload) {
    return payload.replace(/IFNULL\(([^,]+),([^)]+)\)/gi, 'IF(ISNULL($1),$2,$1)');
  },
};

export default ifnull2ifisnull;
