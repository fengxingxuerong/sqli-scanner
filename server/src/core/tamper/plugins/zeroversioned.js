// 关键字用零版本注释包裹 /*!00000KEY*/，绕过基于关键字的规则
export const zeroversioned = {
  name: 'zeroversioned',
  description: '将核心关键字用 /*!00000KEY*/ 零版本注释包裹',
  compat: { dbms: ['MySQL', 'MariaDB'] },
  transform(payload) {
    return payload.replace(/\b(SELECT|UNION|WHERE|AND|OR|FROM|ORDER|BY)\b/gi,
      (m) => '/*!00000' + m + '*/');
  },
};
export default zeroversioned;
