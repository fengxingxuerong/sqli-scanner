// UNION 关键字内插注释，绕过基于 UNION 整词的规则
export const misunion = {
  name: 'misunion',
  description: '将 UNION 改写为 UNI/**/ON，绕过基于 UNION 整词的规则',
  transform(payload) {
    return payload.replace(/\bUNION\b/gi, 'UNI/**/ON');
  },
};
export default misunion;
