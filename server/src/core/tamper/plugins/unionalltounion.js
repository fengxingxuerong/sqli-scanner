// UNION ALL 转 UNION，变形联合查询关键字
export const unionalltounion = {
  name: 'unionalltounion',
  description: '将 UNION ALL 改写为 UNION，变形联合查询关键字',
  transform(payload) {
    return payload.replace(/UNION\s+ALL/gi, 'UNION');
  },
};
export default unionalltounion;
