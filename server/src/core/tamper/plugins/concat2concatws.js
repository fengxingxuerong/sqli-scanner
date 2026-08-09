// CONCAT() 转 CONCAT_WS(CHAR(32), ...)，避免逗号并变换函数形态
export const concat2concatws = {
  name: 'concat2concatws',
  description: '将 CONCAT(...) 改写为 CONCAT_WS(CHAR(32), ...)，变换函数形态',
  transform(payload) {
    return payload.replace(/CONCAT\(/gi, 'CONCAT_WS(CHAR(32),');
  },
};
export default concat2concatws;
