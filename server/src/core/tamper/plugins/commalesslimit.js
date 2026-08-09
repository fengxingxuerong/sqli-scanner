// LIMIT a, b 转 LIMIT b OFFSET a，去除逗号（绕过逗号过滤）
export const commalesslimit = {
  name: 'commalesslimit',
  description: '将 LIMIT a, b 改写为 LIMIT b OFFSET a，去除逗号',
  transform(payload) {
    return payload.replace(/LIMIT\s+(\d+)\s*,\s*(\d+)/gi, 'LIMIT $2 OFFSET $1');
  },
};
export default commalesslimit;
