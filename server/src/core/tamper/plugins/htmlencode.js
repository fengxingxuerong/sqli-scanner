// HTML 实体编码所有非字母数字字符，绕过基于明文字符的 WAF 规则
export const htmlencode = {
  name: 'htmlencode',
  description: '将非字母数字字符 HTML 实体编码（&#NN;），绕过基于明文字符的规则',
  transform(payload) {
    return payload.replace(/[^a-zA-Z0-9]/g, (c) => '&#' + c.charCodeAt(0) + ';');
  },
};
export default htmlencode;
