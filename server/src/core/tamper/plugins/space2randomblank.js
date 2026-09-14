// 空格转随机空白字符（%09–%0D 或 %A0），绕过空格过滤
export const space2randomblank = {
  name: 'space2randomblank',
  description: '将空格替换为随机空白字符（%09–%0D 或 %A0）',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const blanks = ['%09','%0a','%0b','%0c','%0d','%a0'];
    return payload.replace(/ /g, () => blanks[Math.floor(Math.random() * blanks.length)]);
  },
};
export default space2randomblank;
