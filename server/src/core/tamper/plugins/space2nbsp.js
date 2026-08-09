// 空格转非断空格（%A0），绕过空格过滤
export const space2nbsp = {
  name: 'space2nbsp',
  description: '将空格替换为非断空格 %a0，绕过空格过滤',
  transform(payload) {
    return payload.replace(/ /g, '%a0');
  },
};
export default space2nbsp;
