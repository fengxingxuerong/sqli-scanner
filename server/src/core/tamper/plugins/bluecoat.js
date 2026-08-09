// BlueCoat ProxySG 风格：空格转 %09，等号转 LIKE（绕过等号关键字规则）
export const bluecoat = {
  name: 'bluecoat',
  description: '空格替换为 %09，等号 = 替换为 LIKE，绕过 BlueCoat 类规则',
  transform(payload) {
    return payload.replace(/ /g, '%09').replace(/=/g, ' LIKE ');
  },
};
export default bluecoat;
