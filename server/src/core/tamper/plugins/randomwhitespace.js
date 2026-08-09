// 空格替换为随机空白字符（tab/newline/form-feed/cr/vertical-tab 轮换）
// 说明：sqlmap 原版用随机，本实现用确定性轮换以保证可测；绕过空格过滤的核心目的不变。
const POOL = ['%09', '%0a', '%0c', '%0d', '%0b'];

export const randomwhitespace = {
  name: 'randomwhitespace',
  description: '将空格替换为空白字符序列（%09/%0a/%0c/%0d/%0b 轮换），绕过空格过滤',
  transform(payload) {
    let i = 0;
    return payload.replace(/ /g, () => POOL[i++ % POOL.length]);
  },
};

export default randomwhitespace;
