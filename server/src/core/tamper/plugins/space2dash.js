// 空格 -> -- 后接随机十六进制 + %0A 换行终止（MySQL 行注释风格，对齐 sqlmap space2dash.py:48）
// 随机串避免相同 payload 被缓存命中；仅作用于空格位置，不改变关键字语义。
// [T5] %0A 终止必须有：否则第一个空格后整段 payload 被行注释吞掉，注入必然失效。
import { randomBytes } from 'crypto';

export const space2dash = {
  name: 'space2dash',
  description: '将空格替换为 -- 后接随机注释并以换行终止（MySQL 行注释风格，避免缓存）',
  doctests: [
    // 随机十六进制，用正则断言换行终止契约
    { input: 'a b', match: '^a--[0-9a-f]{6}%0Ab$' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/ /g, () => '--' + randomBytes(3).toString('hex') + '%0A');
  },
};

export default space2dash;
