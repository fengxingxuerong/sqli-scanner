// 空格 -> -- 后接随机十六进制（MySQL 行注释风格）
// 随机串避免相同 payload 被缓存命中；仅作用于空格位置，不改变关键字语义。
import { randomBytes } from 'crypto';

export const space2dash = {
  name: 'space2dash',
  description: '将空格替换为 -- 后接随机注释（MySQL 行注释风格，避免缓存）',
  transform(payload) {
    return payload.replace(/ /g, () => '--' + randomBytes(3).toString('hex'));
  },
};

export default space2dash;
