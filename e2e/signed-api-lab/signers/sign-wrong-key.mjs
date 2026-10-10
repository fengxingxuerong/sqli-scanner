// 场景 C 用：**密钥错**的签名脚本 —— 字段集与算法都对，唯独密钥不对。
//
// ⇒ 连**未注入的基线请求**都被目标判非法（恒 400）。这就是
//   `transform_rejected(kind='baseline')` 的形态：不是「这个参数没洞」，
//   而是「我们发的每一个请求都没被当成合法请求」⇒ 整轮结论作废，且应当**早停**
//   （后面每一条必然同样被拒，继续跑只是白烧请求预算）。
//
// 现实对应物：从测试环境拷了签名密钥上线到生产目标、或者密钥轮换后忘了同步 SDK。
import { buildSign, paramsOf } from '../sign-scheme.mjs';

export function transform(req) {
  const url = String(req.url || '');
  if (!url.includes('/api/')) return req;
  const u = new URL(url);
  // 唯一区别：密钥用错的（字段集与算法与正确脚本逐字相同）
  u.searchParams.set('sign', buildSign(paramsOf(url), 'wrong-key-from-staging'));
  return { url: u.toString() };
}
