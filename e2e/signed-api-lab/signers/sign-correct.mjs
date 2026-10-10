// 场景 A 用：与靶站同一套方案、对**当前真实参数集**签名（正确实现）。
// 这是「SDK 在发出前一刻算签」的正常形态 —— 扫描器改完 id 之后，签名叫本脚本重算，
// 于是注入请求在目标眼里与浏览器发出的等价 ⇒ 注入真的抵达 SQL。
import { buildSign, paramsOf } from '../sign-scheme.mjs';

export function transform(req) {
  const url = String(req.url || '');
  // 只给业务接口签名；其它路径（保活页/取页）原样放行，省得把靶站计数搅浑
  if (!url.includes('/api/')) return req;
  const u = new URL(url);
  u.searchParams.set('sign', buildSign(paramsOf(url)));
  return { url: u.toString() };
}
