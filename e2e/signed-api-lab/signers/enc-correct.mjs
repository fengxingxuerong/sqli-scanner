// A2 用：把 `meta.enc` 叶子**加密回去**（整包字段级加密接口的正确脚本）。
//
// 引擎在发送前已经把明文 payload 写进了这个叶子（它是 JSON 里唯一的字符串叶子），
// 本脚本只做一件事：读出来、加密、放回原位。服务端解得开 ⇒ 注入真的抵达 SQL 拼接点。
//
// 只对 /api/enc 生效，其它请求原样放行 —— 一个签名/加密脚本被挂在整条扫描链上时，
// 它对非目标接口必须是无副作用的（否则会破坏保活页/取页这些不该被改写的请求）。
import { encryptString, decryptString } from '../enc-scheme.mjs';

export function transform(req) {
  const url = String(req.url || '');
  if (!url.includes('/api/enc')) return req;
  const raw = typeof req.data === 'string' ? req.data : '';
  if (!raw) return req;
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch {
    return req; // 不是 JSON（例如表单点）⇒ 不改写，让原请求照常出去
  }
  if (!obj || typeof obj !== 'object' || !obj.meta || typeof obj.meta.enc !== 'string') return req;
  // ⚠ 幂等：已经是合法密文就**别再加密**。
  // 第一版无条件 encryptString(...)，于是"未改动的基线"（body.data 仍是抓包那份密文）
  // 被二次加密 ⇒ 服务端解出来的明文是那段 base64 ⇒ 拼进 SQL 是语法错。
  // 后果不是"报错"，而是**静默地把 B2 那种漏覆盖场景也洗成"抵达 SQL"**：
  // reachedPayload 一度实测 100/100（连基线都算注入），指标当场失真。
  // 真实 SDK 不会有这个问题（它加密的一直是自己那份明文副本），但脚本挂在扫描链上
  // 面对的是"混合了明文与密文"的流量，所以判一下才是诚实实现。
  if (decryptString(obj.meta.enc) === null) {
    obj.meta.enc = encryptString(obj.meta.enc);
    return { data: JSON.stringify(obj) };
  }
  return req;
}
