// C2 用：**沿用抓包时的时钟与 nonce**（防重放接口的典型失败方式）。
//
// 现实对应物：把 Burp 里那条请求连同 t/n/sign 一起抄进脚本，"照着发"。
// ⇒ 时钟窗（60s）一过，**连未注入的基线请求**都被拒 ⇒ 整轮一个合法请求都没送达。
// 这正是 `transform_rejected(kind='baseline')` 在防重放族上的形态
// （sign 族里由 sign-wrong-key.mjs 承担同一角色）。
//
// 刻意用一个**固定在过去**的时间戳而不是"发请求时再取当前时间"：
// 判据的成立条件（基线连续被拒 + 从未成功）必须与跑批时刻无关，否则套件会抖。
import { buildSign, TICK_KEY } from '../sign-scheme.mjs';

/** 2020-11-14，永远落在 60s 窗外 —— 让"过期"这件事变成确定性的 */
const STALE_T = '1605312000000';
const FIXED_N = 'deadbeefcafebabe';

export function transform(req) {
  const url = String(req.url || '');
  if (!url.includes('/api/tick')) return req;
  const u = new URL(url);
  u.searchParams.set('t', STALE_T);
  u.searchParams.set('n', FIXED_N);
  u.searchParams.set('sign', buildSign([...u.searchParams.entries()], TICK_KEY));
  return { url: u.toString() };
}
