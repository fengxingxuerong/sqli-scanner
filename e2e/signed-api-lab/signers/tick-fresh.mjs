// A3 用：防重放接口（`t` 时钟窗 + `n` 一次性 nonce + 三者参与的 sign）的正确脚本。
//
// 关键点在于**每条请求都要现算**：
//   · `t` 必须落在窗内（用发送时刻的 Date.now()，不是抓包时刻）；
//   · `n` 必须每条都换（服务端记住用过的 nonce，重复即拒 —— 重试/重放第二次就死了）；
//   · `sign` 必须覆盖改过的 t/n/id，三者任一变了都要重算。
// 这三件事是"抓包重放"与"能扫的扫描器"之间真正的分水岭：
// 抓来的报文几秒钟就过期，只有把算法交给脚本、由脚本在发送前一刻生成，才能持续扫完一轮。
import { buildSign, TICK_KEY } from '../sign-scheme.mjs';
import crypto from 'node:crypto';

export function transform(req) {
  const url = String(req.url || '');
  if (!url.includes('/api/tick')) return req;
  const u = new URL(url);
  u.searchParams.set('t', String(Date.now()));
  u.searchParams.set('n', crypto.randomBytes(8).toString('hex'));
  u.searchParams.set('sign', buildSign([...u.searchParams.entries()], TICK_KEY));
  return { url: u.toString() };
}
