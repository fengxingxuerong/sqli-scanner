// 场景 B 用：**字段集算错**的签名脚本 —— 现实里最常见的一类「脚本配好了但没全覆盖」。
//
// 失效形态（照抄真实项目里会犯的那个错）：SDK 拿着**它自己那份参数副本**算签，
// 而扫描器改的是 URL 上的 `id`，副本里仍是抓包时那条 `id=1`。
// ⇒ 基线（id 没被改）签名正确、目标放行；一旦 id 被换成 payload（=每条注入请求），
//   目标按「真实参数集」验签就失配 ⇒ 恒 400。
// 这正是 `transform_rejected(kind='injection')` 要抓的形状：基线正常而注入全被拒。
//
// ⚠ 与 `sign-wrong-key.mjs` 的区别是**故意的**：那一支连基线都拒（脚本整体不对），
//   这一支基线过、只有注入被拒（脚本覆盖不全）—— 两种成因的处置完全不同，
//   所以判据必须能分开，靶场也必须能分别造出来。
import { buildSign } from '../sign-scheme.mjs';

/** 抓包那一刻的参数副本（漏了「注入会改哪个字段」这件事） */
const CAPTURED = [['id', '1'], ['t', '1']];

export function transform(req) {
  const url = String(req.url || '');
  if (!url.includes('/api/')) return req;
  const u = new URL(url);
  u.searchParams.set('sign', buildSign(CAPTURED));
  return { url: u.toString() };
}
