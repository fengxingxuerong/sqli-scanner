// ============================================================================
// enc-scheme.mjs —— signed-api-lab 的「整包字段级加密」方案（靶站与脚本共用）
//
// 覆盖 D32 留的第二族症状（TODO「D32 剩下的账」第 7 条）：
//   请求体是 `{"head":{...},"body":{"data":"<base64(AES-CBC(明文))>"}}`，
//   服务端**先解密 `meta.enc` 再把它拼进 SQL**。扫描器看到的是一个字符串叶子，
//   把 payload 明文写进去 ⇒ 服务端解不开 ⇒ 400 ⇒ 报告「未检出」。
//   这类目标在真实项目里通常配一句"前端 CryptoJS 加密了，扫描器没法测"，
//   而它其实只需要在发送前一刻把那个叶子加密回去 —— 这正是请求变换扩展点的用途。
//
// 与 sign-scheme.mjs 同一条纪律：**靶站验的与脚本产的是同一份代码**，
// 否则改一处算法就会让 A2 场景红得与能力无关。
// 密钥/IV 刻意写死并入库：这是靶场；真项目的密钥绝不该出现在仓库或对话记录里。
// ============================================================================
import crypto from 'node:crypto';

const KEY = Buffer.from('0123456789abcdef', 'utf8'); // AES-128
const IV = Buffer.from('fedcba9876543210', 'utf8'); // 固定 IV（很多老前端就是这么干的）

/** 明文 → base64 密文 */
export function encryptString(plain) {
  const c = crypto.createCipheriv('aes-128-cbc', KEY, IV);
  return Buffer.concat([c.update(String(plain), 'utf8'), c.final()]).toString('base64');
}

/**
 * base64 密文 → 明文。解不开一律返回 null（靶站照此回 400）。
 *
 * ⚠️ **必须严格**，这一条是实测换来的：Node 的 `Buffer.from(x,'base64')` 会
 *   **静默忽略非法字符**，而扫描器在字符串叶子上的动作是"在原值后追加 SQL 片段"
 *   （报文实测：`"yRCH…==" → "yRCH…=='" / "yRCH…== AND 1=1-- -"`）。
 *   宽松解码下这些全都还原成同一份 16 字节 ⇒ 服务端解出 '1' ⇒
 *   注入被靶站"吃掉了"：0 次解密失败、76 条请求全以明文 1 抵达 SQL、检出 0。
 *   看着像"引擎对这个目标无能为力"，实际是靶站不像真目标 —— 真实后端要么严格解码、
 *   要么密文长度/分块直接错。校验取三重：字符集、4 字节对齐、**解码后再编码必须等于原串**。
 * @returns {string|null}
 */
const B64_CANONICAL = /^[A-Za-z0-9+/]*={0,2}$/;
export function decryptString(b64) {
  const s = String(b64 ?? '');
  // 空串 / 非规范 base64（含空格、引号、`-`、`_` 之外的任何越界字符）⇒ 直接判"不是密文"
  if (!s || !B64_CANONICAL.test(s) || s.length % 4 !== 0) return null;
  let buf;
  try {
    buf = Buffer.from(s, 'base64');
  } catch {
    return null;
  }
  // 往返一致才算规范密文（挡掉 "AAAA==" 这类解码后再编码变短的同形串）
  if (buf.toString('base64') !== s) return null;
  if (buf.length < 16 || buf.length % 16 !== 0) return null; // AES-CBC 密文必为整块
  try {
    const d = crypto.createDecipheriv('aes-128-cbc', KEY, IV);
    return Buffer.concat([d.update(buf), d.final()]).toString('utf8');
  } catch {
    return null; // padding 坏 ⇒ 不是本方案产出的密文
  }
}
