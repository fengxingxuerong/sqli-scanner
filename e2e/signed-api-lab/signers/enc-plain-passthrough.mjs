// B2 用：**漏覆盖加密字段**的脚本 —— 对 `/api/enc` 原样透传，不加密。
//
// 现实对应物：脚本只处理了顶层某个字段、或只加了 `sign` 忘了加密 body，
// 也可能是"密文字段换了名字没同步"。症状与 D 组不同：**基线仍然能过**
// （meta.enc 保持靶场初始的那份真密文，服务端解得开），
// 而每条被注入的请求都变成明文 ⇒ 服务端解不开 ⇒ 恒 400。
// ⇒ 这正是 `transform_rejected(kind='injection')` 在**加密族**上的形态
//   （sign 族里由 sign-partial-fields.mjs 承担同一角色，两者成因相同、写法不同）。
export function transform(req) {
  return req;
}
