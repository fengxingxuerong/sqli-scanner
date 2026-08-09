import { tamperRegistry } from './TamperRegistry.js';
import { obfuscatePayload } from '../../engine/payloads.js';
// 导入内置插件（副作用：下方 registerMany 注册到单例）
import { space2comment } from './plugins/space2comment.js';
import { randomcase } from './plugins/randomcase.js';
import { charencode } from './plugins/charencode.js';
import { equaltolike } from './plugins/equaltolike.js';
import { keywordSplit } from './plugins/keywordSplit.js';
import { comments } from './plugins/comments.js';
import { base64encode } from './plugins/base64encode.js';
// v3 新增高频 WAF 绕过插件（覆盖 sqlmap 常见 tamper 的子集）
import { space2plus } from './plugins/space2plus.js';
import { space2dash } from './plugins/space2dash.js';
import { multiplespaces } from './plugins/multiplespaces.js';
import { versionedkeywords } from './plugins/versionedkeywords.js';
import { charunicodeencode } from './plugins/charunicodeencode.js';
import { nonrecursivereplace } from './plugins/nonrecursivereplace.js';
import { lowercase } from './plugins/lowercase.js';
import { uppercase } from './plugins/uppercase.js';
import { percentage } from './plugins/percentage.js';
// v7 新增高频 WAF 绕过插件（扩展 sqlmap 常见 tamper 子集 16 → 28）
import { between } from './plugins/between.js';
import { greatest } from './plugins/greatest.js';
import { least } from './plugins/least.js';
import { ifnull2ifisnull } from './plugins/ifnull2ifisnull.js';
import { versionedmorekeywords } from './plugins/versionedmorekeywords.js';
import { halfversionedmorekeywords } from './plugins/halfversionedmorekeywords.js';
import { modsecurityversioned } from './plugins/modsecurityversioned.js';
import { modsecurityzeroversioned } from './plugins/modsecurityzeroversioned.js';
import { chardoubleencode } from './plugins/chardoubleencode.js';
import { unmagicquotes } from './plugins/unmagicquotes.js';
import { appendnullbyte } from './plugins/appendnullbyte.js';
import { randomwhitespace } from './plugins/randomwhitespace.js';
// v9 新增 34 个 WAF 绕过插件（覆盖 sqlmap 常见 tamper 剩余子集，内置总数 28 → 62）
import { apostrophemask } from './plugins/apostrophemask.js';
import { apostrophenullencode } from './plugins/apostrophenullencode.js';
import { apostrophe2char } from './plugins/apostrophe2char.js';
import { bluecoat } from './plugins/bluecoat.js';
import { commentbeforewhitespace } from './plugins/commentbeforewhitespace.js';
import { commentafterwhitespace } from './plugins/commentafterwhitespace.js';
import { concat2concatws } from './plugins/concat2concatws.js';
import { commalesslimit } from './plugins/commalesslimit.js';
import { commalessmid } from './plugins/commalessmid.js';
import { escapequotes } from './plugins/escapequotes.js';
import { htmlencode } from './plugins/htmlencode.js';
import { ifnull2casewhenisnull } from './plugins/ifnull2casewhenisnull.js';
import { informationschemacomment } from './plugins/informationschemacomment.js';
import { overlongutf8 } from './plugins/overlongutf8.js';
import { quote2hex } from './plugins/quote2hex.js';
import { randomcomments } from './plugins/randomcomments.js';
import { securesphere } from './plugins/securesphere.js';
import { sp_password } from './plugins/sp_password.js';
import { space2hash } from './plugins/space2hash.js';
import { space2morecomment } from './plugins/space2morecomment.js';
import { space2mssqlblank } from './plugins/space2mssqlblank.js';
import { space2mssqlhash } from './plugins/space2mssqlhash.js';
import { space2mysqlblank } from './plugins/space2mysqlblank.js';
import { space2mysqldash } from './plugins/space2mysqldash.js';
import { space2randomblank } from './plugins/space2randomblank.js';
import { space2nbsp } from './plugins/space2nbsp.js';
import { space2blank } from './plugins/space2blank.js';
import { symboliclogical } from './plugins/symboliclogical.js';
import { unionalltounion } from './plugins/unionalltounion.js';
import { misunion } from './plugins/misunion.js';
import { sleep2delay } from './plugins/sleep2delay.js';
import { sleep2pg } from './plugins/sleep2pg.js';
import { tab2comment } from './plugins/tab2comment.js';
import { zeroversioned } from './plugins/zeroversioned.js';
// v10 新增 2 个 WAF 绕过插件（补齐 sqlmap 剩余子集，内置总数 62 → 64）
import { hex2char } from './plugins/hex2char.js';
import { charunicodeasciiencode } from './plugins/charunicodeasciiencode.js';

// 导入即注册内置插件（幂等：重复导入不会重复注册，Map 以 name 去重）
tamperRegistry.registerMany([
  space2comment,
  randomcase,
  charencode,
  equaltolike,
  keywordSplit,
  comments,
  base64encode,
  // v3 新增
  space2plus,
  space2dash,
  multiplespaces,
  versionedkeywords,
  charunicodeencode,
  nonrecursivereplace,
  lowercase,
  uppercase,
  percentage,
  // v7 新增
  between,
  greatest,
  least,
  ifnull2ifisnull,
  versionedmorekeywords,
  halfversionedmorekeywords,
  modsecurityversioned,
  modsecurityzeroversioned,
  chardoubleencode,
  unmagicquotes,
  appendnullbyte,
  randomwhitespace,
  // v9 新增
  apostrophemask,
  apostrophenullencode,
  apostrophe2char,
  bluecoat,
  commentbeforewhitespace,
  commentafterwhitespace,
  concat2concatws,
  commalesslimit,
  commalessmid,
  escapequotes,
  htmlencode,
  ifnull2casewhenisnull,
  informationschemacomment,
  overlongutf8,
  quote2hex,
  randomcomments,
  securesphere,
  sp_password,
  space2hash,
  space2morecomment,
  space2mssqlblank,
  space2mssqlhash,
  space2mysqlblank,
  space2mysqldash,
  space2randomblank,
  space2nbsp,
  space2blank,
  symboliclogical,
  unionalltounion,
  misunion,
  sleep2delay,
  sleep2pg,
  tab2comment,
  zeroversioned,
  // v10 新增
  hex2char,
  charunicodeasciiencode,
]);

/**
 * 链式执行 tamper 插件：前一个输出作为下一个输入。
 * @param {string} payload 待混淆的注入串
 * @param {object} ctx 检测上下文 { httpClient, target, point, dbms, config }
 * @param {string[]} pluginNames 按序排列的插件名（对应 config.wafEvasion.tamper.plugins）
 * @returns {string} 转换后的串
 */
export function applyTampers(payload, ctx, pluginNames = []) {
  const plugins = tamperRegistry.resolve(pluginNames || []);
  let out = payload;
  for (const p of plugins) {
    out = p.transform(out, ctx);
  }
  return out;
}

/**
 * 统一混淆钩子：Detector / injection / Extractor 三处均改调此函数。
 * 优先级：
 *   1) config.wafEvasion.tamper.enabled → 链式 applyTampers（新体系）
 *   2) config.wafEvasion.obfuscate(legacy) → 原 obfuscatePayload（向后兼容现状）
 *   3) 均未开 → 原样返回（与现状一致）
 * 向后兼容保证：tamper 关闭且 obfuscate 关闭时，返回值恒等于入参。
 * @param {string} value 已填充的注入值
 * @param {object} ctx 检测上下文（含 config.wafEvasion）
 * @returns {string}
 */
export function obfuscateWithConfig(value, ctx) {
  const config = (ctx && ctx.config) || {};
  const we = config.wafEvasion || {};

  // 1) tamper 链式优先
  if (we.tamper && we.tamper.enabled) {
    const plugins = we.tamper.plugins || [];
    return applyTampers(value, ctx, plugins);
  }
  // 2) legacy 单混淆
  if (we.obfuscate) {
    return obfuscatePayload(value);
  }
  // 3) 原样
  return value;
}

export default obfuscateWithConfig;
