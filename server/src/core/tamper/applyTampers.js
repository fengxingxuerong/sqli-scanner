import { tamperRegistry } from './TamperRegistry.js';
import { obfuscatePayload } from './obfuscate.js';
import { logger } from '../logger.js';
// 导入内置插件（副作用：下方 registerMany 注册到单例）
import { space2comment } from './plugins/space2comment.js';
import { randomcase } from './plugins/randomcase.js';
import { charencode } from './plugins/charencode.js';
import { equaltolike } from './plugins/equaltolike.js';
import { keywordSplit } from './plugins/keywordSplit.js';
import { hexliterals } from './plugins/hexliterals.js';
import { comments } from './plugins/comments.js';
import { base64encode } from './plugins/base64encode.js';
// v3 新增高频 WAF 绕过插件（覆盖 sqlmap 常见 tamper 的子集）
import { space2plus } from './plugins/space2plus.js';
import { space2dash } from './plugins/space2dash.js';
import { multiplespaces } from './plugins/multiplespaces.js';
import { versionedkeywords } from './plugins/versionedkeywords.js';
import { charunicodeencode } from './plugins/charunicodeencode.js';
import { nonrecursivereplace } from './plugins/nonrecursivereplace.js';
import { keywordinterleave } from './plugins/keywordinterleave.js';
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
// v11 新增 14 个 WAF 绕过插件（对标 sqlmap 官方 tamper，内置总数 62 → 76）
import { xforwardedfor } from './plugins/xforwardedfor.js';
import { varnish } from './plugins/varnish.js';
import { charunicodeescape } from './plugins/charunicodeescape.js';
import { hexentities } from './plugins/hexentities.js';
import { hex2char } from './plugins/hex2char.js';
import { decentities } from './plugins/decentities.js';
import { if2case } from './plugins/if2case.js';
import { plus2concat } from './plugins/plus2concat.js';
import { plus2fnconcat } from './plugins/plus2fnconcat.js';
import { equaltorlike } from './plugins/equaltorlike.js';
import { eunion } from './plugins/0eunion.js';
import { dunion } from './plugins/dunion.js';
import { schemasplit } from './plugins/schemasplit.js';
import { space2morehash } from './plugins/space2morehash.js';
// v12 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 76 → 88）
import { backslash2forward } from './plugins/backslash2forward.js';
import { binary } from './plugins/binary.js';
import { commentbeforeparentheses } from './plugins/commentbeforeparentheses.js';
import { concat2ws } from './plugins/concat2ws.js';
import { css } from './plugins/css.js';
import { dbase64encode } from './plugins/dbase64encode.js';
import { decimal2char } from './plugins/decimal2char.js';
import { delimit } from './plugins/delimit.js';
import { djson } from './plugins/djson.js';
import { dmultiline } from './plugins/dmultiline.js';
import { json } from './plugins/json.js';
import { jsonescape } from './plugins/jsonescape.js';
import { space2span } from './plugins/space2span.js';
import { union2no } from './plugins/union2no.js';
// v13 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 90 → 102）
import { noequals } from './plugins/noequals.js';
import { arges } from './plugins/arges.js';
import { char2ascii } from './plugins/char2ascii.js';
import { substring2left } from './plugins/substring2left.js';
import { substring2mid } from './plugins/substring2mid.js';
import { lpad } from './plugins/lpad.js';
import { xml2json } from './plugins/xml2json.js';
import { nconcatenation } from './plugins/nconcatenation.js';
import { hardindex } from './plugins/hardindex.js';
import { postpon } from './plugins/postpon.js';
import { sap } from './plugins/sap.js';
import { lad } from './plugins/lad.js';
// v14 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 102 → 114）
import { agent } from './plugins/agent.js';
import { base64decode } from './plugins/base64decode.js';
import { dconcat } from './plugins/dconcat.js';
import { dpayload } from './plugins/dpayload.js';
import { gzip } from './plugins/gzip.js';
import { compression } from './plugins/compression.js';
import { lax2xml } from './plugins/lax2xml.js';
import { xpath2json } from './plugins/xpath2json.js';
import { aspdelivery } from './plugins/aspdelivery.js';
import { dhs } from './plugins/dhs.js';
import { coffee } from './plugins/coffee.js';
import { accessfilter } from './plugins/accessfilter.js';
// v15 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 114 → 126）
import { aspjetty } from './plugins/aspjetty.js';
import { hex2ascii } from './plugins/hex2ascii.js';
import { octalencode } from './plugins/octalencode.js';
import { randomunion } from './plugins/randomunion.js';
import { tab2space } from './plugins/tab2space.js';
import { nullencode } from './plugins/nullencode.js';
import { doubleencode } from './plugins/doubleencode.js';
import { mixedcase } from './plugins/mixedcase.js';
import { newline2space } from './plugins/newline2space.js';
import { squiggle } from './plugins/squiggle.js';
import { scientific } from './plugins/scientific.js';
import { reversestring } from './plugins/reversestring.js';
// v16 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 126 → 138）
import { brotli } from './plugins/brotli.js';
import { hex2dec } from './plugins/hex2dec.js';
import { bin2ascii } from './plugins/bin2ascii.js';
import { randomorder } from './plugins/randomorder.js';
import { space2newline } from './plugins/space2newline.js';
import { space2carriage } from './plugins/space2carriage.js';
import { comment2space } from './plugins/comment2space.js';
import { keyword2hex } from './plugins/keyword2hex.js';
import { char2hex } from './plugins/char2hex.js';
import { swapcase } from './plugins/swapcase.js';
import { randomascii } from './plugins/randomascii.js';
import { floatencode } from './plugins/floatencode.js';
// v17 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 138 → 150）
import { caesar } from './plugins/caesar.js';
import { rot13 } from './plugins/rot13.js';
import { xor } from './plugins/xor.js';
import { atbash } from './plugins/atbash.js';
import { vigenere } from './plugins/vigenere.js';
import { space2backslash } from './plugins/space2backslash.js';
import { space2tilda } from './plugins/space2tilda.js';
import { space2dot } from './plugins/space2dot.js';
import { space2comma } from './plugins/space2comma.js';
import { space2underscore } from './plugins/space2underscore.js';
import { space2pipe } from './plugins/space2pipe.js';
import { space2slash } from './plugins/space2slash.js';
// v18 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 150 → 162）
import { hex2bin } from './plugins/hex2bin.js';
import { oct2hex } from './plugins/oct2hex.js';
import { dec2hex } from './plugins/dec2hex.js';
import { bin2hex } from './plugins/bin2hex.js';
import { space2paren } from './plugins/space2paren.js';
import { space2excl } from './plugins/space2excl.js';
import { space2quest } from './plugins/space2quest.js';
import { space2at } from './plugins/space2at.js';
import { space2dollar } from './plugins/space2dollar.js';
import { space2percent } from './plugins/space2percent.js';
import { space2caret } from './plugins/space2caret.js';
import { space2ampersand } from './plugins/space2ampersand.js';
// v19 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 162 → 174）
import { space2colon } from './plugins/space2colon.js';
import { space2semicolon } from './plugins/space2semicolon.js';
import { space2lt } from './plugins/space2lt.js';
import { space2gt } from './plugins/space2gt.js';
import { space2brace } from './plugins/space2brace.js';
import { space2bracket } from './plugins/space2bracket.js';
import { space2asterisk } from './plugins/space2asterisk.js';
import { space2equal } from './plugins/space2equal.js';
import { concat2hex } from './plugins/concat2hex.js';
import { keyword2unicode } from './plugins/keyword2unicode.js';
import { randomdigit } from './plugins/randomdigit.js';
import { str2hex } from './plugins/str2hex.js';
// v20 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 174 → 186）
import { comment2dash } from './plugins/comment2dash.js';
import { newline2comment } from './plugins/newline2comment.js';
import { encode2hex } from './plugins/encode2hex.js';
import { encode2dec } from './plugins/encode2dec.js';
import { encode2oct } from './plugins/encode2oct.js';
import { randomboundary } from './plugins/randomboundary.js';
import { randomcaseall } from './plugins/randomcaseall.js';
import { space2sqlcomment } from './plugins/space2sqlcomment.js';
import { space2blockcomment } from './plugins/space2blockcomment.js';
import { keyword2hexall } from './plugins/keyword2hexall.js';
import { string2hexall } from './plugins/string2hexall.js';
import { space2eolcomment } from './plugins/space2eolcomment.js';
// v21 新增 14 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 186 → 200）
import { space2any } from './plugins/space2any.js';
import { space2letter } from './plugins/space2letter.js';
import { keyword2binary } from './plugins/keyword2binary.js';
import { keyword2octal } from './plugins/keyword2octal.js';
import { keyword2decimal } from './plugins/keyword2decimal.js';
import { string2binary } from './plugins/string2binary.js';
import { string2octal } from './plugins/string2octal.js';
import { string2decimal } from './plugins/string2decimal.js';
import { space2unicode } from './plugins/space2unicode.js';
import { space2widechar } from './plugins/space2widechar.js';
import { nonempty } from './plugins/nonempty.js';
import { unparen } from './plugins/unparen.js';
import { unhtmlencode } from './plugins/unhtmlencode.js';
import { num2hex } from './plugins/num2hex.js';
// v22 新增 WAF 绕过插件 — 国内 WAF 专杀（360、安全狗、云锁）
import { _360waf } from './plugins/_360waf.js';
import { safedog } from './plugins/safedog.js';
import { yundun } from './plugins/yundun.js';
// v23 新增 WAF 绕过插件 — 补齐 sqlmap 高频 tamper 剩余缺口（modsecurityversionedkeywords / halfversionedmysql）
import { modsecurityversionedkeywords } from './plugins/modsecurityversionedkeywords.js';
import { halfversionedmysql } from './plugins/halfversionedmysql.js';
// v24 新增 20 个 WAF 绕过插件 — 补齐 sqlmap 官方 tamper 全集（205 → 225）
import { blindbinary } from './plugins/blindbinary.js';
import { castprefix } from './plugins/castprefix.js';
import { dollarquote } from './plugins/dollarquote.js';
import { ord2ascii } from './plugins/ord2ascii.js';
import { overlongutf8more } from './plugins/overlongutf8more.js';
import { quote2ltat } from './plugins/quote2ltat.js';
import { sign } from './plugins/sign.js';
import { infoschema2innodb } from './plugins/infoschema2innodb.js';
import { mssqlnosemicolon } from './plugins/mssqlnosemicolon.js';
import { odbcbrace } from './plugins/odbcbrace.js';
import { oraclequote } from './plugins/oraclequote.js';
import { luanginx } from './plugins/luanginx.js';
import { luanginxmore } from './plugins/luanginxmore.js';
import { mid2leftright } from './plugins/mid2leftright.js';
import { substring2leftright } from './plugins/substring2leftright.js';
import { sleep2getlock } from './plugins/sleep2getlock.js';
import { sleep2hex } from './plugins/sleep2hex.js';
import { uniontable } from './plugins/uniontable.js';
import { unionvalues } from './plugins/unionvalues.js';
import { unionvaluesrow } from './plugins/unionvaluesrow.js';
import { dash2hash } from './plugins/dash2hash.js';

// 导入即注册内置插件（幂等：重复导入不会重复注册，Map 以 name 去重）
tamperRegistry.registerMany([
  space2comment,
  randomcase,
  charencode,
  equaltolike,
  keywordSplit,
  // CRS v4 针对性变体（2026-09-09 CRS v4.1.0 全量 228 插件静态扫描 + 动态 A/B 产出）
  // 经实测淘汰两个变体，勿回退：
  //   · mysqlversioncomment（/*!50000KW*/）→ CRS 942500 专为此形态设规则，反而多命中一条
  //   · logicalops（AND→&&）→ 与 symboliclogical 完全重复，且 942120 直接检测 && / ||
  hexliterals,
  comments,
  base64encode,
  // v3 新增
  space2plus,
  space2dash,
  multiplespaces,
  versionedkeywords,
  charunicodeencode,
  nonrecursivereplace,
  // [P1-FIX 2026-09-10 实战实测] 插入式双写：ANDAND 只能扛「删一次」的过滤，
  // 全局删除型（replace(/and/gi,'')）需 ANANDD；两种下插入式都成立，故为严格更优解
  keywordinterleave,
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
  // v11 新增
  xforwardedfor,
  varnish,
  charunicodeescape,
  hexentities,
  hex2char,
  decentities,
  if2case,
  plus2concat,
  plus2fnconcat,
  equaltorlike,
  eunion,
  dunion,
  schemasplit,
  space2morehash,
  // v12 新增 14 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 76 → 90）
  backslash2forward,
  binary,
  commentbeforeparentheses,
  concat2ws,
  css,
  dbase64encode,
  decimal2char,
  delimit,
  djson,
  dmultiline,
  json,
  jsonescape,
  space2span,
  union2no,
  // v13 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 90 → 102）
  noequals,
  arges,
  char2ascii,
  substring2left,
  substring2mid,
  lpad,
  xml2json,
  nconcatenation,
  hardindex,
  postpon,
  sap,
  lad,
  // v14 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 102 → 114）
  agent,
  base64decode,
  dconcat,
  dpayload,
  gzip,
  compression,
  lax2xml,
  xpath2json,
  aspdelivery,
  dhs,
  coffee,
  accessfilter,
  // v15 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 114 → 126）
  aspjetty,
  hex2ascii,
  octalencode,
  randomunion,
  tab2space,
  nullencode,
  doubleencode,
  mixedcase,
  newline2space,
  squiggle,
  scientific,
  reversestring,
  // v16 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 126 → 138）
  brotli,
  hex2dec,
  bin2ascii,
  randomorder,
  space2newline,
  space2carriage,
  comment2space,
  keyword2hex,
  char2hex,
  swapcase,
  randomascii,
  floatencode,
  // v17 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 138 → 150）
  caesar,
  rot13,
  xor,
  atbash,
  vigenere,
  space2backslash,
  space2tilda,
  space2dot,
  space2comma,
  space2underscore,
  space2pipe,
  space2slash,
  // v18 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 150 → 162）
  hex2bin,
  oct2hex,
  dec2hex,
  bin2hex,
  space2paren,
  space2excl,
  space2quest,
  space2at,
  space2dollar,
  space2percent,
  space2caret,
  space2ampersand,
  // v19 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 162 → 174）
  space2colon,
  space2semicolon,
  space2lt,
  space2gt,
  space2brace,
  space2bracket,
  space2asterisk,
  space2equal,
  concat2hex,
  keyword2unicode,
  randomdigit,
  str2hex,
  // v20 新增 12 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 174 → 186）
  comment2dash,
  newline2comment,
  encode2hex,
  encode2dec,
  encode2oct,
  randomboundary,
  randomcaseall,
  space2sqlcomment,
  space2blockcomment,
  keyword2hexall,
  string2hexall,
  space2eolcomment,
  // v21 新增 14 个 WAF 绕过插件（对标 sqlmap 更多高频 tamper，内置总数 186 → 200）
  space2any,
  space2letter,
  keyword2binary,
  keyword2octal,
  keyword2decimal,
  string2binary,
  string2octal,
  string2decimal,
  space2unicode,
  space2widechar,
  nonempty,
  unparen,
  unhtmlencode,
  num2hex,
  // v22 新增 — 国内 WAF 专杀
  _360waf,
  safedog,
  yundun,
  // v23 新增 — 补齐 sqlmap 高频 tamper 剩余缺口
  modsecurityversionedkeywords,
  halfversionedmysql,
  // v24 新增 — 补齐 sqlmap 官方 tamper 全集
  blindbinary,
  castprefix,
  dollarquote,
  ord2ascii,
  overlongutf8more,
  quote2ltat,
  sign,
  infoschema2innodb,
  mssqlnosemicolon,
  odbcbrace,
  oraclequote,
  luanginx,
  luanginxmore,
  mid2leftright,
  substring2leftright,
  sleep2getlock,
  sleep2hex,
  uniontable,
  unionvalues,
  unionvaluesrow,
  dash2hash,
]);

/**
 * 需要保护的提取标记模式：
 *   __S__ / __E__     — Extractor 标量提取标记
 *   SQLISCANNER<N>    — injection.js UNION 列探测标记
 * 这些标记被 tamper 变换后，引擎在响应中无法匹配 → UNION 漏检 / 数据提取失败。
 */
const _MARKER_RE = /__S__|__E__|SQLISCANNER\d+/g;

/**
 * 纯数字占位符前缀（不与 NUM_MARKER_BASE_A=7331000 冲突）。
 * 数字不被 charunicodeencode / htmlencode / charencode / lowercase / uppercase 编码，
 * 因此占位符在大多数编码类 tamper 下能存活，执行后可被还原。
 */
const _PH_PREFIX = '7331999';
// [T8] 数字边界锚点：payload 自带 1733199901 之类长数字时，
// 无锚点会把其中 `7331999901` 的 `7331999`+`901` 误认为占位符还原 → 破坏 payload。
const _PH_RE = /(?<!\d)7331999(\d{3})(?!\d)/g;
// [P0-FIX 2026-09-05] 宽松还原：无边界锚点，仅在严格锚定还原计数不足时启用。
// 场景：编码类 tamper 把占位符相邻字符编成以数字结尾的形式（如 x → %u0078），
// 数字粘连使 (?<!\d) 失配 → 严格一遍漏还原 → 走回退分支导致标记被编码破坏。
// 宽松版通过索引合法性（idx < placeholders.length）约束误还原面。
const _PH_LENIENT_RE = /7331999(\d{3})/g;

function _runChain(input, plugins, ctx) {
  let out = input;
  for (const p of plugins) {
    // [T7] 单插件异常隔离：tamper 崩溃原被 Extractor._send 吞成 null，
    // 会被静默误判为检测阴性 → 此处告警并跳过该插件，链上其余插件照常执行。
    try {
      out = p.transform(out, ctx);
    } catch (e) {
      try {
        logger.warn(`[tamper] 插件 ${p.name} 执行异常，已跳过：${e.message}`);
      } catch { /* logger 不可用时静默跳过 */ }
    }
  }
  return out;
}

/**
 * 链式执行 tamper 插件：前一个输出作为下一个输入。
 *
 * ★FIX [P0]：占位暂存还原——防止编码类 tamper 破坏提取标记。
 *
 * 策略：
 *   1. 用纯数字占位符替换 payload 中的 __S__/__E__/SQLISCANNER<N> 标记；
 *   2. 执行 tamper 链（占位符是纯数字，不被 charunicodeencode/htmlencode/
 *      charencode/lowercase/uppercase 等编码类 tamper 变换）；
 *   3. 还原占位符为原始标记；
 *   4. 如果占位符被某个 tamper 编码（如 char2hex 在引号内编码数字）导致
 *      还原失败，回退到不保护标记的版本重新执行 tamper 链——确保不会
 *      比不保护更糟。
 *
 * @param {string} payload 待混淆的注入串
 * @param {object} ctx 检测上下文 { httpClient, target, point, dbms, config }
 * @param {string[]} pluginNames 按序排列的插件名（对应 config.wafEvasion.tamper.plugins）
 * @returns {string} 转换后的串
 */
export function applyTampers(payload, ctx, pluginNames = []) {
  // [P1-FIX 2026-09-05] resolve 透传 ctx：消费插件元数据（dbms 限定告警 / terminal 截断）
  const plugins = tamperRegistry.resolve(pluginNames || [], ctx || {});
  if (plugins.length === 0) return payload;

  // [CRS-FIX 2026-09-09] markerSafe 通道
  // 占位保护是"防止编码类 tamper 破坏提取标记"的兜底，但它同时挡住了**语义等价**的标记变形：
  // 'SQLISCANNER0' → 0x53514c49... 回显完全一致，却因占位符是纯数字而永远无法被变形。
  // 代价是实的：CRS 942511/942200 以「引号」为锚点，UNION 列探测在 CRS 下 100% 被拦
  // （waf-real 动态实测 5 场景 union 检出 0，全靠 boolean 兜底）。
  // 故为插件提供 markerSafe 声明：变换对标记语义无损时整链跳过占位保护。
  // 保守策略：仅当链上**全部**插件都声明 markerSafe 才走无保护通道，混合链仍走既有保护逻辑。
  if (plugins.every((p) => p.markerSafe === true)) return _runChain(payload, plugins, ctx);

  // --- 占位暂存 ---
  const placeholders = [];
  const protectedPayload = String(payload).replace(_MARKER_RE, (m) => {
    const idx = placeholders.length;
    placeholders.push(m);
    return `${_PH_PREFIX}${String(idx).padStart(3, '0')}`;
  });

  // 无标记 → 直接执行（无需保护）
  if (placeholders.length === 0) {
    return _runChain(payload, plugins, ctx);
  }

  // 执行 tamper 链（保护版）
  let out = _runChain(protectedPayload, plugins, ctx);

  // --- 第一遍：严格锚定还原（数字边界完整时命中） ---
  let restoredCount = 0;
  out = out.replace(_PH_RE, (m, idx) => {
    const marker = placeholders[Number(idx)];
    if (marker) { restoredCount++; return marker; }
    return m;
  });

  // 所有占位符都成功还原 → 返回保护版
  if (restoredCount === placeholders.length) {
    return out;
  }

  // --- 第二遍：宽松还原（[P0-FIX 2026-09-05]） ---
  // 严格一遍计数不足：占位符可能因相邻编码字符以数字结尾（%u0078 等）发生
  // 数字粘连而漏还原。去掉边界锚点重试，仅接受索引合法的匹配，且总还原数
  // 不超过占位符数（防 payload 自带 7331999xxx 长数字造成连环误还原）。
  out = out.replace(_PH_LENIENT_RE, (m, idx) => {
    if (restoredCount >= placeholders.length) return m;
    const marker = placeholders[Number(idx)];
    if (marker) { restoredCount++; return marker; }
    return m;
  });

  if (restoredCount === placeholders.length) {
    return out;
  }

  // 还原失败（占位符被编码类 tamper 变换导致正则匹配不到）→
  // 回退到不保护标记的版本重新执行 tamper 链，确保不会比不保护更糟
  return _runChain(payload, plugins, ctx);
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
