// 验证 applyTampers 标记保护机制（P0-D3 修复后）
import { applyTampers } from '../server/src/core/tamper/applyTampers.js';

// 基准：原始 payload 含提取标记
const basePayload = '__S__x__E__7331999001 UNION SELECT 1,2,3';

// 场景 1: charencode 单独作用（terminal:true）
console.log('=== 场景 1: charencode 单独作用 ===');
const r1 = applyTampers(basePayload, {}, ['charencode']);
console.log('输出 ：', r1.slice(0, 100));
console.log('标记 intact:', /__S__/.test(r1) && /__E__/.test(r1) ? 'YES ✓' : 'NO ✗');
console.log();

// 场景 2: space2comment（非 terminal）单独作用
console.log('=== 场景 2: space2comment 单独作用 ===');
const r2 = applyTampers(basePayload, {}, ['space2comment']);
console.log('输出 ：', r2.slice(0, 100));
console.log('标记 intact:', /__S__/.test(r2) && /__E__/.test(r2) ? 'YES ✓' : 'NO ✗');
console.log();

// 场景 3: charencode 紧跟 space2nbsp（链截断，只有 charencode 生效）
console.log('=== 场景 3: charencode + space2nbsp（链截断） ===');
const r3 = applyTampers(basePayload, {}, ['charencode', 'space2nbsp']);
console.log('输出 ：', r3.slice(0, 100));
console.log('标记 intact:', /__S__/.test(r3) && /__E__/.test(r3) ? 'YES ✓' : 'NO ✗');
console.log();

// 场景 4: 多个非 terminal 插件
console.log('=== 场景 4: space2comment + space2nbsp ===');
const r4 = applyTampers(basePayload, {}, ['space2comment', 'space2nbsp']);
console.log('输出 ：', r4.slice(0, 100));
console.log('标记 intact:', /__S__/.test(r4) && /__E__/.test(r4) ? 'YES ✓' : 'NO ✗');
console.log();

// 场景 5: SQLISCANNER 标记
console.log('=== 场景 5: SQLISCANNER0 标记 ===');
const sqlPayload = 'SQLISCANNER0 UNION SELECT 1,2,3';
const r5 = applyTampers(sqlPayload, {}, ['charencode']);
console.log('输出 ：', r5.slice(0, 100));
console.log('标记 intact:', /SQLISCANNER0/.test(r5) ? 'YES ✓' : 'NO ✗');
console.log();

// 场景 6: 暴力测试 — 所有插件依次跑 __S__x__E__
console.log('=== 场景 6: 暴力测试所有插件对 __S__x__E__ 的影响 ===');
const toTest = ['charencode', 'chardoubleencode', 'space2comment', 'space2nbsp', 'randomcase', 'lowercase', 'uppercase', 'apostrophemask', 'htmlencode', 'charunicodeencode', 'base64encode'];
let pass = 0, fail = 0;
for (const name of toTest) {
  try {
    const r = applyTampers(basePayload, {}, [name]);
    const ok = /__S__/.test(r) && /__E__/.test(r);
    console.log(`${name.padEnd(20)} : ${ok ? 'OK ✓' : 'FAIL ✗'}`);
    if (!ok) { console.log('         输出:', r.slice(0, 120)); fail++; }
    else pass++;
  } catch(e) {
    console.log(`${name.padEnd(20)} : ERROR ${e.message}`);
    fail++;
  }
}
console.log();
console.log(`通过 ${pass} / 失败 ${fail}`);
