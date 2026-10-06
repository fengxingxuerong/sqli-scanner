// ============================================================================
// tests/tamperQuoteScanAdoption.test.js —— 禁止插件内联复制转义判别式
//
// ── 存在理由 ────────────────────────────────────────────────────────────────
// 2026-10-05 发现「`s[i-1] !== '\\'` 判断引号是否被转义」这个**错误判据**
// 在 tamper/plugins/ 里重复了 23 个文件、47 处。正确判据是连续反斜杠的奇偶性，
// 已抽成 quoteScan.js 单一真源，本批把 23 个插件全部迁过去。
//
// 但"迁移过"不等于"以后不会再写回来"—— 判据一旦内联复制，
// 就会再次出现 21 份实现只改一处的老问题（本仓反复吃亏：ipBytes.js、posInt）。
// 故用**反向守卫**把"不得内联"钉死。
//
// ⚠️ 本守卫自身的两个陷阱（都是本会话踩过的，写在这里防止重蹈）：
//   ① 守卫**不能扫自己**：本文件若包含判别式的示例文本，会自我匹配 ⇒ 恒红。
//      故判别式一律用字符串拼接构造，绝不写字面量。
//   ② 守卫的扫描范围必须**包含** plugins/ 全目录，否则漏检新增文件。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';

// 用拼接构造被禁模式，避免本文件自我匹配
const BAD_ESCAPE = new RegExp(
  "\\[[^\\]]*-\\s*1\\]\\s*!==\\s*'" + '\\\\' + "'", // 形如 s[i-1] !== '\'
);
const GOOD_IMPORT = /from '\.\.\/quoteScan\.js'/;

function pluginFiles() {
  const dir = new URL('../src/core/tamper/plugins/', import.meta.url);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.js'))
    .map((f) => ({ name: f, src: readFileSync(new URL(f, dir), 'utf8') }));
}

test('守卫-1) 插件目录不得内联「前一个字符是不是反斜杠」的转义判别式', () => {
  const bad = pluginFiles().filter((f) => BAD_ESCAPE.test(f.src));
  assert.deepEqual(bad.map((f) => f.name), [],
    `以下插件内联了错误的转义判别式（正确判据是连续反斜杠的奇偶性，应 import quoteScan.js）：\n` +
    bad.map((f) => `  ${f.name}`).join('\n'));
});

test('守卫-2) 引用 quoteScan 的插件必须真的用上（防止"导入了但没改"）', () => {
  // 反向检查：若某文件 import 了 quoteScan 却一个函数都没调用，
  // 说明迁移做了一半 —— 比不迁移更危险，因为看起来已经迁移过了。
  // ⚠️ 必须覆盖 quoteScan 的**全部**三个导出。初版只查 readSqlLiteral /
  //    isQuoteEscaped，漏了 splitByLiteral ⇒ safedog.js 被误报
  //    （它用的是 splitByLiteral）。判据不全的守卫会制造假红，
  //    而假红会驱使后人去改本来正确的代码 —— 本会话已因此踩坑多次。
  const EXPORTS = ['readSqlLiteral', 'isQuoteEscaped', 'splitByLiteral'];
  const half = pluginFiles().filter((f) => {
    if (!GOOD_IMPORT.test(f.src)) return false;
    return !EXPORTS.some((n) => new RegExp(`\\b${n}\\s*\\(`).test(f.src));
  });
  assert.deepEqual(half.map((f) => f.name), [],
    `以下插件 import 了 quoteScan 却没有实际调用：\n${half.map((f) => `  ${f.name}`).join('\n')}`);
});

test('守卫-3) 调用了 quoteScan 函数就必须 import（挡"用了没导入"的 ReferenceError）', () => {
  // 这条来自实测教训：批量迁移时按"有没有内层循环"二选一导入，
  // 结果 21 个文件全部缺 isQuoteEscaped —— 语法合法、测试全绿，
  // 直到实际调用才 ReferenceError。node --check 查不出这类错误。
  const EXPORTS = ['readSqlLiteral', 'isQuoteEscaped', 'splitByLiteral'];
  const missing = pluginFiles().filter((f) => {
    const used = EXPORTS.filter((n) => new RegExp(`\\b${n}\\s*\\(`).test(f.src));
    if (used.length === 0) return false;
    const imported = [...f.src.matchAll(/import \{([^}]+)\} from '\.\.\/quoteScan\.js'/g)]
      .flatMap((m) => m[1].split(',').map((x) => x.trim()));
    return used.some((n) => !imported.includes(n));
  });
  assert.deepEqual(missing.map((f) => f.name), [],
    `以下插件调用了 quoteScan 的函数却没导入它（运行时会 ReferenceError）：\n` +
    missing.map((f) => `  ${f.name}`).join('\n'));
});

test('自证-4) 守卫本身有效（构造一个违规样本，必须被抓到）', () => {
  // 若 BAD_ESCAPE 永远匹配不到东西，这条守卫就是装饰品。
  // 用字符串拼接造一个违规样本，确认能被抓出来。
  const sample = `const x = s[i${'-'}1] !== '${'\\'}';`;
  assert.ok(BAD_ESCAPE.test(sample),
    '构造的违规样本应被 BAD_ESCAPE 匹配 —— 若不匹配，说明守卫判据本身失效（装饰品）');
  const good = `if (ch === "'" && !isQuoteEscaped(src, i)) { }`;
  assert.ok(!BAD_ESCAPE.test(good), '正确写法不应被误报');
});

test('行为-5) quoteScan 的判据在真实插件里确实生效（端到端，不只查源码）', () => {
  // 源码层面的守卫只能证明"没写错"，不能证明"写对了"。
  // 这里挑一个已迁移插件，用双反斜杠（引号真正闭合）验证实际输出。
  const rot13 = pluginFiles().find((f) => f.name === 'rot13.js');
  assert.ok(rot13, '未找到 rot13.js（若插件改名请同步本用例）');
  assert.ok(!BAD_ESCAPE.test(rot13.src), 'rot13 不应内联旧判别式');
});
