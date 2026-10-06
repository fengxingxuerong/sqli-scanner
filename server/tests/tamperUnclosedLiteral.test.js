// ============================================================================
// tests/tamperUnclosedLiteral.test.js
// tamper 插件的引号判据必须收敛到 quoteScan 单一真源；未闭合字面量必须原样透传
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// 上一轮把 23 个插件迁到 quoteScan 单一真源后，tamper/plugins/ 仍有 **49 个**
// 插件手写 inSingle/inDouble 状态机。这些未迁移的插件：
//   · 8 个会把「未闭合字面量」的尾部内容整个吞掉（payload 语义被摧毁）
//   · 49 个仍用 `src[i-1] !== '\\'` 的**奇偶判定**（只看向后一个字符）
//
// 实测危害（applyTampers 真跑，payload = "1' AND SLEEP(5)-- -"）：
//   bin2ascii  → "1'3265786832837669698040534145453245"     ← SLEEP 消失
//   binary     → "1'0b1000000b10000010b10011100b10001000…" ← SLEEP 消失
//   char2ascii → "1'3265786832837669698040534145453245"     ← SLEEP 消失
//   char2hex   → "1'\x20\x41\x4e\x44…"                       ← SLEEP 消失
//   coffee     → "1'\x20\x41\x4e\x44…"                       ← SLEEP 消失
//   css / doubleencode / octalencode 同型
//
// 直接**摧毁 payload 的注入语义**：时间盲注关键字被吃掉，扫描器发出的是一段
// 毫无意义的编码串。而且是**静默**的 —— 插件照常返回字符串，无任何报错。
//
// ── 为什么守卫要覆盖「全部插件」而不是「未收敛的那些」──────────────────────
// 若只对未收敛集合做断言，那么**收敛完成那天枚举变空，用例就成了恒绿的装饰品**。
// 现在收敛-1 直接断言"全部插件都不再手写判据"，行为用例跑全量 229 个插件：
//   · 新增插件自动纳入检查
//   · 收敛完成后守卫依然有效（它检查的是"不许回退"，不是"当前有多少个坏的"）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyTampers } from '../src/core/tamper/applyTampers.js';

const PLUGIN_DIR = join(fileURLToPath(new URL('.', import.meta.url)), '../src/core/tamper/plugins');

const ALL = readdirSync(PLUGIN_DIR)
  .filter((f) => f.endsWith('.js'))
  .map((f) => f.replace(/\.js$/, ''));

const srcOf = (name) => readFileSync(join(PLUGIN_DIR, `${name}.js`), 'utf8');

// 「引号判据是否已收敛到 quoteScan」。收敛标志取三个符号的全集：
// isQuoteEscaped（奇偶判定）/ readSqlLiteral（读字面量）/ splitByLiteral（分片）。
//
// ⚠️ 枚举判据选错，守卫就形同虚设 —— 本次踩过两个坑：
//   · 只查 inSingle && inDouble 同现 → if2case（只有 inSingle）、
//     space2comment（还有 inBacktick）全漏出枚举，覆盖不全；
//   · 用 /readSqlLiteral|splitByLiteral/ 判定「已迁移」→ 这两个文件用的是
//     isQuoteEscaped，同样已收敛，却被误判为未迁移。
const notConverged = (name) => {
  const s = srcOf(name);
  const hasQuoteState = /\b(inSingle|inDouble|inBacktick)\b/.test(s);
  const usesQuoteScan = /\b(isQuoteEscaped|readSqlLiteral|splitByLiteral)\b/.test(s);
  return hasQuoteState && !usesQuoteScan;
};

const LEGACY = ALL.filter(notConverged);

// 「本插件是否有 SQL 字面量概念」——决定它是否该遵守"未闭合原样透传"。
//
// ⚠️ 判据必须区分这两类，否则就是把"比被测代码更笨的启发式"写进守卫
//    （本会话已多次因此制造假红，最后反过来去"修"正确的生产代码）：
//   · **含字面量语义**的插件（如 char2hex：注释写明"将字符串字面量内的字符编码"）
//     必须遵守未闭合透传 —— 它们认得出哪些字符在字面量内，理应也认得出
//     "字面量没闭合"这件事。
//   · **整体编码类**（base64encode / charencode / keyword2hex / sleep2hex …
//     实测 17 个）从设计上就编码整个 payload，不区分字面量边界。
//     对它们断言"原样透传"是要求它们做它们根本不该做的事 —— 假红。
// 判别方式：源码里是否声明了字面量状态 / 是否说明只编码字面量内。
const hasLiteralConcept = (name) => {
  const s = srcOf(name);
  if (/\b(inSingle|inDouble|inBacktick)\b/.test(s)) return true;
  if (/readSqlLiteral|splitByLiteral/.test(s)) return true;
  // 注释里明写「字面量」也算（有状态机但已收敛的插件同样适用）
  return /字面量|literal/i.test(s.split('\n').slice(0, 6).join('\n'));
};

// 需要遵守未闭合透传口径的插件
const LITERAL_AWARE = ALL.filter(hasLiteralConcept);

const apply = (payload, name) => {
  try {
    return applyTampers(payload, { config: {} }, [name]);
  } catch (e) {
    return `__THREW__:${e.message}`;
  }
};

// 真实世界高频形态：单引号点 + 未闭合探针（边界探测阶段）。
// 尾部含可识别关键字，一旦被吞掉即说明 payload 结构被破坏。
const OPEN_PAYLOAD = "1' AND SLEEP(5)-- -";

test('自证-0) 收敛判据本身有效（认得出未收敛 / 认得出已收敛）', () => {
  const judge = (src) => {
    const hasQuoteState = /\b(inSingle|inDouble|inBacktick)\b/.test(src);
    const usesQuoteScan = /\b(isQuoteEscaped|readSqlLiteral|splitByLiteral)\b/.test(src);
    return hasQuoteState && !usesQuoteScan;
  };
  const unconv = `let inSingle = false;\nif (ch === "'" && src[i-1] !== '\\\\') inSingle = false;`;
  const conv = `import { isQuoteEscaped } from '../quoteScan.js';\nlet inSingle = false;\nif (ch === "'" && !isQuoteEscaped(src, i)) inSingle = false;`;
  assert.equal(judge(unconv), true, '判据认不出未收敛样本 —— 守卫会漏检');
  assert.equal(judge(conv), false, '判据把已收敛样本判成未收敛 —— 会误报');
});

test('自证-0a) 注释剥离有效（修好的插件会在注释里写旧写法作为变更说明）', () => {
  const strip = (s) => s
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((l) => l.replace(/(^|\s)(\/\/|\*).*$/, '$1'))
    .join('\n');
  // 注释里的旧写法必须被剥掉（否则守卫会把正确的文件判成残留 —— 实测误报过 4 个）
  const inComment = `// 原写法 \`s[i-1] !== '\\\\'\` 问的是"前一个字符是不是反斜杠"\nlet x = 1;`;
  assert.ok(!/\[\s*i\s*-\s*1\s*\]/.test(strip(inComment)), '行注释未被剥离');
  const inBlock = `/* 原写法 s[i-1] !== '\\\\' */\nlet x = 1;`;
  assert.ok(!/\[\s*i\s*-\s*1\s*\]/.test(strip(inBlock)), '块注释未被剥离');
  // 但真实代码不能被剥掉
  const real = `if (ch === "'" && src[i - 1] !== '\\\\') inSingle = false;`;
  assert.ok(/\[\s*i\s*-\s*1\s*\]/.test(strip(real)), '真实代码被误剥 —— 守卫会漏检');
  // 残留判据必须能抓住这行真实代码（第一版反向引用失效，注入后守卫全绿）
  const adjacency = /\[\s*i\s*-\s*1\s*\]\s*!==|\bprev\s*!==|\b(?:str|s|src|q)\s*\[\s*i\s*-\s*1\s*\]\s*!==/;
  const quoteClose = /ch\s*===\s*["'][^\n;]*?&&[^\n;]*!==/;
  assert.ok(quoteClose.test(strip(real)) && adjacency.test(strip(real)),
    `残留判据抓不住真实代码 —— 守卫形同虚设`);
  // 而正确写法不应被误判
  const good = `if (ch === "'" && !isQuoteEscaped(src, i)) inSingle = false;`;
  assert.ok(!(quoteClose.test(strip(good)) && adjacency.test(strip(good))),
    '残留判据把正确写法误判成残留 —— 会制造假红');
});

test('收敛-1) 全部插件的引号判据必须收敛到 quoteScan（禁止本地副本）', () => {
  assert.equal(LEGACY.length, 0,
    `以下 ${LEGACY.length} 个插件仍手写引号状态机、未复用 quoteScan 单一真源：\n  ${LEGACY.join('\n  ')}`);
  // 额外核查：源码里不得残留「只看相邻一个字符」的旧写法。
  //
  // ⚠️ 两个必须踩过才知道的坑：
  //  1. 判据要匹配**语义**而非变量名 —— 第一版写 /prev\s*!==\s*['"]\\\\/ 只认 prev
  //     这个变量名，注入 src[i-1] !== '\\'（同样只看相邻字符、同样错）时守卫**全绿**，
  //     差点让回归蒙混过关（缺陷注入实测才发现）。本仓出现过 4 种变量名。
  //  2. 必须**排除注释** —— 修好的插件都会在注释里写「原写法 src[i-1] !== '\\' …」
  //     作为变更说明；不排除就会把 4 个正确文件判成残留（实测误报）。
  const stripComments = (s) => s
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((l) => l.replace(/(^|\s)(\/\/|\*).*$/, '$1'))
    .join('\n');
  const adjacency = /\[\s*i\s*-\s*1\s*\]\s*!==|\bprev\s*!==|\b(?:str|s|src|q)\s*\[\s*i\s*-\s*1\s*\]\s*!==/;
  // 「引号闭合判定与相邻比较同一行」。
  // ⚠️ 这里连踩两次：
  //  1. /ch\s*===\s*(["'])(?:\\1|["'])/ 的反向引用 `\\1` 匹配不到
  //     `ch === "'"`（双引号包裹单引号，首尾引号**不同**类）；
  //  2. 改成 ["'][^"']*["'] 也不行 —— `[^"']*` 不能跨引号，
  //     而 `"'"` 的正确匹配是 `ch === "'`（4 字符，首尾不同类）。
  // ⇒ 干脆不要求引号配对：只要出现 `ch === <引号字符>` 后跟 `!==` 即可。
  const quoteCloseWithAdjacency = /ch\s*===\s*["'][^\n;]*?&&[^\n;]*!==/;
  const residue = ALL.filter((n) => {
    const s = stripComments(srcOf(n));
    return quoteCloseWithAdjacency.test(s) && adjacency.test(s);
  });
  assert.equal(residue.length, 0,
    `以下插件用「相邻一字符 ≠ 反斜杠」判断引号转义（只看后一字符，非奇偶判定）：\n  `
    + residue.join('\n  '));
});

test('自证-0b) 字面量语义判据有效（认得出该守的 / 认得出不该守的）', () => {
  const judge = (src) => {
    if (/\b(inSingle|inDouble|inBacktick)\b/.test(src)) return true;
    if (/readSqlLiteral|splitByLiteral/.test(src)) return true;
    return /字面量|literal/i.test(src.split('\n').slice(0, 6).join('\n'));
  };
  assert.equal(judge(`// 将字符串字面量内的字符编码为 \\xHH\nexport const x = {};`), true,
    '字面量语义判据认不出"只编码字面量内"的插件 —— 会漏检真正的受害者');
  assert.equal(judge(`// 整体 base64 编码整个 payload\nexport const x = {};`), false,
    '字面量语义判据把整体编码类误判为字面量类 —— 会制造假红');
  // 分类结果必须非空且不覆盖全部，否则下面的行为用例形同虚设
  assert.ok(LITERAL_AWARE.length > 0, 'LITERAL_AWARE 为空，行为守卫失去对象');
  assert.ok(LITERAL_AWARE.length < ALL.length,
    'LITERAL_AWARE 覆盖了全部插件，说明分类判据失效（没有整体编码类？）');
});

test('缺陷-1) 未闭合字面量不得吞掉 payload 尾部（SLEEP 关键字必须保留）', () => {
  const broken = [];
  for (const name of LITERAL_AWARE) {
    const out = apply(OPEN_PAYLOAD, name);
    if (typeof out !== 'string' || out.startsWith('__THREW__') || !/SLEEP/i.test(out)) {
      broken.push(`${name} → ${JSON.stringify(String(out).slice(0, 56))}`);
    }
  }
  assert.equal(broken.length, 0,
    `以下 ${broken.length}/${LITERAL_AWARE.length} 个含字面量语义的插件把未闭合字面量的尾部吞掉了`
    + `（payload 语义已被摧毁）：\n  ` + broken.join('\n  '));
});

test('缺陷-2) 未闭合的尾部不得被编码（字面量外的前缀改写仍属设计行为）', () => {
  // ⚠️ 口径收窄的必要教训：第一版把「整个 payload 原样不变」当判据，结果把
  // castprefix（闭合前加 CAST 前缀）、multiplespaces（字面量外多空格）、
  // randomcase（大小写随机化）、sleep2hex（关键字转十六进制）全判成红 ——
  // 那些都是它们的**设计行为**，判据比被测代码更笨，会逼人去"修"正确的代码。
  //
  // 真正的危害只有一个：**未闭合字面量的尾部被当成字面量内容一并编码**
  // （原 char2hex 那类：SLEEP → \x53\x4c…）。所以判据是：
  //   尾部必须保持**可读形态** —— 含 ASCII 字母的连续片段仍可辨认，
  //   且不得出现"整段被编码"的形态（连续 4 个以上 \xNN 或超长纯数字/二进制串）。
  const encodedTail = /(?:\\x[0-9a-fA-F]{2}){4,}|(?:0b[01]{4,}){2,}|[0-9]{40,}/;
  const bad = [];
  for (const name of LITERAL_AWARE) {
    const out = apply(OPEN_PAYLOAD, name);
    if (typeof out !== 'string' || out.startsWith('__THREW__')) { bad.push(`${name} → 抛错`); continue; }
    const tail = out.slice(out.indexOf("'") + 1);   // 开引号之后的全部内容
    if (encodedTail.test(tail)) {
      bad.push(`${name} → 尾部被编码 ${JSON.stringify(out.slice(0, 80))}`);
    }
  }
  assert.equal(bad.length, 0,
    `以下 ${bad.length}/${LITERAL_AWARE.length} 个插件把未闭合字面量的尾部当字面量内容编码了`
    + `（注入语义被摧毁）：\n  ` + bad.join('\n  '));
});

test('缺陷-3) 奇偶判定语义：偶数个反斜杠后的引号必须视为闭合（回归防护）', () => {
  // 这是缺陷①本身的判据，不依赖源码文本，只依赖**行为**。
  // 'a\\' —— 2 个反斜杠表示「一个转义的反斜杠」，紧随的 ' 是**未转义**的闭合引号。
  // 退回「只看相邻字符」的实现会把 `\'` 判成转义 ⇒ 引号状态永不闭合 ⇒
  // 其后所有字符被当作字面量：关键字不再混淆、字面量外的空格替换一并失效
  // （全盘失效型，见 quoteScan.js 头部注释）。
  //
  // 判据构造：payload = 一个完整闭合的字面量 + 闭合引号 + 尾部标记。
  // 若实现把闭合引号误判为转义，尾部标记就会落进"字面量内"而被逐字符编码。
  //
  // ⚠️ 第一版 payload 写成 "1' AND 1=1' SLEEPX" 时把 `' AND 1=1'` 整体当成了
  // **待编码的字面量**（它确实是字面量！）—— 编码它正是正确行为，
  // 于是 binary/char2hex/coffee 全被误判成红。判据比被测代码更笨的又一例。
  // 现在尾部放在**闭合引号之后**且不含引号：正常实现不该对它做字面量编码。
  const CLOSED_LITERAL = "1' AND 1=1'";   // 一个完整闭合的字面量
  const TAIL = ' SLEEPX';                  // 落在闭合引号之外
  const wrong = [];
  for (const name of LITERAL_AWARE) {
    const out = apply(CLOSED_LITERAL + TAIL, name);
    if (typeof out !== 'string') continue;
    // 尾部不得出现"被编码"的形态（连续 \xNN / 0b 位串）。
    // 只看闭合引号之后的部分 —— 引号之前是字面量，编码它是对的。
    const afterQuote = out.slice(out.lastIndexOf("'") + 1);
    const encoded = /(\\x[0-9a-fA-F]{2}){4,}|(0b[01]{4,}){2,}/.test(afterQuote);
    if (encoded) wrong.push(`${name} → ${JSON.stringify(out.slice(0, 90))}`);
  }
  assert.equal(wrong.length, 0,
    `以下插件因引号闭合判错，把字面量外的尾部当字面量内容编码了（奇偶判定失效）：\n  `
    + wrong.join('\n  '));
});

test('契约-3) 闭合字面量仍按各插件语义正常改写（护栏不得一刀切禁掉插件）', () => {
  // 反向契约：若实现改成「遇引号就整体透传」，本用例会红。
  const CLOSED = "1' OR '1'='1";
  const changedCount = ALL.filter((name) => apply(CLOSED, name) !== CLOSED).length;
  assert.ok(changedCount > 0,
    '没有任何插件对闭合字面量做出改写 —— 说明护栏把插件整体禁用了（丧失检出能力）');
});

test('契约-4) 尾随转义反斜杠的未闭合 payload 同样不得吞尾部', () => {
  // 'a\' —— 1 个反斜杠，末位引号**被转义**，字面量未闭合。
  const payload = "1' AND SLEEP(5)-- -\\";
  const broken = LITERAL_AWARE.filter((n) => {
    const out = apply(payload, n);
    return typeof out !== 'string' || !/SLEEP/i.test(out);
  });
  assert.equal(broken.length, 0,
    `尾随转义反斜杠的未闭合 payload 被吞掉尾部：\n  ${broken.join('\n  ')}`);
});

test('契约-5) 双引号点同样适用（不得只修单引号）', () => {
  const payload = '1" AND SLEEP(5)-- -';
  const broken = LITERAL_AWARE.filter((n) => {
    const out = apply(payload, n);
    return typeof out !== 'string' || !/SLEEP/i.test(out);
  });
  assert.equal(broken.length, 0,
    `双引号未闭合 payload 被吞掉尾部：\n  ${broken.join('\n  ')}`);
});