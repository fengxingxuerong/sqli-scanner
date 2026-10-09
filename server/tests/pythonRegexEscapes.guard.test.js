// ============================================================================
// server/tests/pythonRegexEscapes.guard.test.js —— 守卫「把 Python 正则转义抄进 JS」这一族
//
// 起因（2026-10-09，批次 D25）：三个 tamper 插件的上游对标实现（sqlmap 1.10.10，Python）
// 用 `\Z` 表示**串尾**，被逐字符抄进 JS 正则。JS 里没有 `\Z` 这个断言 ——
// `\Z` 就是**字面量字母 Z** ⇒ 关键词落在 payload 末尾时边界永不成立，那一个词永不变形。
// 实测三处：halfversionedmorekeywordsopen / versionedmorekeywordsnospace /
// versionedkeywordsnospace（`1' UNION ALL SELECT USER` 的句尾 USER 漏包）。
//
// 为什么值得一条守卫而不是修完就算：这个形状**没有任何运行时报错** ——
// 正则照样编译、插件照样跑、既有 doctest 全绿（因为 doctest 的输入都以引号收尾，
// 恰好没有"关键词在句尾"的样本）。只有把边界补进 doctest，再加一条静态守卫，
// 才能在下一次"照着上游抄"时立刻红。
//
// 判据口径：
//   ① `\A \Z \z \G` 在 JS 里都不是断言，是字面字母 —— 无论落在正则字面量还是字符串里，
//      出现就说明作者想表达的是 Perl 语义 ⇒ 一律算违规（不必先判定它在哪种字面量里）。
//   ② **先剥注释再扫**（D21 的现成教训：判据的文本源必须排除注释）——
//      本仓三个插件的说明注释里现在都写着 `\Z`，不剥注释这条守卫会第一跑就假红。
//   ③ 双反斜杠 `\\Z` 是"字面反斜杠 + Z"，合法，不算（正则字符串拼接里常见）。
//   ④ 分母：扫描文件数必须够多，防止文件集为空后恒绿。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);
const BS = String.fromCharCode(92);

// ① 要禁的四个：Perl/Python 的串界与起点断言，JS 无此语义
const FORBIDDEN = ['A', 'Z', 'z', 'G'];
// 注意拼接层级：正则源里要出现"一个字面反斜杠"必须写两个 ⇒ 这里是 BS+BS，
// 少一层的写法（BS + '[…]'）会拼出 `\[AZzG]`＝"字面左括号…"，**永远匹配不到**，
// 主判据就变成恒绿。本文件的自证① 首跑抓到的正是这个（2026-10-09）。
const VIOLATION_RE = new RegExp('(?:^|[^' + BS + BS + '])' + BS + BS + '[' + FORBIDDEN.join('') + ']');

let tracked = [];
let gitSkip = false;
try {
  tracked = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split(NUL)
    .filter((f) => /\.(js|mjs|cjs)$/.test(f));
} catch (e) {
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

// ② 取"参与判据的行"。刻意**不用块正则**剥注释：本仓 tamper 插件里到处是版本注释起始序列
//   （斜杠星!0）与收尾星杠序列，`/\*[\s\S]*?\*\//` 会把它们当块注释配对，
//   一口吃掉跨几行的真代码（2026-10-09 差点就这么写了 —— 而这条注释本身若写成块注释，
//   里面的收尾星杠序列会先把它闭合，node 当场 SyntaxError，实测踩过）。
//   改成按行判：整行注释/续行按前缀剔除，行尾注释从双斜杠处截断。
function codePart(line) {
  const t = line.replace(/\/\/.*$/, '');
  const s = t.trim();
  if (s.startsWith('//') || s.startsWith('*') || s.startsWith('/*')) return '';
  return t;
}

function scan() {
  const hits = [];
  let scanned = 0;
  for (const f of tracked) {
    const abs = path.join(REPO, f);
    let st;
    try {
      st = statSync(abs);
    } catch {
      continue;
    }
    if (!st.isFile() || st.size > 2 * 1024 * 1024) continue;
    let text;
    try {
      text = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    scanned++;
    text.split('\n').forEach((raw, i) => {
      const line = codePart(raw);
      if (line && VIOLATION_RE.test(line)) hits.push(f + ':' + (i + 1) + '  ' + line.trim().slice(0, 90));
    });
  }
  return { hits, scanned };
}

test('自证：判据吃单反斜杠、吐掉双反斜杠与注释（否则它会在自己的说明上假红）', () => {
  const src = [
    'const a = /x|\\Z/.source;', // ① 正则里的 \Z ⇒ 必须抓到
    'const b = "foo\\Z";', // ② 字符串里的 \Z ⇒ 也必须抓到（同样不是断言）
    'const c = new RegExp("x" + "\\\\\\\\Z");', // ③ 双反斜杠（字面反斜杠+Z）⇒ 不许抓
    '// 上游 Python 原文写 \\Z（串尾）', // ④ 整行注释 ⇒ 不许抓
    '  * 说明里也写 \\Z', // ⑤ 块注释续行 ⇒ 不许抓
    'const d = /ok$/; // 注释里提 \\A ⇒ 不许抓但这行仍要看前半段', // ⑥ 行尾注释截断
    'const e = /bad\\A/; // 行尾还有 \\A', // ⑦ 代码段里的 \A ⇒ 必须抓到
  ].join('\n');
  const flagged = src
    .split('\n')
    .map((l, i) => ({ i, part: codePart(l) }))
    .filter((x) => x.part && VIOLATION_RE.test(x.part))
    .map((x) => x.i);
  assert.deepEqual(flagged, [0, 1, 6], '应当只剩 ①②⑦ 三行，实得 ' + JSON.stringify(flagged));
});

test('自证：扫描面不为空（文件集一旦被算错，零命中就等于恒绿）', () => {
  const { scanned } = scan();
  assert.ok(scanned >= 800, `只扫到 ${scanned} 个 JS 文件，文件集采集可能已经坏了`);
});

test('JS 代码里不得出现 Perl/Python 串界转义 \\A \\Z \\z \\G', { skip: gitSkip }, () => {
  const { hits } = scan();
  assert.equal(
    hits.length,
    0,
    `${hits.length} 处把 Python 正则转义抄进了 JS —— JS 里 \\Z/\\A/\\z/\\G 是字面字母，
不是"串尾/串首"断言：正则照样编译、用例照样跑，边界静默失效。要串尾写 $，要串首写 ^。
` + hits.join('\n')
  );
});
