// ============================================================================
// payloadFill.dollar.test.js —— 占位符填充不得解释 `$` 序列（payload 保真）
// ============================================================================
// 存在理由：fillPayload 是**每条注入请求的最后一道拼装机**，五个通道全部经它
// （ErrorDetector / BooleanBlind / TimeBlind / Stacked / SecondOrder / Oob /
//  DBFingerprinter / injection 的 UNION 标记探针）。旧实现用
//   template.replaceAll('{ORIG}', v.orig)
// 的**字符串**替换形态 —— 而 JS 在字符串替换值里会解释 `$&`、`` $` ``、`$'`、`$$`。
// 占位符的值全部来自不可信侧：{ORIG} 是目标参数的原值（多半从 Burp/curl 抓包导入），
// {BD} 是探测出来的闭合前缀，{CALLBACK}/{DOMAIN} 是用户配置的带外地址。
//
// 修复前实测（fillPayload("{ORIG}' AND '1'='1", {orig})）：
//   orig = d$'q         → d' AND '1'='1q' AND '1'='1   ← 模板尾巴被拼进了值里
//   orig = a$&b         → a{ORIG}b' AND '1'='1          ← 把未替换的占位符发给目标
//   orig = alice$$bot   → alice$bot' AND '1'='1         ← 值被静默截短
//   orig = p$`q         → pq' AND '1'='1                ← 值被截短
// 三条通道并不同源地受影响：Detector.probeBoundary 用的是**字符串拼接**（值完好），
// 而所有检测器用 fillPayload（值被改）→ 学习到的闭合前缀与实际发送的不一致。
// 后果是假阴性（发了条语法都不对的 SQL）而不是报错，所以没有任何日志会提示。
//
// 本文件钉四件事：
//   ① `$` 序列在 orig/bd/sep 三个位置都原样落地；
//   ② 填充后不残留占位符（`a$&b` 那种回展开尤其要防）；
//   ③ 值里写着另一个占位符时**不得二次展开**（单趟替换的性质）；
//   ④ 全仓静态守卫：不许再出现「字符串形态替换 {占位符}」的写法。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { fillPayload, replaceAllLiteral, BENCHMARK_MAX_ITER } from '../src/engine/payloads.js';

const TPL = `{ORIG}' AND '1'='1`;
const DOLLAR_FORMS = [`d$'q`, 'a$&b', 'alice$$bot', 'p$`q', '$&$`$\'$$', 'cost$1USD'];

test('① orig 含各种 $ 序列时，值必须逐字落在 payload 开头', () => {
  for (const orig of DOLLAR_FORMS) {
    const out = fillPayload(TPL, { orig });
    assert.ok(out.startsWith(orig), `值被改写：${JSON.stringify(orig)} → ${JSON.stringify(out)}`);
    assert.equal(out, `${orig}' AND '1'='1`);
  }
});

test('① bd / sep 同样受保（闭合前缀与注释符也可能带 $）', () => {
  assert.equal(fillPayload(`{ORIG}{BD} AND 1=1`, { orig: 'x', bd: `'$'` }), `x'$' AND 1=1`);
  assert.equal(fillPayload(`1{SEP}`, { sep: `$&-- -` }), `1$&-- -`);
});

test('② 填充结果里不得残留任何已知占位符', () => {
  for (const orig of DOLLAR_FORMS) {
    const out = fillPayload(TPL, { orig });
    assert.ok(!/\{(?:ORIG|BD|SLEEP|NUM|SEP)\}/.test(out), `残留占位符：${out}`);
  }
});

test('③ 值里写着另一个占位符时不被二次展开（单趟替换）', () => {
  // 链式 replace 会先写入 orig=`{BD}`，再在下一趟把它当占位符换掉 → 静默串台
  const out = fillPayload(`{ORIG} AND {BD}`, { orig: '{BD}', bd: 'INJECTED' });
  assert.equal(out, `{BD} AND INJECTED`);
});

test('① 既有行为不动：SLEEP/NUM 照常填充、未知占位符原样保留、重功能仍受限', () => {
  assert.equal(fillPayload(`SLEEP({SLEEP})`, { sleep: 3 }), 'SLEEP(3)');
  assert.match(fillPayload(`RAND({NUM})`, { num: 42 }), /^RAND\(42\)$/);
  assert.equal(fillPayload(`{UNKNOWN} x`, { orig: 'a' }), '{UNKNOWN} x');
  assert.equal(fillPayload(`{ORIG} x`, { orig: 'a' }), 'a x');
  // capHeavyFunctions 仍在最外层生效（迭代数被钉在模块导出的上限，不写死数字）
  assert.equal(
    fillPayload(`{ORIG} AND BENCHMARK(99999999,MD5(1))`, { orig: '1' }),
    `1 AND BENCHMARK(${BENCHMARK_MAX_ITER},MD5(1))`
  );
});

test('replaceAllLiteral：字面量写入，绝不展开 $ 序列', () => {
  assert.equal(replaceAllLiteral(`a{X}b`, '{X}', `$&$'`), `a$&$'b`);
  assert.equal(replaceAllLiteral(`{X}{X}`, '{X}', 'y'), 'yy', '多处出现要全换');
  assert.equal(replaceAllLiteral(`no placeholder`, '{X}', 'y'), 'no placeholder');
  assert.equal(replaceAllLiteral(`{X}`, '{X}', ''), '');
});

// ── ④ 静态守卫 ──────────────────────────────────────────────────────────────
// 缺陷的根因是「写法看起来无害」：replaceAll 的第二个参数是变量时，JS 仍按替换模式解释。
// 只靠单测只能盖住被调到的那几条，新增代码会重犯 —— 所以这里直接把**写法**钉掉。
function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (/\.m?js$/.test(name)) out.push(p);
  }
  return out;
}

test('④ 全仓不得再用「字符串形态的替换值」去填 {占位符}', () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const files = [...walk(join(root, 'src')), ...walk(join(root, '..', 'src', 'shared'))];
  // 形如 .replace('{XXX}', <不是函数>) —— 第二个参数以 ( 之外的任何值都算可疑
  const bad = /\.[a-zA-Z]*replace\w*\(\s*['"]\{[A-Z_]+\}['"]\s*,\s*(?!\s*(?:\(|function\b|async\b))/;
  const hits = [];
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    src.split('\n').forEach((line, idx) => {
      if (bad.test(line) && !/\/\/\s*guard-exempt/.test(line)) {
        hits.push(`${f.replace(root, '')}:${idx + 1}: ${line.trim()}`);
      }
    });
  }
  assert.deepEqual(
    hits,
    [],
    '以下位置用字符串形态的替换值填占位符，$& / $\' / dollar-backtick / $$ 会被当替换模式展开，请改用 replaceAllLiteral：\n' +
      hits.join('\n')
  );
});
