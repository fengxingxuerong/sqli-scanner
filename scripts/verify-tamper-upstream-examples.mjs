// ============================================================================
// scripts/verify-tamper-upstream-examples.mjs —— 用 sqlmap 官方 doctest 反测我们的 tamper
//
// 为什么：`tamper:parity` 只证明「官方有的插件我们也有同名的」，`tamper.doctest.test.js`
//   只证明「我们的 transform 符合我们自己写的期望」。**两份判据都是自报的** ——
//   翻译错了但自洽（把 A→B 译成 A→C，并顺手把期望写成 C）能同时绿过这两道门。
//   上游 docstring 里的 `>>> tamper(输入) / 期望输出` 是**第三方出的卷子**：
//   同一条输入、同一个期望输出，由上游作者为其真实行为背书。跑不赢就是语义漂移。
//
//   与仓内既有纪律同源：判据必须能跑、必须来自外部、豁免必须逐条点名。
//
// 用法：
//   node scripts/verify-tamper-upstream-examples.mjs              # 离线校验（读已入库快照）
//   node scripts/verify-tamper-upstream-examples.mjs --refresh    # 重抓上游源码并重生成快照
//   node scripts/verify-tamper-upstream-examples.mjs --refresh --src <解压目录>
// 退出码：存在「非基线内」的字面不一致 → 1
// ============================================================================
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execSync } from 'node:child_process';
import os from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SQLMAP_TAG = '1.10.10';
const SNAPSHOT = resolve(ROOT, 'server/src/core/tamper/upstream-sqlmap-doctests.json');
const BASELINE = resolve(ROOT, 'server/src/core/tamper/tamper-upstream-examples-baseline.json');
const TARBALL_URL = `https://codeload.github.com/sqlmapproject/sqlmap/tar.gz/refs/tags/${SQLMAP_TAG}`;

// ---------- Python 字符串字面量 → JS 字符串 ----------
// 只处理 doctest 里出现的形态：'x' / "x" / u'x' / rb'x' 加常见转义；解析不了返回 null（绝不猜）。
function parsePyLiteral(src) {
  let s = src.trim();
  const prefix = s.match(/^([a-zA-Z]{1,2})(?=['"])/);
  if (prefix) {
    if (!/^(u|b|r|rb|br|ur|f)?$/i.test(prefix[1])) return null;
    if (/f/i.test(prefix[1])) return null; // f-string 含表达式，不猜
    s = s.slice(prefix[1].length);
  }
  const q = s[0];
  if (q !== "'" && q !== '"') return null;
  if (s.startsWith(q.repeat(3))) return null; // 三引号（docstring 本体）不在这里处理
  if (s[s.length - 1] !== q) return null;
  const raw = /^(r|rb|br)$/i.test(prefix?.[1] || '');
  const body = s.slice(1, -1);
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\' && !raw) {
      const n = body[++i];
      if (n === undefined) return null;
      if (n === 'n') out += '\n';
      else if (n === 't') out += '\t';
      else if (n === 'r') out += '\r';
      else if (n === '\\') out += '\\';
      else if (n === "'") out += "'";
      else if (n === '"') out += '"';
      else if (n === 'x') { const h = body.slice(i + 1, i + 3); if (!/^[0-9a-fA-F]{2}$/.test(h)) return null; out += String.fromCharCode(parseInt(h, 16)); i += 2; }
      else if (n === 'u') { const h = body.slice(i + 1, i + 5); if (!/^[0-9a-fA-F]{4}$/.test(h)) return null; out += String.fromCharCode(parseInt(h, 16)); i += 4; }
      else if (n === 'U') { const h = body.slice(i + 1, i + 9); if (!/^[0-9a-fA-F]{8}$/.test(h)) return null; out += String.fromCodePoint(parseInt(h, 16)); i += 8; }
      else if (n === '0') { out += '\0'; }
      else return null;
    } else if (c === q) {
      // 未转义的同种引号 ⇒ 要么是紧邻的转义对，要么是我们没解析好的形态
      if (body[i + 1] === q) { out += q; i++; continue; }
      return null;
    } else out += c;
  }
  return out;
}

// ---------- 从上游 .py 抽 >>> tamper(...) / 期望输出 ----------
// 上游 docstring 的三种真实形态都要吃到：
//   ① 两行式：`>>> tamper('in')` 紧跟 ` 'out' `（最常见）
//   ② 单行式：`>>> tamper(u'in') == 'out'`（少数，如 charunicodeencode）
//   ③ 元组式：输出是 `('payload', u'comments')`（randomcomments 一类）
// 关键坑：docstring 收尾的 `"""` 与后续缩进代码行都可能被并进「期望输出」——
// 所以不靠缩进/后缀猜边界，而是**逐行累加、第一个能解析成 Python 字面量的累积即答案**；
// 一个都解析不出来 ⇒ 这条示例直接放弃（绝不猜）。
function extractFromSource(name, src) {
  const lines = src.split(/\r?\n/);
  const pairs = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*>>>\s*tamper\((.*)\)\s*(?:#.*)?$/);
    if (!m) continue;
    const argText = m[1].trim();
    const argParts = splitTopLevel(argText.startsWith('(') ? argText : `(${argText})`);
    const input = parsePyLiteral(argParts[0] ?? '');
    if (input === null) continue;

    // 形态②：同一行自带 `== 'out'`
    const eqIdx = (lines[i].match(/^\s*>>>\s*tamper\(.*?\)\s*==\s*(.+?)\s*$/) || [])[1];
    if (eqIdx) {
      const out2 = parsePyLiteral(eqIdx);
      if (out2 !== null) { pairs.push({ input, output: out2 }); continue; }
    }

    // 形态①③：向后累加，第一个可解析的累积就是期望输出
    let output = null, comments = null, tuple = false;
    let acc = '';
    for (let j = i + 1; j < Math.min(lines.length, i + 6); j++) {
      const l = lines[j];
      if (/^\s*$/.test(l)) break;
      if (/>>>\s/.test(l)) break;
      const cand = (acc ? `${acc} ${l.trim()}` : l.trim());
      if (/^"""/.test(cand)) break; // docstring 收尾
      acc = cand;
      if (acc.startsWith('(')) {
        const parts = splitTopLevel(acc);
        const first = parsePyLiteral(parts[0] ?? '');
        if (first !== null) { output = first; tuple = true; if (parts.length > 1) comments = parsePyLiteral(parts[1]); break; }
      } else {
        const first = parsePyLiteral(acc);
        if (first !== null) { output = first; break; }
      }
    }
    if (output === null) continue;
    pairs.push({ input, output, ...(tuple ? { tuple, comments } : {}) });
  }
  return pairs;
}

// 顶层逗号切分（忽略引号内的逗号）—— 处理 ('payload', u'comments') 形态
function splitTopLevel(s) {
  const inner = s.replace(/^\(/, '').replace(/\)\s*$/, '');
  const parts = [];
  let cur = '', depth = 0, quote = null;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (quote) {
      cur += c;
      if (c === '\\') { cur += inner[++i] ?? ''; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { parts.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

const refresh = process.argv.includes('--refresh');

if (refresh) {
  // 取上游源码：优先 --src 指定的解压目录，否则拉 tarball 到临时目录
  const srcArg = process.argv.find((a) => a.startsWith('--src='));
  let tamperDir = srcArg ? resolve(srcArg.split('=')[1]) : null;
  if (!tamperDir) {
    const tmp = join(os.tmpdir(), `sqlmap-${SQLMAP_TAG}`);
    mkdirSync(tmp, { recursive: true });
    const tgz = join(tmp, 'src.tar.gz');
    if (!existsSync(tgz)) execSync(`curl -sSL --retry 3 -o "${tgz}" "${TARBALL_URL}"`, { stdio: 'inherit' });
    execSync(`tar -xzf "${tgz}" -C "${tmp}" --wildcards '*/tamper/*.py'`, { stdio: 'inherit' });
    const found = readdirSync(tmp).map((d) => join(tmp, d, 'tamper')).filter((d) => existsSync(d));
    if (!found.length) throw new Error('解压后未找到 tamper 目录');
    tamperDir = found[0];
  }
  const perPlugin = {};
  for (const f of readdirSync(tamperDir).filter((x) => x.endsWith('.py') && x !== '__init__.py').sort()) {
    const name = f.replace(/\.py$/, '');
    const pairs = extractFromSource(name, readFileSync(join(tamperDir, f), 'utf8'));
    if (pairs.length) perPlugin[name] = pairs;
  }
  const total = Object.values(perPlugin).reduce((a, b) => a + b.length, 0);
  writeFileSync(SNAPSHOT, JSON.stringify({ _comment: '上游 sqlmap docstring 里的 >>> tamper(输入)/期望输出 对，按 tag 钉死。这是外部判据，不许手工编辑：改动只允许来自 --refresh。', tag: SQLMAP_TAG, at: new Date().toISOString(), plugins: Object.keys(perPlugin).length, examples: total, perPlugin }, null, 2));
  console.log(`已写入快照：${Object.keys(perPlugin).length} 个插件 / ${total} 条官方示例 → ${SNAPSHOT}`);
}

if (!existsSync(SNAPSHOT)) {
  console.error('缺快照 upstream-sqlmap-doctests.json，请先 --refresh');
  process.exit(1);
}
const snap = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : { excluded: {}, drift: {} };

// 必须走 core/tamper/index.js —— 它是「导入即注册」的显式入口；
// 直接 import TamperRegistry.js 拿到的是空注册表（本轮实测：79 个插件全被判成"本仓无同名"）。
const { tamperRegistry } = await import(pathToFileURL(resolve(ROOT, 'server/src/core/tamper/index.js')).href);

let checked = 0, ok = 0;
const mismatch = [];
const skippedNoPlugin = [];
const skippedRandom = [];
const skippedError = [];

for (const [name, pairs] of Object.entries(snap.perPlugin)) {
  const plugin = tamperRegistry.get(name);
  if (!plugin) { skippedNoPlugin.push(name); continue; }
  const knownExcl = baseline.excluded?.[name];
  for (const [idx, { input, output }] of pairs.entries()) {
    let got;
    try { got = plugin.transform(input, {}); } catch (e) { skippedError.push(`${name}#${idx}: ${e.message}`); continue; }
    let deterministic = true;
    try { deterministic = String(plugin.transform(input, {})) === String(got); } catch { deterministic = false; }
    if (!deterministic || knownExcl?.kind === 'nondeterministic') {
      skippedRandom.push({ name, idx, input, want: output, got, reason: knownExcl?.reason || '本插件输出含随机性，字面比对不适用' });
      continue;
    }
    checked++;
    if (String(got) === String(output)) ok++;
    else mismatch.push({ name, idx, input, want: output, got: String(got), known: Boolean(baseline.drift?.[`${name}#${idx}`]) });
  }
}

const unexpected = mismatch.filter((m) => !m.known);
// 豁免账必须会"过期"：某条本仓已改成与上游一致，却还留在账里 = 静默拿到一条无人复核的自由度。
// 这里不判红（不阻塞），但逐条点名；--prune-baseline 直接把已失效的行删掉。
const staleKeys = Object.keys(baseline.drift || {}).filter((k) => {
  if (!k.includes('#')) return false;
  const [name, idx] = k.split('#');
  // [2026-10-07] 随机性插件的"是否仍漂移"只能靠单次采样判 ⇒ 会随运气翻牌
  // （实测 randomcomments#0 在 ~1/16 的概率下恰好撞出上游那条形态 ⇒ 被误报"已失效"）。
  // 已在 `excluded` 里声明 nondeterministic 的插件，其 drift 行不参与失效判定。
  if (baseline.excluded?.[name]?.kind === 'nondeterministic') return false;
  const pairs = snap.perPlugin[name];
  if (!pairs) return true; // 上游已没有这个插件/示例 ⇒ 账项失效
  const p = pairs[Number(idx)];
  if (!p) return true;
  const plugin = tamperRegistry.get(name);
  if (!plugin) return false;
  try { return String(plugin.transform(p.input, {})) === String(p.output); } catch { return false; }
});
const removedKeys = Object.keys(baseline.drift || {}).filter((k) => !k.includes('#') && !snap.perPlugin[k]);
if (staleKeys.length || removedKeys.length) {
  console.log(`  ⚠️ 豁免账里 ${staleKeys.length + removedKeys.length} 项已失效（本仓输出已与上游一致，或上游已无此示例）：${[...staleKeys, ...removedKeys].join(', ')}`);
  console.log('     → 跑 `node scripts/verify-tamper-upstream-examples.mjs --prune-baseline` 删掉，别把豁免当永久额度');
}
if (process.argv.includes('--prune-baseline')) {
  const keep = Object.fromEntries(Object.entries(baseline.drift || {}).filter(([k]) => !staleKeys.includes(k) && !removedKeys.includes(k)));
  writeFileSync(BASELINE, JSON.stringify({ ...baseline, drift: keep, _prunedAt: new Date().toISOString() }, null, 2));
  console.log(`已删 ${staleKeys.length + removedKeys.length} 项失效豁免`);
}
console.log(`=== tamper 语义对齐上游官方示例（tag ${snap.tag}，快照 ${snap.at?.slice(0, 10)}）===`);
console.log(`  上游示例覆盖插件 ${Object.keys(snap.perPlugin).length} 个｜字面比对 ${checked} 条，一致 ${ok} 条`);
if (skippedRandom.length) console.log(`  随机性跳过 ${skippedRandom.length} 条（逐条点名，不静默）`);
// [2026-10-07] 双跑判异只是隐式兜底：两跑撞出同一形态（概率 Σp²）时会漏判成确定性插件并进入
// 字面比对 ⇒ 必然翻红（实测 space2mysqlblank#0 触发过）。凡命中随机跳过却未登记 excluded 的，
// 点名提醒登记 —— 别让下一批人再踩同一个翻牌。
const unregisteredRandom = [...new Set(skippedRandom.filter((s) => !baseline.excluded?.[s.name]).map((s) => s.name))];
if (unregisteredRandom.length) console.log(`  ⚠️ 以下插件输出含随机性但未登记 excluded/kind=nondeterministic（双跑判异有撞车漏检率，会随运气翻红）：${unregisteredRandom.join(', ')}`);
if (skippedNoPlugin.length) console.log(`  本仓无同名插件 ${skippedNoPlugin.length}: ${skippedNoPlugin.join(', ')}`);
if (skippedError.length) console.log(`  调用抛错 ${skippedError.length}: ${skippedError.join(' | ')}`);
for (const m of mismatch) {
  console.log(`  ${m.known ? '[基线已点名]' : '[新漂移]'} ${m.name}#${m.idx}`);
  console.log(`      输入: ${JSON.stringify(m.input)}`);
  console.log(`      上游: ${JSON.stringify(m.want)}`);
  console.log(`      本仓: ${JSON.stringify(m.got)}`);
}
if (unexpected.length) {
  console.error(`\n❌ ${unexpected.length} 条与上游官方示例不一致（且不在基线里）`);
  process.exit(1);
}
console.log('\n✅ 无新增漂移');
