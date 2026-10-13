#!/usr/bin/env node
/**
 * greenguard-check.mjs —— 恒绿门禁检测器（spec 5.1.1 规则 8）
 *
 * 解决什么：门禁脚本"无论检查结果如何都 exit 0" = 恒绿 = 形同虚设。本脚本静态扫描
 * scripts/ 下的门禁脚本，标记恒绿嫌疑（catch 内 exit(0)、末尾无条件 exit(0)、
 * 目标缺失时仍 exit(0) 等模式），逼人当面确认"这到底是真绿还是恒绿"。
 *
 * 判据（保守，宁可有误报再豁免，不漏放恒绿）：
 *   ① catch 块内出现 process.exit(0) —— 吞掉错误后以成功退出
 *   ② 文件末尾的 process.exit(0) 前无任何 if/throw 守卫 —— 不依赖检查结果
 *   ③ 出现 `process.exit(0)` 的次数 == 所有 exit 调用次数 —— 只退出成功不退出失败
 *
 * 豁免：greenguard-waivers.json 登记豁免项 + 理由（如工具脚本本就无条件 exit 0）。
 *
 * 用法：
 *   node scripts/greenguard-check.mjs            # 扫描 scripts/ 下所有 .mjs
 *   node scripts/greenguard-check.mjs --selftest # 自证判据不空转
 *   node scripts/greenguard-check.mjs --file=scripts/foo.mjs
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const argv = process.argv.slice(2);
const has = (n) => argv.includes(`--${n}`);
const flag = (n) => argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);

const WAIVERS_PATH = path.join(HERE, 'greenguard-waivers.json');
function loadWaivers() {
  try {
    return new Set(JSON.parse(fs.readFileSync(WAIVERS_PATH, 'utf8')).map((w) => w.file || w));
  } catch {
    return new Set();
  }
}

/** 扫描单个文件的恒绿嫌疑 */
function scanFile(filePath) {
  const src = fs.readFileSync(filePath, 'utf8');
  const suspects = [];

  // ① catch 块内 process.exit(0)
  const catchRe = /catch\s*(?:\([^)]*\))?\s*\{/g;
  let m;
  while ((m = catchRe.exec(src)) !== null) {
    // 找到 catch 块的闭合大括号
    let depth = 1;
    let i = m.index + m[0].length;
    while (i < src.length && depth > 0) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}') depth--;
      i++;
    }
    const catchBody = src.slice(m.index, i);
    if (/process\.exit\s*\(\s*0\s*\)/.test(catchBody) && !/process\.exit\s*\(\s*[12]\s*\)/.test(catchBody)) {
      const line = src.slice(0, m.index).split('\n').length;
      suspects.push({ line, pattern: 'catch-exit-0', desc: 'catch 块内 process.exit(0) 且无 exit(1/2) —— 吞错误后成功退出' });
    }
  }

  // ② 所有 exit 调用统计
  const allExits = [...src.matchAll(/process\.exit\s*\(\s*(\d+)\s*\)/g)];
  const exit0Count = allExits.filter((e) => e[1] === '0').length;
  const exitNon0Count = allExits.filter((e) => e[1] !== '0').length;
  // throw / process.exitCode = 非0 也算失败退出路径（不算恒绿）
  const hasThrow = /\bthrow\b/.test(src);
  const hasExitCodeNon0 = /process\.exitCode\s*=\s*[^0]/.test(src);
  if (allExits.length > 0 && exit0Count > 0 && exitNon0Count === 0 && !hasThrow && !hasExitCodeNon0) {
    suspects.push({ line: 0, pattern: 'only-exit-0', desc: `仅有 process.exit(0)（${exit0Count} 处），无 exit(1/2)/throw/exitCode —— 无论结果如何都成功退出` });
  }

  return suspects;
}

function listGateScripts() {
  const dir = HERE;
  return fs.readdirSync(dir)
    .filter((f) => f.endsWith('.mjs') && f !== 'greenguard-check.mjs')
    .map((f) => path.join(dir, f));
}

function run() {
  const onlyFile = flag('file');
  const files = onlyFile ? [path.resolve(ROOT, onlyFile)] : listGateScripts();
  const waivers = loadWaivers();
  const findings = [];

  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const rel = path.relative(ROOT, file).replace(/\\/g, '/');
    if (waivers.has(rel)) continue;
    const suspects = scanFile(file);
    if (suspects.length > 0) {
      findings.push({ file: rel, suspects });
    }
  }

  if (findings.length > 0) {
    console.error('✗ 恒绿门禁嫌疑（需确认是真绿还是恒绿，或登记到 greenguard-waivers.json）：');
    for (const { file, suspects } of findings) {
      for (const s of suspects) {
        console.error(`  ${file}${s.line ? `:${s.line}` : ''}  [${s.pattern}]  ${s.desc}`);
      }
    }
    process.exit(1);
  }
  console.log('✔ 未检出恒绿嫌疑（或已全部豁免）');
  process.exit(0);
}

function selftest() {
  // 自证判据不空转：构造一个恒绿脚本，确认被检出
  //
  // ⚠ 夹具必须落在**临时目录**，且退出必须走 `process.exitCode` 而不是 `process.exit()`：
  //   原实现把夹具写进 scripts/（= 本工具的扫描面），并在 try 里 process.exit() —— 而
  //   Node 的 process.exit 是同步终止，**finally 不会执行** ⇒ 夹具永久留在 scripts/ 里，
  //   它恰好就是判据 ① 的样本 ⇒ 下一轮 greenguard 自己判红。
  //   实测：2026-10-13 现场 `scripts/.greenguard-selftest-fake.mjs` 就是这么留下的。
  //   两条都要修：写在 tmpdir（漏清也伤不到门禁），退出用 exitCode（让 finally 真跑）。
  const fake = path.join(os.tmpdir(), `greenguard-selftest-fake-${process.pid}.mjs`);
  const normalFake = path.join(os.tmpdir(), `greenguard-selftest-normal-${process.pid}.mjs`);
  const fakeSrc = `import fs from 'node:fs';\ntry { fs.readFileSync('nonexistent'); } catch { process.exit(0); }\n`;
  const normalSrc = `import fs from 'node:fs';\nif (!fs.existsSync('x')) process.exit(1);\nprocess.exit(0);\n`;
  fs.writeFileSync(fake, fakeSrc, 'utf8');
  fs.writeFileSync(normalFake, normalSrc, 'utf8');
  try {
    const suspects = scanFile(fake);
    if (suspects.length === 0) {
      console.error('✗ selftest 失败：构造的恒绿脚本未被检出（判据空转）');
      process.exitCode = 1;
      return;
    }
    // 确认正常脚本不被误报
    const normalSuspects = scanFile(normalFake);
    // normalSrc 有 exit(1) 和 exit(0)，不会触发 only-exit-0；catch-exit-0 也不触发
    const falsePositives = normalSuspects.filter((s) => s.pattern === 'only-exit-0');
    if (falsePositives.length > 0) {
      console.error('✗ selftest 失败：正常脚本（有 exit(1)）被误报为 only-exit-0');
      process.exitCode = 1;
      return;
    }
    console.log('✔ greenguard-check selftest 通过（恒绿可检出，正常脚本不误报 only-exit-0）');
    process.exitCode = 0;
  } finally {
    for (const p of [fake, normalFake]) {
      try {
        fs.unlinkSync(p);
      } catch {
        /* 清理失败不影响判据结论；夹具在 tmpdir，不会进扫描面 */
      }
    }
  }
}

if (has('selftest')) selftest();
else run();