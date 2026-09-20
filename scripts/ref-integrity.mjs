#!/usr/bin/env node
// ============================================================================
// scripts/ref-integrity.mjs —— 引用完整性门禁
//
// 为什么需要它（2026-09-20 实测教训）：
//   ci.yml 里两个 job 写着 `node e2e/tamper-matrix/run.js` 与 `node e2e/waf-lab/run.js`，
//   而这两个文件**根本不存在**（真入口是 tamper-test.mjs / compare-real.run.py）。
//   更糟的是它们都带 `continue-on-error: true` —— `node <不存在的文件>` 每次报
//   Cannot find module 却从不拦人，于是这两个 job **从未验证过任何东西**。
//   是靠人工 grep 才发现的，说明「引用路径存在性」缺一道自动闸门。
//
// 本门禁校验三处引用源里的**本地文件路径**是否真实存在：
//   ① .github/workflows/*.yml —— run: 步骤里的 node/python/bash/shell 调用
//   ② package.json（根）与 server/package.json —— scripts 里的 node/python 调用
//   ③ e2e/run-all.mjs —— 靶场注册表里的 entry 字段
//
// 只校验**本地文件**（相对路径）：npm / npx / cargo / docker 等外部命令不在此列。
// 不校验 `--flag=path` 形态的可选路径参数（那不是入口，缺失属合法）。
//
// 用法：
//   node scripts/ref-integrity.mjs            # 检查（违规则退出码 1）
//   node scripts/ref-integrity.mjs --json     # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const JSON_OUT = process.argv.includes('--json');

// 外部命令白名单：这些不是本地文件，不该被当路径校验
const EXTERNAL_CMDS = new Set([
  'npm', 'npx', 'pnpm', 'yarn', 'cargo', 'docker', 'docker-compose', 'make',
  'tsc', 'vitest', 'eslint', 'prettier', 'git', 'sh', 'bash', 'pwsh',
]);

/** 从一条命令串里抽出「像是本地入口文件」的路径，并带着它们各自的基准目录 */
function extractPaths(cmd) {
  const out = [];
  // 关键：`cd <dir> && node <path>` 里的 path 是**相对那个 dir** 的。
  // 不处理这个前缀就会误报（实测三例：package.json 的 server script、
  // server/package.json 的 start / cli —— 都是相对 server/ 的）。
  // 按 && / ; / | 切段，跟踪当前的 cd 目标。
  const segments = String(cmd).split(/&&|;|\|\|?|\n/);
  let base = '';
  for (const seg of segments) {
    const cdMatch = /^\s*cd\s+([^\s&;|]+)/.exec(seg);
    if (cdMatch) {
      base = cdMatch[1].replace(/^\.\//, '').replace(/\/$/, '');
    }
    // 匹配 node / python / python3 / tsx / deno 后跟的路径 token
    const re = /\b(?:node|python3?|tsx|deno)\s+((?:\.{0,2}\/)?[a-zA-Z0-9._@/-]+\.(?:m?js|cjs|ts|py))/g;
    let m;
    while ((m = re.exec(seg))) out.push({ ref: m[1], base });
  }
  return out;
}

/** 解析多行 run 块：YAML 里 `run: |` 后面的缩进行 */
function collectYamlRunBlocks(text) {
  const lines = text.split('\n');
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)-?\s*run:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const inline = m[2].trim();
    if (inline && inline !== '|' && inline !== '>' && inline !== '|-') {
      blocks.push({ line: i + 1, cmd: inline });
      continue;
    }
    // 块形式：收集后续缩进更深的行
    const buf = [];
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (!l.trim()) { buf.push(''); continue; }
      const li = l.search(/\S/);
      if (li <= indent) break;
      buf.push(l);
    }
    if (buf.length) blocks.push({ line: i + 1, cmd: buf.join('\n') });
    i += buf.length;
  }
  return blocks;
}

const findings = []; // { source, where, ref, resolved }

/**
 * @param {string} source      引用来源文件（相对 ROOT）
 * @param {string} where       位置描述（行号 / script 名）
 * @param {string} ref         被引用的路径 token
 * @param {string} [base='']   基准目录（相对 ROOT）——命令串里 `cd X &&` 的目标，
 *                             或 package.json 所在目录。`ref` 相对它解析。
 */
function checkRef(source, where, ref, base = '') {
  // 跳过 npm 脚本名（`node` 后跟的 token 若已在白名单里则不是文件）
  if (EXTERNAL_CMDS.has(ref)) return;
  // 绝对路径 / 明显不是仓库内文件的外部形状（如指向 node_modules 的包名）跳过
  if (path.isAbsolute(ref)) return;
  const rel = ref.replace(/^\.\//, '');
  const abs = path.join(ROOT, base, rel);
  const exists = fs.existsSync(abs);
  findings.push({
    source, where,
    ref: base ? path.posix.join(base, rel) : rel,
    exists,
  });
}

// ---------- ① workflows ----------
const WF_DIR = path.join(ROOT, '.github', 'workflows');
if (fs.existsSync(WF_DIR)) {
  for (const f of fs.readdirSync(WF_DIR).filter((x) => /\.ya?ml$/i.test(x))) {
    const rel = path.posix.join('.github/workflows', f);
    const text = fs.readFileSync(path.join(WF_DIR, f), 'utf8');
    for (const b of collectYamlRunBlocks(text)) {
      // workflow 的 run 步骤基准目录是仓库根
      for (const p of extractPaths(b.cmd)) checkRef(rel, `第 ${b.line} 行`, p.ref, p.base);
    }
    // [EXTRA] CI-FIX 注释里若提到「原来写的路径」，那不算引用，跳过——
    //  注释行以 # 开头，collectYamlRunBlocks 只取 run 块内容，天然排除。
  }
}

// ---------- ② package.json ----------
for (const pkgRel of ['package.json', 'server/package.json']) {
  const abs = path.join(ROOT, pkgRel);
  if (!fs.existsSync(abs)) continue;
  const pkg = JSON.parse(fs.readFileSync(abs, 'utf8'));
  // 基准目录 = package.json 所在目录（server/package.json 的 `node index.js` → server/index.js）
  const pkgBase = path.posix.dirname(pkgRel) === '.' ? '' : path.posix.dirname(pkgRel);
  for (const [name, cmd] of Object.entries(pkg.scripts || {})) {
    for (const p of extractPaths(String(cmd))) checkRef(pkgRel, `scripts.${name}`, p.ref, p.base || pkgBase);
    // npm run <script> 交叉引用：确保被引用的 script 真的存在
    const runRe = /\bnpm run ([a-zA-Z0-9:_-]+)/g;
    let m;
    while ((m = runRe.exec(String(cmd)))) {
      const target = m[1];
      if (!(target in (pkg.scripts || {}))) {
        findings.push({
          source: pkgRel, where: `scripts.${name}`, ref: `npm run ${target}`,
          exists: false, kind: 'script',
        });
      }
    }
  }
}

// ---------- ③ e2e/run-all.mjs 的 entry ----------
const RUN_ALL = path.join(ROOT, 'e2e', 'run-all.mjs');
if (fs.existsSync(RUN_ALL)) {
  const text = fs.readFileSync(RUN_ALL, 'utf8');
  const re = /entry:\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(text))) checkRef('e2e/run-all.mjs', 'entry', m[1]);
}

// ---------- 输出 ----------
const bad = findings.filter((f) => !f.exists);
const kindOf = (f) => (f.kind === 'script' ? '脚本引用' : '文件路径');

if (JSON_OUT) {
  console.log(JSON.stringify({ total: findings.length, missing: bad }, null, 2));
} else {
  console.log(`引用完整性门禁：校验 ${findings.length} 处本地引用`);
  console.log('  来源：.github/workflows/*.yml · package.json · server/package.json · e2e/run-all.mjs');
  console.log('');
  if (bad.length === 0) {
    console.log('✅ 全部存在');
  } else {
    console.error(`❌ 发现 ${bad.length} 处引用不存在：`);
    for (const f of bad) {
      console.error(`  - [${kindOf(f)}] ${f.source} → ${f.where}`);
      console.error(`      ${f.ref}`);
    }
    console.error('\n这类错误极其隐蔽：若被 continue-on-error 包裹，CI 会静默失败、从不拦人。');
  }
}

process.exit(bad.length ? 1 : 0);
