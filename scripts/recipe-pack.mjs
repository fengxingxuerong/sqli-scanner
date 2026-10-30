#!/usr/bin/env node
// ============================================================================
// recipe-pack.mjs —— 配方包校验与导出（D179）
//
// 背景：CVE 披露窗口内「高保真 + 非破坏的定向检测」是流量入口（本周 assetnote 的单 CVE
// 扫描器 4 天 905★，见 docs/竞品对标-2026W44.md §一/C）。本仓不追「谁发得快」，只解决
// **配方怎么装进来、怎么保证不吹牛**：
//   · 条目格式直接复用官方扩展点 `--payload-file`（[D24]），不新增引擎语法；
//   · 元信息（目标特征/修复建议/A-B 口径）与条目放在一个包里，避免「payload 在 A 文件、
//     说明在 B 文档」两头漂移；
//   · **没有真机验证就不许写 CVE 号**：`demo: true` 的包带 `cve` 直接判红。
//
// 用法：
//   node scripts/recipe-pack.mjs --check                    # 校验 recipes/ 下全部配方
//   node scripts/recipe-pack.mjs --export <packDir> --out <file>  # 导出成 --payload-file
//   node scripts/recipe-pack.mjs --selftest                 # 自证判据不空转
// ============================================================================
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCustomEntries, mergeCustomEntries } from '../server/src/engine/payloads/customPayloads.js';
import { PAYLOAD_REGISTRY, isDestructivePayload, hasDestructiveSql } from '../server/src/engine/payloadRegistry.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const RECIPES_DIR = join(ROOT, 'recipes');
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

/** 身份字段（id / title / entries 非空） */
function validateIdentity(pack, errors) {
  if (!/^[a-z0-9][a-z0-9-]{2,}$/.test(String(pack.id || ''))) errors.push(`id 非法（小写 kebab，≥3 字符）：${pack.id}`);
  if (!pack.title) errors.push('缺 title');
  if (!Array.isArray(pack.entries) || !pack.entries.length) errors.push('entries 为空（配方至少要有一条检测条目）');
}

/** 破坏性条目必须自己声明 risk 3（配方不是高危池后门） */
function checkDestructive(entries, errors) {
  for (const e of entries) {
    if ((isDestructivePayload(e) || hasDestructiveSql(e)) && Number(e?.risk ?? 1) < 3) {
      errors.push(`条目 ${e?.id} 命中破坏性判据但 risk < 3（配方不是高危池后门：要么改 non-destructive，要么显式 risk 3）`);
    }
  }
}

/** 跨包 id 重复（两个配方用同一个 id，加载顺序会变成隐性依赖） */
function checkCrossPackIds(entries, allIds, errors) {
  if (!allIds) return;
  for (const e of entries) if (allIds.has(e?.id)) errors.push(`id 与其它配方重复：${e?.id}`);
}

/**
 * 条目层：引擎校验 → 冲突 → 破坏性 → 跨包重复。
 * @param {Array<object>} entries 原始条目
 * @param {{baseRegistry?: Array<object>, allIds?: Set<string>}} ctx 上下文
 * @param {string[]} errors 错误收集器
 * @returns {number} 通过引擎校验的条目数（0 表示条目层已不可用）
 */
function validateEntries(entries, ctx, errors) {
  // ① 与 --payload-file 同一判据（不另写一套）
  const v = validateCustomEntries(entries);
  for (const e of v.errors || []) errors.push(`条目校验：${e}`);
  if (!v.entries?.length) return 0;
  // ② 与内置注册表冲突即拒（只追加，不覆盖）
  try {
    mergeCustomEntries(ctx.baseRegistry || PAYLOAD_REGISTRY, v.entries);
  } catch (e) {
    errors.push(`与内置注册表冲突：${String(e?.message || e).slice(0, 160)}`);
  }
  checkDestructive(entries, errors);
  checkCrossPackIds(entries, ctx.allIds, errors);
  return v.entries.length;
}

/** 语义字段：demo 不许声称 CVE；非 demo 必须给 CVE + 受影响版本 + A/B + 修复建议 */
function validateSemantics(pack, errors) {
  const hasRemediation = Array.isArray(pack.remediation) && pack.remediation.length > 0;
  if (pack.demo === true) {
    if (pack.cve) errors.push('demo 配方不得声明 cve（没有真机验证就不许写 CVE 号）');
    if (!pack.ab) errors.push('demo 配方缺 ab（A/B 验证口径）');
    if (!hasRemediation) errors.push('demo 配方缺 remediation（修不好等于只给了一半交付）');
    return;
  }
  if (!CVE_RE.test(String(pack.cve || ''))) errors.push(`非 demo 配方必须给合法 cve（形如 CVE-2024-12345），实际：${pack.cve}`);
  if (!pack.affected) errors.push('缺 affected（受影响版本/产品）');
  if (!pack.ab) errors.push('缺 ab（A/B 验证口径：修前命中 / 修后 0）');
  if (!hasRemediation) errors.push('缺 remediation');
}

/**
 * 校验一个配方包（组合三个子判据；拆开是为了守住函数级复杂度硬上限）。
 * @param {unknown} pack `pack.json` 解析后的对象
 * @param {{baseRegistry?: Array<object>, allIds?: Set<string>}} [ctx] 内置注册表与跨包已用 id 集
 * @returns {{ok: boolean, errors: string[], entries: Array<object>}} 校验结果（`entries` 为原始条目）
 */
function validatePack(pack, ctx = {}) {
  if (!pack || typeof pack !== 'object' || Array.isArray(pack)) {
    return { ok: false, errors: ['pack.json 顶层必须是对象'], entries: [] };
  }
  const errors = [];
  validateIdentity(pack, errors);
  const entries = Array.isArray(pack.entries) ? pack.entries : [];
  const usable = entries.length ? validateEntries(entries, ctx, errors) : 0;
  validateSemantics(pack, errors);
  return { ok: errors.length === 0, errors, entries: usable ? entries : [] };
}

/**
 * 读取 recipes/ 下全部配方包（每个子目录一份 pack.json）。
 * @param {string} [dir] 配方根目录（默认仓库 recipes/）
 * @returns {Array<{dir: string, pack: object}>} 配方列表
 */
function listPacks(dir = RECIPES_DIR) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => join(dir, d.name))
    .filter((p) => existsSync(join(p, 'pack.json')))
    .sort()
    .map((p) => ({ dir: p, pack: JSON.parse(readFileSync(join(p, 'pack.json'), 'utf8')) }));
}

/** 校验全部配方，返回错误列表（空数组 = 全过） */
function checkAll(dir) {
  const packs = listPacks(dir);
  if (!packs.length) return [`${dir} 下没有任何 pack.json`];
  const allIds = new Set();
  const errors = [];
  for (const { dir: d, pack } of packs) {
    const r = validatePack(pack, { allIds });
    for (const e of r.errors) errors.push(`${d.replace(ROOT, '.')}: ${e}`);
    for (const e of r.entries) if (e?.id) allIds.add(e.id);
  }
  return errors;
}

function runCheck(dir = RECIPES_DIR) {
  const errors = checkAll(dir);
  if (errors.length) {
    console.error('[recipes] ✗ 配方校验未通过：');
    for (const e of errors) console.error('  · ' + e);
    process.exitCode = 1;
    return;
  }
  const packs = listPacks(dir);
  const total = packs.reduce((n, p) => n + (Array.isArray(p.pack.entries) ? p.pack.entries.length : 0), 0);
  console.log(`[recipes] ✓ ${packs.length} 个配方（共 ${total} 条检测条目）通过校验`);
  process.exitCode = 0;
}

function runExport(packRef, out) {
  const target = existsSync(join(packRef, 'pack.json')) ? join(packRef, 'pack.json') : packRef;
  if (!existsSync(target)) {
    console.error(`[recipes] ✗ 找不到配方：${packRef}`);
    process.exitCode = 1;
    return;
  }
  const pack = JSON.parse(readFileSync(target, 'utf8'));
  const r = validatePack(pack);
  if (!r.ok) {
    console.error('[recipes] ✗ 配方未通过校验，拒绝导出：');
    for (const e of r.errors) console.error('  · ' + e);
    process.exitCode = 1;
    return;
  }
  const dest = resolve(out);
  writeFileSync(dest, JSON.stringify(r.entries, null, 2) + '\n', 'utf8');
  console.log(`[recipes] 已导出 ${pack.id} → ${dest}（${r.entries.length} 条，可直接喂 --payload-file）`);
  process.exitCode = 0;
}

// ── 自证：每条判据都要能红 ────────────────────────────────────────────────────
const GOOD_ENTRY = {
  id: 'selftest-pg-err',
  dbms: ['PostgreSQL'],
  technique: 'error',
  level: 2,
  risk: 1,
  clause: ['where'],
  boundary: ["'"],
  template: "{ORIG}' AND CAST((SELECT 1/0) AS int)-- -",
  where: 'value',
  note: 'selftest',
};

/** 合格配方夹具（demo 形态：不带 cve） */
function goodPack(over = {}) {
  return { id: 'selftest-pack', title: '自证配方', demo: true, ab: { baseline: 'x', expect: 'y' }, remediation: ['参数化'], entries: [{ ...GOOD_ENTRY }], ...over };
}

function selftest() {
  const cases = [
    { name: 'demo 带 cve（未验证就声称 CVE）', pack: goodPack({ cve: 'CVE-2024-1234' }), expect: /不得声明 cve/ },
    { name: '非 demo 无 cve', pack: goodPack({ demo: false, ab: { baseline: 'x' } }), expect: /必须给合法 cve/ },
    { name: '非 demo 缺 affected', pack: goodPack({ demo: false, cve: 'CVE-2024-1234', ab: { baseline: 'x' } }), expect: /缺 affected/ },
    { name: 'entries 为空', pack: goodPack({ entries: [] }), expect: /entries 为空/ },
    { name: '条目缺 template', pack: goodPack({ entries: [{ id: 'x1', dbms: ['PostgreSQL'], technique: 'error' }] }), expect: /条目校验/ },
    { name: '条目 technique 越界', pack: goodPack({ entries: [{ ...GOOD_ENTRY, id: 'x2', technique: 'sideways' }] }), expect: /条目校验/ },
    { name: '包内 id 重复', pack: goodPack({ entries: [{ ...GOOD_ENTRY }, { ...GOOD_ENTRY }] }), expect: /条目校验/ },
    { name: '破坏性条目 risk 1（高危池后门）', pack: goodPack({ entries: [{ ...GOOD_ENTRY, id: 'x3', template: "{ORIG}'; DROP TABLE items-- -" }] }), expect: /risk < 3/ },
    { name: '与内置注册表 id 冲突', pack: goodPack({ entries: [{ ...GOOD_ENTRY, id: PAYLOAD_REGISTRY[0].id }] }), expect: /冲突/ },
    { name: '缺 ab（A/B 口径）', pack: goodPack({ ab: undefined }), expect: /缺 ab/ },
    { name: '缺 remediation', pack: goodPack({ remediation: [] }), expect: /缺 remediation/ },
  ];
  const failures = [];
  if (!validatePack(goodPack()).ok) failures.push(`合格夹具被误判：${JSON.stringify(validatePack(goodPack()).errors)}`);
  for (const c of cases) {
    const r = validatePack(c.pack);
    if (r.ok) failures.push(`「${c.name}」未被检出（判据空转）`);
    else if (!r.errors.some((e) => c.expect.test(e))) failures.push(`「${c.name}」报错文案不符（期望 ${c.expect}，实际 ${JSON.stringify(r.errors)}）`);
  }
  // 真仓必须能通过（否则门禁本身不可用）
  const realErrors = checkAll(RECIPES_DIR);
  if (realErrors.length) failures.push(`仓库自带配方未通过：${realErrors.join(' | ')}`);
  if (failures.length) {
    console.error('[recipes] ✗ selftest 失败：');
    for (const f of failures) console.error('  · ' + f);
    process.exitCode = 1;
    return;
  }
  console.log(`[recipes] ✓ selftest 通过：合格夹具不误判 + ${cases.length} 种回归各自被检出 + 仓库配方本身可过`);
  process.exitCode = 0;
}

const argv = process.argv.slice(2);
/** 支持 `--out=path` 与 `--out path` 两种写法（首版只认等号形式 ⇒ 导出悄悄落到 cwd） */
function outArg() {
  const eq = argv.find((a) => a.startsWith('--out='));
  if (eq) return eq.slice('--out='.length);
  const i = argv.findIndex((a) => a === '--out');
  return i >= 0 ? argv[i + 1] : null;
}
const idx = argv.findIndex((a) => a === '--export');
if (argv.includes('--selftest')) selftest();
else if (idx >= 0) runExport(argv[idx + 1], outArg() || join(process.cwd(), 'recipe-payloads.json'));
else runCheck();
