#!/usr/bin/env node
// ============================================================================
// scripts/coverage-calibration.mjs —— 覆盖率回归校准（spec 5.1.1 规则 6 / 模块 1.7）
//
// 解决什么：覆盖率阈值在 vitest.config.ts 里集中配置，但没有任何东西验证"门禁真的会拦"。
// 历史上阈值曾被设为 0（等于没门禁）或被注释掉，CI 照绿。本脚本：
//   ① 无参数：校验 vitest.config.ts 的 thresholds 存在、各值 > 0 且 < 100（合理范围）
//   ② --selftest：构造一个极低覆盖率的临时场景，跑覆盖率，确认门禁失败（判据不空转）
//
// 用法：
//   node scripts/coverage-calibration.mjs          # 校验阈值配置
//   node scripts/coverage-calibration.mjs --selftest  # 自证门禁会拦（跑 vitest，约 10s）
// ============================================================================
import { readFileSync, existsSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const selftest = process.argv.includes('--selftest');

function readThresholds() {
  const cfgPath = join(ROOT, 'vitest.config.ts');
  if (!existsSync(cfgPath)) throw new Error('vitest.config.ts 不存在');
  const src = readFileSync(cfgPath, 'utf8');
  const m = src.match(/thresholds:\s*\{[^}]*\}/s);
  if (!m) throw new Error('vitest.config.ts 中找不到 coverage.thresholds 配置');
  const block = m[0];
  const extract = (key) => {
    const v = block.match(new RegExp(`${key}:\\s*(\\d+(?:\\.\\d+)?)`));
    return v ? parseFloat(v[1]) : null;
  };
  return {
    statements: extract('statements'),
    branches: extract('branches'),
    functions: extract('functions'),
    lines: extract('lines'),
  };
}

function validateThresholds(t) {
  const errors = [];
  for (const [k, v] of Object.entries(t)) {
    if (v === null) errors.push(`${k} 缺失`);
    else if (v <= 0) errors.push(`${k}=${v} ≤ 0（等于没有门禁）`);
    else if (v >= 100) errors.push(`${k}=${v} ≥ 100（不可能达到）`);
  }
  return errors;
}

if (!selftest) {
  const t = readThresholds();
  const errors = validateThresholds(t);
  console.log('覆盖率阈值配置：', JSON.stringify(t));
  if (errors.length) {
    console.error('❌ 阈值配置不合理：');
    for (const e of errors) console.error(`  · ${e}`);
    process.exit(1);
  }
  console.log('✅ 阈值配置合理（全部 > 0 且 < 100）');
  process.exit(0);
}

// ── --selftest：构造极低覆盖率场景，确认门禁失败 ──────────────────────────
console.log('selftest：构造极低覆盖率场景，确认门禁失败...');

const tmpDir = join(ROOT, 'src', '__coverage_calibrate__');
const tmpSrc = join(tmpDir, 'calibrate.ts');
const tmpTest = join(tmpDir, 'calibrate.test.ts');

try {
  mkdirSync(tmpDir, { recursive: true });
  // 写一个有 4 个函数的源文件，但测试只覆盖 1 个 → 覆盖率 25% < 阈值 67%
  writeFileSync(tmpSrc, `
export function covered() { return 1; }
export function uncovered1() { return 2; }
export function uncovered2() { return 3; }
export function uncovered3() { return 4; }
`);
  writeFileSync(tmpTest, `
import { test, expect } from 'vitest';
import { covered } from './calibrate';
test('calibrate', () => { expect(covered()).toBe(1); });
`);

  const vitestBin = join(ROOT, 'node_modules', 'vitest', 'vitest.mjs');
  const r = spawnSync('node', [vitestBin, 'run', '--coverage', '--no-file-parallelism', tmpTest], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 30000,
  });
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  const code = r.status ?? -1;

  // vitest 覆盖率门禁失败时 exit code 非 0
  if (code !== 0) {
    console.log(`✅ selftest 通过：极低覆盖率场景被门禁拦截（exit=${code}）`);
    process.exit(0);
  } else {
    console.error(`❌ selftest 失败：极低覆盖率场景未被拦截（exit=0），门禁可能失效`);
    console.error('   vitest 输出尾部：', out.split('\n').slice(-10).join('\n'));
    process.exit(1);
  }
} finally {
  try { unlinkSync(tmpSrc); } catch { /* noop */ }
  try { unlinkSync(tmpTest); } catch { /* noop */ }
  try { require('node:fs').rmdirSync(tmpDir); } catch { /* noop */ }
}