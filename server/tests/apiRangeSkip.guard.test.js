import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const savedSecureDir = process.env.MYSQL_SECURE_FILE_DIR;
delete process.env.MYSQL_SECURE_FILE_DIR;
const { default: CASES } = await import('../../e2e/api-range-lab/cases.mjs?api-range-skip-guard');
if (savedSecureDir === undefined) delete process.env.MYSQL_SECURE_FILE_DIR;
else process.env.MYSQL_SECURE_FILE_DIR = savedSecureDir;

const ctx = {
  state: {},
  note() {},
  get: async () => ({ json: { data: { available: false } } }),
};

test('api-range：缺 secure_file_priv 的 sqlmap fileWrite 必须显式 SKIP，不得静默 PASS', async () => {
  const c = CASES.find((item) => item.group === 'sqlmap' && item.name.includes('--file-write'));
  assert.ok(c, '找不到 sqlmap fileWrite 用例');
  const out = await c.run(ctx);
  assert.ok(out instanceof Error && out.__skip === true, '缺前置必须返回 __skip Error，不能 return undefined');
  assert.match(out.message, /MYSQL_SECURE_FILE_DIR/);
});

test('api-range：前置扫描缺席的 sqlmap export 必须显式 SKIP，不得静默 PASS', async () => {
  const c = CASES.find((item) => item.group === 'sqlmap' && item.name.includes('report/export'));
  assert.ok(c, '找不到 sqlmap export 用例');
  const out = await c.run(ctx);
  assert.ok(out instanceof Error && out.__skip === true, '前置未执行必须返回 __skip Error，不能 return undefined');
  assert.match(out.message, /前置 fileWrite 用例未产出真实扫描/);
});

test('CI：api-range 必须注入 secure_file_priv 目录，文件读写两条不得环境性跳过', () => {
  const ci = readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const start = ci.indexOf('- name: api-range-lab 接口层靶场');
  assert.ok(start >= 0, 'CI 找不到 api-range 步骤');
  const end = ci.indexOf('\n      - name:', start + 1);
  const step = ci.slice(start, end < 0 ? undefined : end);
  assert.match(step, /MYSQL_SECURE_FILE_DIR:\s*\/tmp\/mysql-fw-lab/, 'api-range 未注入已挂载的 secure_file_priv 目录');
});

test('CI：api-range 失败现场与引擎日志必须上传，且旧验收报告不得张冠李戴', () => {
  const ci = readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const cleanup = ci.indexOf('rm -f e2e/results/acceptance-report.md');
  const apiRange = ci.indexOf('- name: api-range-lab 接口层靶场');
  assert.ok(cleanup >= 0 && cleanup < apiRange, '必须在 api-range 开跑前清理旧验收报告');
  const upload = ci.indexOf('name: acceptance-report');
  assert.ok(upload >= 0, '找不到 acceptance artifact 上传步骤');
  const block = ci.slice(upload, ci.indexOf('if-no-files-found:', upload));
  assert.match(block, /e2e\/api-range-lab\/out\/api-range-report\.json/, 'artifact 缺 api-range 报告');
  assert.match(block, /logs\/engine-api-range\.log/, 'artifact 缺 api-range 引擎日志');
});
