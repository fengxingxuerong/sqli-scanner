import { randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { extractFailureDetails } from './failureDetail.mjs';

export const TEST_EVIDENCE_KEEP = 8;

function countsOf(output) {
  const counts = {};
  for (const key of ['tests', 'pass', 'fail', 'skipped']) {
    const m = String(output || '').match(new RegExp(`^# ${key} (\\d+)$`, 'm'));
    counts[key] = m ? Number(m[1]) : null;
  }
  return counts;
}

function safeLabel(value) {
  return String(value || 'run').replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'run';
}

export function pruneTestEvidence(root, keep = TEST_EVIDENCE_KEEP) {
  if (!Number.isInteger(keep) || keep < 1) throw new Error(`TEST_EVIDENCE_KEEP 必须为正整数，实得 ${keep}`);
  const dir = join(root, 'logs', 'test-evidence');
  let names;
  try {
    names = readdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  const groups = new Map();
  for (const name of names) {
    const ext = name.endsWith('.log') ? '.log' : name.endsWith('.json') ? '.json' : null;
    if (!ext) continue;
    const base = name.slice(0, -ext.length);
    const file = join(dir, name);
    const group = groups.get(base) || { files: [], mtimeMs: 0 };
    group.files.push(file);
    group.mtimeMs = Math.max(group.mtimeMs, statSync(file).mtimeMs);
    groups.set(base, group);
  }
  const removed = [...groups.entries()]
    .sort((a, b) => b[1].mtimeMs - a[1].mtimeMs)
    .slice(keep)
    .flatMap(([, group]) => {
      for (const file of group.files) rmSync(file, { force: true });
      return group.files;
    });
  return removed;
}

export function writeTestEvidence({ root, suite, attempt, command, exitCode, output, now = new Date() }) {
  const dir = join(root, 'logs', 'test-evidence');
  mkdirSync(dir, { recursive: true });
  const stamp = now.toISOString().replace(/[-:.]/g, '');
  const nonce = randomBytes(4).toString('hex');
  const base = `${stamp}-${process.pid}-${safeLabel(suite)}-${safeLabel(attempt)}-${nonce}`;
  const outputPath = join(dir, `${base}.log`);
  const metaPath = join(dir, `${base}.json`);
  const text = String(output ?? '');
  const meta = {
    createdAt: now.toISOString(),
    suite,
    attempt,
    command,
    exitCode: exitCode ?? null,
    counts: countsOf(text),
    failures: extractFailureDetails(text, Number.MAX_SAFE_INTEGER),
    outputFile: relative(root, outputPath).replace(/\\/g, '/'),
  };
  writeFileSync(outputPath, text, 'utf8');
  writeFileSync(metaPath, `${JSON.stringify(meta, null, 2)}\n`, 'utf8');
  pruneTestEvidence(root);
  return { outputPath, metaPath, ...meta };
}
