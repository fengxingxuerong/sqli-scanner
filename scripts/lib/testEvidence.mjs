import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { extractFailureDetails } from './failureDetail.mjs';

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
  return { outputPath, metaPath, ...meta };
}
