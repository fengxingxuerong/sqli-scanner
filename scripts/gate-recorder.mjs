#!/usr/bin/env node
/**
 * gate-recorder.mjs —— 门禁运行记录器（spec 5.1.1 规则 9）
 *
 * 解决什么：CI job 被 skip 时无记录 ⇒ "门禁跑过"这件事不可追溯。本脚本在每个 job
 * 执行后写入 gate-records/<run-id>/<job>.json，记录 job 名/状态/失败根因/运行 ID。
 * status 三态：passed / failed / not_run（未执行可区分于失败）。
 *
 * 用法（CI post 步骤或 ci-local.mjs 调用）：
 *   node scripts/gate-recorder.mjs --job=lint --status=passed
 *   node scripts/gate-recorder.mjs --job=acceptance --status=failed --reason="MySQL 不可用"
 *   node scripts/gate-recorder.mjs --job=docker --status=not_run --reason="本机无 docker"
 *   node scripts/gate-recorder.mjs --selftest
 *
 * 写入失败仅告警，不改变调用方退出码（门禁结论不因记录器故障而变）。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const RECORDS_DIR = path.join(ROOT, 'gate-records');
const argv = process.argv.slice(2);
const has = (n) => argv.includes(`--${n}`);
const flag = (n) => argv.find((a) => a.startsWith(`--${n}=`))?.slice(n.length + 3);

function getRunId() {
  // CI: GITHUB_RUN_ID；本地: 时间戳
  return process.env.GITHUB_RUN_ID || `local-${Date.now()}`;
}

function record(job, status, reason) {
  const runId = getRunId();
  const dir = path.join(RECORDS_DIR, runId);
  const file = path.join(dir, `${job}.json`);
  const entry = {
    jobName: job,
    status, // passed / failed / not_run
    failureReason: reason || null,
    runId,
    recordedAt: new Date().toISOString(),
  };
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(entry, null, 2) + '\n', 'utf8');
    return true;
  } catch (err) {
    // 写入失败仅告警，不影响门禁结论
    console.error(`⚠ gate-recorder 写入失败（不影响门禁结论）: ${err.message}`);
    return false;
  }
}

function run() {
  const job = flag('job');
  const status = flag('status');
  const reason = flag('reason');
  if (!job || !status) {
    console.error('用法: node scripts/gate-recorder.mjs --job=<name> --status=<passed|failed|not_run> [--reason=<text>]');
    process.exit(2);
  }
  if (!['passed', 'failed', 'not_run'].includes(status)) {
    console.error(`--status 必须是 passed/failed/not_run，得到: ${status}`);
    process.exit(2);
  }
  record(job, status, reason);
  process.exit(0);
}

function selftest() {
  // 自证：写入一条记录，读回确认三态可区分
  const testDir = path.join(RECORDS_DIR, 'selftest');
  try {
    fs.rmSync(testDir, { recursive: true, force: true });
  } catch { /* noop */ }

  const originalRunId = process.env.GITHUB_RUN_ID;
  process.env.GITHUB_RUN_ID = 'selftest';
  try {
    record('test-passed', 'passed', null);
    record('test-failed', 'failed', 'assertion error');
    record('test-skipped', 'not_run', 'dependency missing');

    const passed = JSON.parse(fs.readFileSync(path.join(RECORDS_DIR, 'selftest', 'test-passed.json'), 'utf8'));
    const failed = JSON.parse(fs.readFileSync(path.join(RECORDS_DIR, 'selftest', 'test-failed.json'), 'utf8'));
    const skipped = JSON.parse(fs.readFileSync(path.join(RECORDS_DIR, 'selftest', 'test-skipped.json'), 'utf8'));

    const ok =
      passed.status === 'passed' &&
      failed.status === 'failed' && failed.failureReason === 'assertion error' &&
      skipped.status === 'not_run' && skipped.failureReason === 'dependency missing';

    if (!ok) {
      console.error('✗ selftest 失败：记录三态不可区分或字段缺失');
      process.exit(1);
    }
    console.log('✔ gate-recorder selftest 通过（三态可区分，字段完整）');
    process.exit(0);
  } finally {
    process.env.GITHUB_RUN_ID = originalRunId;
    try { fs.rmSync(path.join(RECORDS_DIR, 'selftest'), { recursive: true, force: true }); } catch { /* noop */ }
  }
}

if (has('selftest')) selftest();
else run();