// ============================================================================
// tests/sidecarDiagUpload.guard.test.js —— 取证上传不得改写 sidecar 门禁结论（D290）
// ============================================================================
// 起因（CI run #439，2026-11-13）：`sidecar-build` 的「Build sidecar (SEA) + smoke」
// 已 success，只因 `if: always()` 的诊断 artifact 上传失败，整轮 CI 被判红；此前 6 次
// push 同配置全绿 ⇒ 非门禁的上传可用性绑架了门禁结论。
//
// 修法是**成对**的，缺一半就会退化成历史事故：
//   ① 上传步 continue-on-error（仅取证通道）；
//   ② 复核步显式读 `steps.sidecar_build.outcome`，非 success 即 exit 1。
// 本仓反复栽在「门禁步骤被 continue-on-error 吞成恒绿」（ci.yml 两处空转 job、
// compare-real.run.py、PG 靶场…），所以 ① 单独出现是**倒退**。本判据同时钉住：
//   · build 步绝不允许 continue-on-error；
//   · 复核步必须存在、必须 always、必须真能判红；
//   · 复核读的每个 step id 必须真实存在（D22 同款配对，否则 outcome 恒显示"未跑"）。
//
// 判据写成纯函数 + 合成反例自证：只查「字符串在不在」的守卫会被注释里的示例骗过，
// 所以每个规则都配一个从真实片段变形出来的反例，变形后判据必须报对应规则。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CI_YML = join(REPO, '.github', 'workflows', 'ci.yml');

/** 切出 sidecar-build job 片段（下一个顶层 job 为右边界），避免拿别的 job 的步骤蒙混 */
function sidecarSegment(raw) {
  const start = raw.indexOf('\n  sidecar-build:');
  if (start < 0) return '';
  const rest = raw.slice(start + 1);
  const nextRel = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:\n/);
  return nextRel > 0 ? rest.slice(0, nextRel + 1) : rest;
}

/** 去掉 job 级注释行后按 YAML step 边界切块 */
function splitSteps(seg) {
  const withoutComments = seg.split('\n').filter((l) => !/^\s{6,}#/.test(l)).join('\n');
  return withoutComments.split(/^      - /m).slice(1);
}

/**
 * 对某个 job 片段做静态判据，返回违规规则 id 数组（空 = 合格）。
 * 纯函数：既跑真实 ci.yml，也跑合成反例。
 */
function inspectSidecarJob(seg) {
  const v = [];
  const chunks = splitSteps(seg);
  // 分母守卫：切分逻辑失效（缩进变了 / 片段切空）必须报，而不是让后面全部"通过"
  if (seg.length < 800 || chunks.length < 8) v.push('step-denominator');

  const build = chunks.find((c) => /npm run build:sidecar/.test(c));
  const upload = chunks.find((c) => /upload-artifact@v4/.test(c) && /sidecar-build-diag/.test(c));
  const verdict = chunks.find((c) => /复核构建结论/.test(c));

  if (!build) v.push('build-step-missing');
  if (!upload) v.push('upload-step-missing');
  if (!verdict) v.push('verdict-step-missing');

  if (build) {
    if (!/^\s*id:\s*sidecar_build\s*$/m.test(build)) v.push('build-id-missing');
    // ① 绝不能落到门禁步骤上：这是本仓「continue-on-error 吞门禁」的历史红线
    if (/continue-on-error/.test(build)) v.push('build-swallowed');
  }
  if (upload) {
    if (!/^\s*id:\s*sidecar_diag_upload\s*$/m.test(upload)) v.push('upload-id-missing');
    if (!/if:\s*always\(\)/.test(upload)) v.push('upload-no-always');
    if (!/continue-on-error:\s*true/.test(upload)) v.push('upload-not-tolerant');
  }
  if (verdict) {
    if (!/if:\s*always\(\)/.test(verdict)) v.push('verdict-no-always');
    if (!/steps\.sidecar_build\.outcome/.test(verdict)) v.push('verdict-reads-build-missing');
    if (!/steps\.sidecar_diag_upload\.outcome/.test(verdict)) v.push('verdict-reads-upload-missing');
    if (!/\bexit 1\b/.test(verdict)) v.push('verdict-fails-red-missing');
    // D22 同款配对：复核读的 id 必须真的有 step 声明，否则 outcome 恒为 skipped/空
    const declared = new Set(
      chunks.flatMap((c) => [...c.matchAll(/^\s*id:\s*([a-zA-Z0-9_]+)\s*$/gm)].map((m) => m[1])),
    );
    const read = [...verdict.matchAll(/steps\.([a-zA-Z0-9_]+)\.outcome/g)].map((m) => m[1]);
    if (read.some((id) => !declared.has(id))) v.push('verdict-id-unpaired');
    if (!read.length) v.push('verdict-reads-nothing');
  }
  return v;
}

const realSegment = sidecarSegment(readFileSync(CI_YML, 'utf8'));

test('★ D290：sidecar-build 的取证上传容错与构建结论复核成对存在', () => {
  assert.ok(realSegment.length > 800, 'ci.yml 里定位不到 sidecar-build job（结构变了？）');
  assert.deepEqual(
    inspectSidecarJob(realSegment),
    [],
    '取证容错与结论复核必须成对：上传可降级，构建失败必须仍能让 job 判红',
  );
});

test('自证：片段切分的分母守卫不会把空片段放成绿', () => {
  assert.ok(inspectSidecarJob('').includes('step-denominator'));
  assert.ok(inspectSidecarJob('  sidecar-build:\n    steps: []\n').includes('step-denominator'));
});

test('自证：门禁步骤被 continue-on-error 吞掉时必须判红（历史红线）', () => {
  const bad = realSegment.replace(
    '        id: sidecar_build\n',
    '        id: sidecar_build\n        continue-on-error: true\n',
  );
  assert.notEqual(bad, realSegment, '变形没生效 ⇒ 自证是摆设');
  assert.ok(inspectSidecarJob(bad).includes('build-swallowed'));
});

test('自证：删掉复核步 / 复核判不了红 / 只读一个 outcome 都必须判红', () => {
  const cut = realSegment.indexOf('      - name: 复核构建结论');
  assert.ok(cut > 0, '找不到复核步起点');
  assert.ok(inspectSidecarJob(realSegment.slice(0, cut)).includes('verdict-step-missing'));

  // 只在复核步片段内换 exit：job 前面的「前置门禁检查」也有 `exit 1`，
  // 全局 replace 第一处会命中它 ⇒ 复核步仍会判红，反例就退化成假的（首跑实测踩过）。
  const noRed = realSegment.slice(0, cut) + realSegment.slice(cut).replace('exit 1', 'exit 0');
  assert.notEqual(noRed, realSegment, '变形没生效 ⇒ 自证是摆设');
  assert.ok(inspectSidecarJob(noRed).includes('verdict-fails-red-missing'));

  const noUploadRead = realSegment.replace(
    'steps.sidecar_diag_upload.outcome',
    'steps.sidecar_build.outcome',
  );
  assert.ok(inspectSidecarJob(noUploadRead).includes('verdict-reads-upload-missing'));
});

test('自证：复核读了不存在的 step id 时必须判红（D22 配对）', () => {
  const ghost = realSegment.replace('steps.sidecar_build.outcome', 'steps.ghost_step.outcome');
  assert.notEqual(ghost, realSegment, '变形没生效 ⇒ 自证是摆设');
  const v = inspectSidecarJob(ghost);
  assert.ok(v.includes('verdict-id-unpaired'));
  assert.ok(v.includes('verdict-reads-build-missing'));
});

test('自证：上传步去掉容错（红点原样复发）或去掉 build id 都必须判红', () => {
  const backTo439 = realSegment.replace('        continue-on-error: true\n', '');
  assert.notEqual(backTo439, realSegment, '变形没生效 ⇒ 自证是摆设');
  assert.ok(inspectSidecarJob(backTo439).includes('upload-not-tolerant'));

  const noBuildId = realSegment.replace('        id: sidecar_build\n', '');
  assert.ok(inspectSidecarJob(noBuildId).includes('build-id-missing'));
});
