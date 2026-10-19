// ============================================================================
// bodyParamsCompanion.guard.test.js —— [D112 2026-10-20] POST 表单伴随字段不变量
//
// ── 为什么有这个文件（真实外部靶场抓出来的静默假阴性）─────────────────────────
// 第三方靶场 **DVWA medium**（`vulnerabilities/sqli/source/medium.php`）的执行开关是
// `isset($_POST['Submit'])` —— 表单里那个「提交按钮」字段必须随请求一起发出，服务端
// 才会执行 `SELECT ... WHERE user_id = $id`。
//
// 本仓此前的行为（`e2e/dvwa-lab` 首跑实测，124 条探针全记录）：
//   · 用户给 `--body '{"id":"1","Submit":"Submit"}'` ⇒ TargetParser 生成 body 点
//   · 但 `buildInjectionRequest` 用 `req.data = { ...(point.formValues || {}) }` 重建报文，
//     而 `formValues` **只有页面抓表单那条路径**才赋值（TargetParser 第 510/526/695 行）
//     ⇒ bodyParams 路径生成的点 `formValues === null`
//   · 结果：注入请求体只剩 `id=<payload>`，`Submit` 被静默丢弃
//   · 服务端因缺 Submit 根本不执行查询 ⇒ 124 条响应**字节数完全相同**（4620）
//     ⇒ 布尔真假恒等、UNION 无回显、报错无信号 ⇒ **0 检出，且不报任何错**
//   · 与 D91 那条 cookie 假阴性同形：报告写「未检出」，和「这个站没有注入」无法区分
//
// 修法（TargetParser 第 3 节）：bodyParams 生成的点自带完整表单快照
// `{ formValues: { ...bodyAll } }`，注入时只覆盖单键、其余原样保留（sqlmap 同口径）。
//
// 本文件钉的是**两条结构不变量**——只补 DVWA 这一个用例治不了同族缺口：
// 任何「以隐藏字段/提交按钮/CSRF 字段为开关」的 POST 表单都会重演同型假阴性。
// 判据性质：纯内存断言（无网络、无子进程），秒级，可进 CI 常驻。
// 真机侧由 e2e/dvwa-lab（外部裁判 3 号）承担。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest } from '../src/engine/injection.js';

/** DVWA medium 形态：注入点 id + 伴随字段 Submit（服务端以它作为执行开关） */
function dvwaMediumTarget() {
  return {
    mode: 'http',
    baseUrl: 'http://dvwa.local/vulnerabilities/sqli/',
    method: 'POST',
    bodyParams: { id: '1', Submit: 'Submit' },
    cookieParams: {},
    headerParams: {},
    jsonBody: null,
    config: {},
  };
}

test('不变量①：bodyParams 生成的每个 body 点都必须自带完整表单快照（formValues 含全部伴随字段）', async () => {
  const target = dvwaMediumTarget();
  const points = await new TargetParser().discover(target, undefined);
  const bodyPoints = points.filter((p) => p.location === 'body');
  assert.ok(bodyPoints.length >= 1, 'bodyParams 应至少产出 1 个 body 注入点');
  for (const p of bodyPoints) {
    assert.ok(
      p.formValues && typeof p.formValues === 'object',
      `body 点 ${p.param} 缺 formValues ⇒ 注入请求会丢掉伴随字段（DVWA medium 假阴性原形）`
    );
    // 快照必须是**完整表单**，不能只有注入点自身
    assert.equal(p.formValues.Submit, 'Submit', `body 点 ${p.param} 的 formValues 缺伴随字段 Submit`);
    assert.equal(p.formValues.id, '1', `body 点 ${p.param} 的 formValues 缺自身原值（应保持原始值）`);
  }
});

test('不变量②：注入请求体保留伴随字段，且只覆盖当前注入点（DVWA medium 逐字段对齐）', async () => {
  const target = dvwaMediumTarget();
  const points = await new TargetParser().discover(target, undefined);
  const idPoint = points.find((p) => p.location === 'body' && p.param === 'id');
  assert.ok(idPoint, '未生成 id 的 body 注入点');

  const req = buildInjectionRequest(target, idPoint, '1 AND 1=1#');
  const data = new URLSearchParams(String(req.data));
  assert.equal(data.get('id'), '1 AND 1=1#', '注入值必须落在 id 上');
  assert.equal(data.get('Submit'), 'Submit', '伴随字段 Submit 必须原样保留（丢掉 ⇒ 服务端不执行查询 ⇒ 全漏检）');
  assert.equal([...data.keys()].length, 2, `请求体字段数应为 2，实际 ${[...data.keys()]}`);
  // multipart 分支不触发时 Content-Type 必须是 urlencoded（PHP 的 $_POST 才解析得到）
  const ct = Object.keys(req.headers).find((k) => /^content-type$/i.test(k));
  assert.match(String(req.headers[ct] || ''), /x-www-form-urlencoded/, '表单点必须是 urlencoded');
});

test('不变量③：多伴随字段场景下每个注入点各自独立覆盖（互不影响、不串行污染）', async () => {
  const target = {
    ...dvwaMediumTarget(),
    bodyParams: { id: '1', Submit: 'Submit', user_token: 'tok-123' },
  };
  const points = await new TargetParser().discover(target, undefined);
  for (const name of ['id', 'Submit', 'user_token']) {
    const p = points.find((q) => q.location === 'body' && q.param === name);
    assert.ok(p, `未生成 ${name} 的 body 注入点`);
    const req = buildInjectionRequest(target, p, 'X');
    const data = new URLSearchParams(String(req.data));
    assert.equal(data.get(name), 'X', `${name} 的注入值必须生效`);
    for (const other of ['id', 'Submit', 'user_token'].filter((n) => n !== name)) {
      assert.equal(data.get(other), p.formValues[other], `注入 ${name} 时 ${other} 必须保持原值`);
    }
  }
});

test('变异自证：点缺 formValues 时伴随字段确实会被丢掉（本判据有牙，不是恒真断言）', () => {
  const target = dvwaMediumTarget();
  // 手工构造「修复前形态」的点：无 formValues
  const legacyPoint = { location: 'body', param: 'id', originalValue: '1' };
  const legacyReq = buildInjectionRequest(target, legacyPoint, '1 AND 1=1#');
  const legacyData = new URLSearchParams(String(legacyReq.data));
  assert.equal(legacyData.get('Submit'), null, '未修复形态必须丢掉 Submit —— 否则本文件判据恒真');
  assert.equal([...legacyData.keys()].length, 1, '未修复形态请求体只剩注入点自身');
});
