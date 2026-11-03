// ============================================================================
// tests/cli.registryOp.test.js —— [D200] CLI 注册表面接线（对标 sqlmap --reg-*）
//
// 为什么单独成文件：注册表面接进 runExploitRegistry（与 runExploit 同门同上下文），
// 判据从「行为」出发（与 exploitFlag.threeEntries.test.js 同形态，不读源码正则）：
//   · 门：EXPLOIT_ENABLED / --authorized / 注入点缺失 → 各自的拒绝信息（零网络）；
//   · 分发：read/add/del 三操作落到 Exploiter 对应方法且参数归一正确（prototype patch）；
//   · 参数面：--reg-key 优先于操作旗标速记、值型旗标忘给值（落 true）按缺失报错、
//     多操作同给/零操作 → 明确报错且不触达引擎。
// 注意：cli.js 导入即加载全模块（main 有 invokedDirectly 守卫不会执行）；
// Exploiter 用 prototype patch（exploitRoutes 模块级实例同理，方法查表发生在调用时）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Exploiter } from '../src/engine/Exploiter.js';

const { runExploitRegistry } = await import('../bin/cli.js');

const REPORT = {
  vulns: [{ pointId: 'p1', dbms: 'SQL Server' }],
  points: [{ id: 'p1', originalValue: '1', location: 'url', param: 'q' }],
  target: {},
  dbms: 'SQL Server',
};

/** 捕获 console 输出并还原（runExploitCore 走 stderr 提示、stdout 结果 JSON） */
async function capture(fn) {
  const err = [];
  const out = [];
  const oe = console.error;
  const ol = console.log;
  console.error = (...a) => err.push(a.join(' '));
  console.log = (...a) => out.push(a.join(' '));
  try {
    return { ret: await fn(), err: err.join('\n'), out: out.join('\n') };
  } finally {
    console.error = oe;
    console.log = ol;
  }
}

/** patch Exploiter 原型上的注册表方法，记录调用与返回值；withFn 结束还原 */
function patchRegistryOps(impls) {
  const calls = { read: [], add: [], del: [] };
  const orig = {
    read: Exploiter.prototype.registryRead,
    add: Exploiter.prototype.registryWrite,
    del: Exploiter.prototype.registryDelete,
  };
  Exploiter.prototype.registryRead = async (ctx, opts) => { calls.read.push(opts); return impls.read ? impls.read(opts) : { ok: true, channel: 'read' }; };
  Exploiter.prototype.registryWrite = async (ctx, opts) => { calls.add.push(opts); return impls.add ? impls.add(opts) : { ok: true, channel: 'add' }; };
  Exploiter.prototype.registryDelete = async (ctx, opts) => { calls.del.push(opts); return impls.del ? impls.del(opts) : { ok: true, channel: 'del' }; };
  return { calls, restore: () => { Exploiter.prototype.registryRead = orig.read; Exploiter.prototype.registryWrite = orig.add; Exploiter.prototype.registryDelete = orig.del; } };
}

function withFlagEnv(authorized, fn) {
  const prevEnabled = process.env.EXPLOIT_ENABLED;
  process.env.EXPLOIT_ENABLED = '1';
  return Promise.resolve(fn()).finally(() => {
    if (prevEnabled === undefined) delete process.env.EXPLOIT_ENABLED;
    else process.env.EXPLOIT_ENABLED = prevEnabled;
  });
}

test('门①：EXPLOIT_ENABLED 未开 → 拒绝且不触达引擎', async () => {
  const prev = process.env.EXPLOIT_ENABLED;
  delete process.env.EXPLOIT_ENABLED;
  const p = patchRegistryOps({});
  try {
    const { ret, err } = await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: true, regKey: 'k' }));
    assert.equal(ret, null);
    assert.match(err, /利用操作未启用/);
    assert.equal(p.calls.read.length, 0);
  } finally {
    if (prev === undefined) delete process.env.EXPLOIT_ENABLED; else process.env.EXPLOIT_ENABLED = prev;
    p.restore();
  }
});

test('门②：未声明 --authorized → 拒绝', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const { ret, err } = await capture(() => runExploitRegistry(REPORT, { regRead: true, regKey: 'k' }));
      assert.equal(ret, null);
      assert.match(err, /--authorized/);
      assert.equal(p.calls.read.length, 0);
    } finally {
      p.restore();
    }
  });
});

test('分发 read：--reg-key/--reg-value 归一进 registryRead', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const { ret } = await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: true, regKey: 'SOFTWARE\\x', regValue: 'v' }));
      assert.equal(ret.channel, 'read');
      assert.deepEqual(p.calls.read, [{ key: 'SOFTWARE\\x', value: 'v' }]);
      assert.equal(p.calls.add.length + p.calls.del.length, 0);
    } finally {
      p.restore();
    }
  });
});

test('分发 read：操作旗标带值 = 键路径速记；--reg-key 优先', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: 'SOFTWARE\\short' }));
      assert.deepEqual(p.calls.read[0], { key: 'SOFTWARE\\short', value: null });
      await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: 'SOFTWARE\\short', regKey: 'SOFTWARE\\explicit' }));
      assert.deepEqual(p.calls.read[1], { key: 'SOFTWARE\\explicit', value: null });
    } finally {
      p.restore();
    }
  });
});

test('分发 add：key/value/data/type 全量进 registryWrite', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const { ret } = await capture(() => runExploitRegistry(REPORT, {
        authorized: true, regAdd: true, regKey: 'k', regValue: 'v', regData: 'd', regType: 'REG_DWORD',
      }));
      assert.equal(ret.channel, 'add');
      assert.deepEqual(p.calls.add, [{ key: 'k', value: 'v', data: 'd', type: 'REG_DWORD' }]);
    } finally {
      p.restore();
    }
  });
});

test('分发 del：key/value 进 registryDelete（引擎侧 xp_regdelete 语义见 takeover 测试）', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const { ret } = await capture(() => runExploitRegistry(REPORT, { authorized: true, regDel: true, regKey: 'k', regValue: 'v' }));
      assert.equal(ret.channel, 'del');
      assert.deepEqual(p.calls.del, [{ key: 'k', value: 'v' }]);
    } finally {
      p.restore();
    }
  });
});

test('参数面：值型旗标忘给值（落 true）按缺失报错；add 缺 data / del 缺 value 同理', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const r1 = await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: true, regKey: true }));
      assert.equal(r1.ret, null);
      assert.match(r1.err, /缺少注册表键路径/);
      const r2 = await capture(() => runExploitRegistry(REPORT, { authorized: true, regAdd: true, regKey: 'k', regValue: 'v' }));
      assert.match(r2.err, /--reg-add 需 --reg-value/);
      const r3 = await capture(() => runExploitRegistry(REPORT, { authorized: true, regDel: true, regKey: 'k' }));
      assert.match(r3.err, /--reg-del 需 --reg-value/);
      assert.equal(p.calls.read.length + p.calls.add.length + p.calls.del.length, 0, '校验失败不得触达引擎');
    } finally {
      p.restore();
    }
  });
});

test('参数面：多操作同给 / 零操作 → 明确报错不触达引擎', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const r1 = await capture(() => runExploitRegistry(REPORT, { authorized: true, regRead: true, regAdd: true, regKey: 'k' }));
      assert.match(r1.err, /一次只执行一种/);
      const r2 = await capture(() => runExploitRegistry(REPORT, { authorized: true }));
      assert.match(r2.err, /未指定注册表操作/);
      assert.equal(p.calls.read.length + p.calls.add.length + p.calls.del.length, 0);
    } finally {
      p.restore();
    }
  });
});

test('门③：报告无注入点 → 拒绝（与 runExploit 同门）', async () => {
  await withFlagEnv(true, async () => {
    const p = patchRegistryOps({});
    try {
      const { ret, err } = await capture(() => runExploitRegistry({ vulns: [], points: [] }, { authorized: true, regRead: true, regKey: 'k' }));
      assert.equal(ret, null);
      assert.match(err, /未发现注入点/);
      assert.equal(p.calls.read.length, 0);
    } finally {
      p.restore();
    }
  });
});
