// dumpAllDatabases 库级并发拖库单元测试
// 桩 Extractor 内部的 enumerateDatabases / dumpDatabase，聚焦验证：
//   1) 库级并发调度（在途峰值 ≥ 并发度，非串行）
//   2) 聚合结果带 db. 前缀，与 ScanManager._extract 取用方式对齐
//   3) 单库失败被 _concurrentMap 吞掉，不影响其他库（容错）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

test('dumpAllDatabases 库级并发 + 前缀聚合 + 单库失败容错', async () => {
  const ex = new Extractor();
  const dbs = ['dbA', 'dbB'];
  const seen = [];
  let inFlight = 0;
  let peak = 0;

  // 桩 enumerateDatabases：直接返回既定库列表（由 ScanManager 负责调用，此处不重测枚举）
  ex.enumerateDatabases = async () => dbs;

  // 桩 dumpDatabase：模拟异步 IO 以观测并发；dbB 抛错验证容错
  ex.dumpDatabase = async (ctx, db) => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await Promise.resolve(); // 让出事件循环，使并发请求能在途叠加（模拟真实异步 IO）
    seen.push(db);
    inFlight--;
    if (db === 'dbB') throw new Error('simulated dbB extraction failure');
    return {
      tables: [`${db}_t1`, `${db}_t2`],
      columns: { [`${db}_t1`]: ['a', 'b'] },
      rows: { [`${db}_t1`]: [{ a: '1', b: '2' }] },
    };
  };

  const ctx = { config: { dumpDatabaseConcurrency: 2, dumpConcurrency: 4 } };
  const res = await ex.dumpAllDatabases(ctx, dbs);

  // 两库都被调度
  assert.deepEqual(seen.sort(), ['dbA', 'dbB']);
  // 并发峰值 ≥ 2（证明非全串行）
  assert.ok(peak >= 2, `期望库级并发，实际峰值=${peak}`);
  // 聚合：databases 保持原序
  assert.deepEqual(res.databases, dbs);
  // 成功库结果正确聚合
  assert.deepEqual(res.tables.dbA, ['dbA_t1', 'dbA_t2']);
  // 失败库（dbB）不污染聚合（被 _concurrentMap 吞掉异常）
  assert.equal(res.tables.dbB, undefined, '失败库不应写入聚合');
  // 前缀聚合正确（columns/rows 加 db. 前缀）
  assert.deepEqual(res.columns['dbA.dbA_t1'], ['a', 'b']);
  assert.deepEqual(res.rows['dbA.dbA_t1'], [{ a: '1', b: '2' }]);
});
