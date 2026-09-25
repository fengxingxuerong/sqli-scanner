// ============================================================================
// api.directScope.test.js —— 直连模式也必须受 scope（授权范围）约束
//
// 两条红线常被当成一条，这里分开（本文件引用的原话）：
//   · SSRF 防护管"别打自己人"（内网/回环/云元数据）
//   · scope 管"别打没授权的人"
// 直连分支过去以"直连不发起 HTTP 请求，跳过 SSRF 校验（无 SSRF 面）"为由，把 **两条一起**
// 跳过了。前一条判断成立（DB 连接是操作者明示意图），后一条不成立：配了 scope 仍可直连任意
// 数据库主机 —— 实测当时 `scope:['10.20.0.0/16']` 配着，`sanitizeStart` 照样放行
// `db:{driverType:'mysql', host:'10.0.0.9'}`。
//
// 断言的形状特意配齐九种，因为"漏放"和"错杀"都各有代价：
//   范围内 / 范围外 / **未配 scope（必须与历史一致，直连仍可任意主机）** /
//   主机只在 connectionString 里（在界内、越界各一）/ 内嵌驱动无主机（不出网⇒放行）/
//   网络驱动拿不到主机（未知即拒，fail closed）/ 域名通配命中与不命中
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { ErrorCode } from '../src/core/errors.js';

const SCOPE = ['10.20.0.0/16'];
const SQL = 'SELECT * FROM users WHERE id={INJECT}';

const direct = (db, config = {}) => sanitizeStart({ mode: 'direct', sqlTemplate: SQL, db, config });

test('直连：主机在授权范围内则放行', () => {
  const r = direct({ driverType: 'mysql', host: '10.20.1.5' }, { scope: SCOPE });
  assert.equal(r.mode, 'direct');
  assert.equal(r.db.host, '10.20.1.5');
});

test('直连：主机越界必须拒绝，且错误码是 SCOPE_VIOLATION（不是 INVALID_TARGET）', () => {
  // 错误码要对：调用方按码分支，"没授权"和"参数写错了"在 UI 上是两句话
  assert.throws(
    () => direct({ driverType: 'mysql', host: '10.0.0.9' }, { scope: SCOPE }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION && /scope/.test(e.message)
  );
});

test('未配 scope 时行为与历史一致（直连仍可任意主机）—— 这条不许被改动作废', () => {
  const r = direct({ driverType: 'mysql', host: '10.0.0.9' }, {});
  assert.equal(r.db.host, '10.0.0.9');
});

test('主机只出现在 connectionString 里时也要判定（界内放行 / 越界拒绝）', () => {
  assert.doesNotThrow(() => direct({ connectionString: 'mysql://u:p@10.20.9.9:3306/d' }, { scope: SCOPE }));
  assert.throws(
    () => direct({ connectionString: 'mysql://u:p@10.0.0.9:3306/d' }, { scope: SCOPE }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION
  );
});

test('内嵌驱动（内存/文件库）不出网 ⇒ 无范围可言，不得误杀', () => {
  for (const driverType of ['memory', 'sqljs', 'sqlite', 'pglite']) {
    assert.doesNotThrow(() => direct({ driverType }, { scope: SCOPE }), `${driverType} 不该被拒`);
  }
});

test('网络驱动却解析不出主机：拒绝（配了 scope 就等于期待"未知目标不放行"）', () => {
  assert.throws(
    () => direct({ driverType: 'mysql' }, { scope: SCOPE }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION && /无法确定数据库主机/.test(e.message)
  );
});

test('域名通配规则对直连主机同样生效', () => {
  assert.doesNotThrow(() => direct({ driverType: 'pg', host: 'db.internal.test' }, { scope: ['*.internal.test'] }));
  assert.throws(
    () => direct({ driverType: 'pg', host: 'db.other.test' }, { scope: ['*.internal.test'] }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION
  );
});

test('接线：HTTP 分支的 scope 断言没被这次改动弄坏', () => {
  assert.throws(
    () => sanitizeStart({ url: 'http://10.0.0.9/x?id=1', config: { scope: SCOPE } }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION
  );
  assert.doesNotThrow(() => sanitizeStart({ url: 'http://10.20.0.5/x?id=1', config: { scope: SCOPE } }));
});
