// [2026-09-29] core/getHeader.js 直接单测 —— 全仓唯一响应头读取口径。
//
// 为什么补这一组：getHeader 是「WAF 判定」与「扫描有效性判定」的共同前置，
// 此前三处各持一份独立实现且已漂移（docs/优化空间评估-2026-09-26.md §3）。
// 收敛后本文件钉住统一语义：任何一处想再"自己写一份"时，这里的口径就是判据。
//
// ⚠️ 数组值语义（set-cookie 等多值头）刻意是 **String(v) 逗号拼接**，不是取首元素：
//   WAF 指纹（F5 BIGIPServer 等）要匹配的正是多值 set-cookie 的整体，
//   取首元素会漏掉"签名在第二条 cookie"的命中。见 getHeader.js 文件头论证。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { getHeader } from '../src/core/getHeader.js';
// scanValidityGuard 必须与唯一实现是**同一个函数**（它对内自用、对外再导出）；
// 若有人改回本地私有实现，这条身份断言立刻红。
import { getHeader as guardGetHeader } from '../src/core/scanValidityGuard.js';

test('getHeader: 普通对象大小写不敏感取值', () => {
  assert.equal(getHeader({ 'Content-Type': 'application/json' }, 'content-type'), 'application/json');
  assert.equal(getHeader({ 'x-waf-status': 'blocked' }, 'X-WAF-STATUS'), 'blocked');
  assert.equal(getHeader({ SERVER: 'cloudflare' }, 'server'), 'cloudflare');
});

test('getHeader: AxiosHeaders 样对象（.get 方法）走 .get 通道', () => {
  const axiosLike = {
    get: (k) => (String(k).toLowerCase() === 'x-waf-status' ? 'blocked' : null),
  };
  assert.equal(getHeader(axiosLike, 'X-Waf-Status'), 'blocked');
});

test('getHeader: .get 返回 null 时回退 entries 通道（不因 .get 存在而丢自有属性）', () => {
  const hybrid = {
    get: () => null, // Map 样 .get 对大小写变体拿不到值
    Server: 'cloudflare',
  };
  assert.equal(getHeader(hybrid, 'server'), 'cloudflare');
});

test('getHeader: 数组值按 String 拼接（多值 set-cookie 的 WAF 指纹依赖整体匹配）', () => {
  const res = { 'set-cookie': ['BIGipServerpool=123', 'TS01abc=xyz'] };
  assert.equal(getHeader(res, 'Set-Cookie'), 'BIGipServerpool=123,TS01abc=xyz');
});

test('getHeader: 缺失/空值口径 —— 缺失 undefined、空串是合法值（不得混淆）', () => {
  assert.equal(getHeader({ a: '1' }, 'b'), undefined);
  assert.equal(getHeader({ a: '' }, 'a'), '');
  assert.equal(getHeader({ a: null }, 'a'), undefined);
});

test('getHeader: 防御口径 —— null/undefined/非对象 headers 一律 undefined（不抛错）', () => {
  assert.equal(getHeader(null, 'server'), undefined);
  assert.equal(getHeader(undefined, 'server'), undefined);
  assert.equal(getHeader('cloudflare', 'server'), undefined);
  assert.equal(getHeader(42, 'server'), undefined);
});

test('getHeader: scanValidityGuard 的导出与唯一实现是同一个函数（防再分叉）', () => {
  assert.equal(guardGetHeader, getHeader);
});
