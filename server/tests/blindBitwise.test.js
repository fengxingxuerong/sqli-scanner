// blindBitwise 单测 v16：mock BIT_COUNT 正则按真实 cond 形态锚定
// （SUBSTRING(SELECT...,pos,1),16,10）—— pos 取 `),16,10) & ` 前的 `,<pos>,1` 段
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractBoolean } from '../src/engine/blindExtractor.js';

function makeMock(secret, { bitwise = true } = {}) {
  const state = { count: 0, bitCountSeen: 0 };
  const httpClient = {
    async request(opts) {
      state.count++;
      const url = String(opts.url || '');
      if (/BIT_COUNT/.test(url)) state.bitCountSeen++;
      const m = /id=\d+\s+AND\s+(.+?)--\s*-/.exec(url);
      if (!m) return { data: 'BASEPAGE', status: 200 };
      const cond = m[1];
      if (cond === '1=2') return { data: 'FALSEPAGE', status: 200 };
      // 等值验证：ASCII(SUBSTRING(expr,pos,1))=N
      const eq = /ASCII\(SUBSTRING\((.*),(\d+),1\)\)=(\d+)/.exec(cond);
      if (eq) {
        const pos = Number(eq[2]);
        const byte = pos >= 1 && pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: byte === Number(eq[3]) ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // 位平面：BIT_COUNT(CONV(HEX(SUBSTRING(expr,pos,1)),16,10) & mask)
      const bc = /BIT_COUNT\(CONV\(HEX\(SUBSTRING\((.*),(\d+),1\),16,10\) & (\d+)\)/.exec(cond);
      if (bc) {
        const pos = Number(bc[2]);
        const mask = Number(bc[3]);
        const byte = pos >= 1 && pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: (byte & mask) !== 0 ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // 字符类收窄：ASCII(SUBSTRING(expr,pos,1)) BETWEEN lo AND hi
      const bw = /ASCII\(SUBSTRING\((.*),(\d+),1\)\) BETWEEN (\d+) AND (\d+)/.exec(cond);
      if (bw) {
        const pos = Number(bw[2]);
        const lo = Number(bw[3]);
        const hi = Number(bw[4]);
        const byte = pos >= 1 && pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: byte >= lo && byte <= hi ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // 二分：ASCII(SUBSTRING(expr,pos,1))>N
      const gt = /ASCII\(SUBSTRING\((.*),(\d+),1\)\)>(\d+)/.exec(cond);
      if (gt) {
        const pos = Number(gt[2]);
        const n = Number(gt[3]);
        const byte = pos >= 1 && pos <= secret.length ? secret.charCodeAt(pos - 1) : 0;
        return { data: byte > n ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // 长度：LENGTH(expr)>N
      if (/LENGTH\(/.test(cond)) {
        const nM = />(\d+)\)$/.exec(cond);
        return { data: secret.length > Number(nM ? nM[1] : 0) ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      }
      // 整值复验：(expr)='<完整值>'
      const full = /\)='([^']*)'/.exec(cond);
      if (full) return { data: full[1] === secret ? 'TRUEPAGE' : 'FALSEPAGE', status: 200 };
      return { data: 'FALSEPAGE', status: 200 };
    },
  };
  return { httpClient, state };
}

function makeEx(ctx) {
  return {
    _extractCache: new Map(),
    async _send(c, v) {
      return c.httpClient.request({ method: 'GET', url: 'http://mock/num?id=' + v });
    },
  };
}

test('blindBitwise：位平面提取收敛到真值（MySQL 族）', async () => {
  const secret = 'bob';
  const { httpClient, state } = makeMock(secret, { bitwise: true });
  const ctx = {
    httpClient, dbms: 'MySQL', scanId: 't1',
    config: { blindBitwise: true, predictOutput: false, blindRobust: { extractVerify: true } },
    point: { id: 'p', location: 'url', param: 'id', originalValue: '1', boundary: '' },
    target: { url: 'http://mock/num?id=1' },
  };
  const got = await extractBoolean(makeEx(ctx), ctx, 'SELECT username FROM users WHERE id = 2');
  assert.equal(got, secret);
  assert.ok(state.bitCountSeen > 0, '应发出 BIT_COUNT 位平面探针');
});

test('blindBitwise 默认关闭：走原二分路径（零回归，无 BIT_COUNT 探针）', async () => {
  const secret = 'bob';
  const { httpClient, state } = makeMock(secret, { bitwise: false });
  const ctx = {
    httpClient, dbms: 'MySQL', scanId: 't2',
    config: { predictOutput: false },
    point: { id: 'p', location: 'url', param: 'id', originalValue: '1', boundary: '' },
    target: { url: 'http://mock/num?id=1' },
  };
  const got = await extractBoolean(makeEx(ctx), ctx, 'SELECT username FROM users WHERE id = 2');
  assert.equal(got, secret);
  assert.equal(state.bitCountSeen, 0, '默认关闭时不应发 BIT_COUNT 探针');
});
