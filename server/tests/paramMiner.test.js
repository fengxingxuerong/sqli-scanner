// ============================================================================
// paramMiner.test.js — 参数挖掘（paramMine，2026-10-02 竞品吸收批次）单测 + 集成
//
// 覆盖：
//   A. mineParams 核心算法（本地 http server 模拟五种目标形态）：
//      反射型隐藏参数命中 / 静态页零发现 / 全回显目标防噪护栏 / 请求预算硬顶 /
//      POST urlencoded 载体
//   B. TargetParser.discover 集成：挖到参数合成注入点（mined: true）；
//      JSON body 目标跳过挖掘；精确标记（值尾 *）跳过挖掘；onlyPoint 跳过挖掘
// ============================================================================

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import querystring from 'node:querystring';
import { HttpClient } from '../src/core/httpClient.js';
import { mineParams } from '../src/engine/discovery/paramMiner.js';
import { TargetParser } from '../src/engine/TargetParser.js';

// ─── 模拟目标服务器：按 query/body 里的参数名决定回显行为 ───
// hiddenLive：会「触发业务逻辑」的隐藏参数（值被回显进响应）；其余一律忽略。
let server;
let baseUrl;
let hitCount = 0;
let behavior = 'reflect'; // reflect | static | echo

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => resolve(raw));
  });
}

before(async () => {
  server = http.createServer(async (req, res) => {
    hitCount += 1;
    const u = new URL(req.url, 'http://x');
    const params = Object.fromEntries(u.searchParams);
    if (req.method === 'POST') {
      const body = querystring.parse(await readBody(req));
      Object.assign(params, body);
    }
    if (behavior === 'echo') {
      // 全回显目标：无条件把输入拼回响应（反射信号失效，且长度差处处存在 → 噪声目标）
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`ok ${req.url}${req.method === 'POST' ? JSON.stringify(params) : ''}`);
      return;
    }
    const reflected = Object.entries(params)
      .filter(([k]) => behavior === 'reflect' && k === 'debug')
      .map(([k, v]) => `${k}=${v}`)
      .join('&');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`ok${reflected ? ` ${reflected}` : ''}`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}/item`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

function freshClient() {
  return new HttpClient();
}

// ─── A. mineParams 核心算法 ───
describe('[paramMine] mineParams 核心算法', () => {
  test('反射型目标：发现隐藏参数 debug（分组探测+二分收敛）', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const result = await mineParams({
      baseUrl,
      client: freshClient(),
      existingParams: ['id'],
      log: () => {},
    });
    assert.deepEqual(result.names, ['debug']);
    assert.equal(result.aborted, null);
    assert.equal(result.reflectsAll, false);
    // 请求预算内的收敛行为：260 字典 9 组 + 二分 + 复核 + baseline/canary，远低于 150 硬顶
    assert.ok(result.requests < 60, `请求数异常偏大：${result.requests}`);
    assert.ok(hitCount === result.requests, '全部探测应真实发到目标');
  });

  test('静态页（无任何活参数）：零发现、不误报、不提前终止', async () => {
    behavior = 'static';
    const result = await mineParams({ baseUrl, client: freshClient() });
    assert.deepEqual(result.names, []);
    assert.equal(result.aborted, null);
  });

  test('全回显目标：防噪护栏触发（aborted=noisy），不产出海量假候选', async () => {
    behavior = 'echo';
    const result = await mineParams({ baseUrl, client: freshClient() });
    assert.deepEqual(result.names, []);
    assert.equal(result.aborted, 'noisy');
  });

  test('请求预算硬顶：maxRequests=3 时到顶即停（aborted=budget）', async () => {
    behavior = 'reflect';
    const result = await mineParams({
      baseUrl,
      client: freshClient(),
      options: { maxRequests: 3 },
    });
    assert.equal(result.requests, 3);
    assert.equal(result.aborted, 'budget');
    assert.deepEqual(result.names, []);
  });

  test('POST urlencoded 载体：同样能发现 body 里的隐藏参数', async () => {
    behavior = 'reflect';
    const result = await mineParams({
      baseUrl,
      method: 'POST',
      bodyParams: { a: '1' },
      client: freshClient(),
      existingParams: ['a'],
    });
    assert.deepEqual(result.names, ['debug']);
  });

  test('existingParams 已发现的参数不重复进候选', async () => {
    behavior = 'reflect';
    // 传入全部字典名 → 候选清空 → 只有 baseline/canary 两个请求
    const { PARAM_WORDLIST } = await import('../src/engine/discovery/paramWordlist.js');
    const result = await mineParams({
      baseUrl,
      client: freshClient(),
      existingParams: PARAM_WORDLIST,
    });
    assert.deepEqual(result.names, []);
    assert.equal(result.requests, 2); // baseline + canary
  });
});

// ─── B. TargetParser.discover 集成 ───
describe('[paramMine] TargetParser.discover 集成', () => {
  function makeTarget(over = {}) {
    return {
      mode: 'http',
      baseUrl,
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config: {},
      ...over,
    };
  }

  test('paramMine=true：挖到的隐藏参数合成 url 注入点（mined: true，originalValue "1"）', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const parser = new TargetParser(freshClient());
    const points = await parser.discover(
      makeTarget({ baseUrl: `${baseUrl}?id=1`, config: { paramMine: true } })
    );
    const mined = points.filter((p) => p.mined === true);
    assert.equal(mined.length, 1);
    assert.equal(mined[0].param, 'debug');
    assert.equal(mined[0].location, 'url');
    assert.equal(mined[0].originalValue, '1');
    assert.ok(points.some((p) => !p.mined), '既有 URL 参数点位应保留');
  });

  test('默认关闭（config 无 paramMine）：零挖掘请求，零行为变化', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const parser = new TargetParser(freshClient());
    await parser.discover(makeTarget());
    assert.equal(hitCount, 0);
  });

  test('JSON body 目标跳过挖掘（载体无合入路径，发出去会是畸形请求）', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const parser = new TargetParser(freshClient());
    const points = await parser.discover(
      makeTarget({
        method: 'POST',
        jsonBody: { user: { id: 1 } },
        config: { paramMine: true },
      })
    );
    assert.equal(hitCount, 0);
    assert.ok(points.some((p) => p.param === 'user.id'), 'JSON 叶子点位照常生成');
    assert.ok(!points.some((p) => p.mined), '不应有挖掘点位');
  });

  test('精确标记（值尾 *）：用户显式指定注入点，跳过挖掘', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const parser = new TargetParser(freshClient());
    const points = await parser.discover(
      makeTarget({ baseUrl: `${baseUrl}?id=1*`, config: { paramMine: true } })
    );
    assert.equal(hitCount, 0);
    assert.deepEqual(
      points.map((p) => p.param),
      ['id'],
      '只剩被标记的注入点（_applyOnlyPoint 语义）'
    );
  });

  test('onlyPoint 单点重测：跳过挖掘', async () => {
    behavior = 'reflect';
    hitCount = 0;
    const parser = new TargetParser(freshClient());
    const points = await parser.discover(
      makeTarget({ baseUrl: `${baseUrl}?id=1`, config: { paramMine: true, onlyPoint: { location: 'url', param: 'id' } } })
    );
    assert.equal(hitCount, 0);
    assert.deepEqual(points.map((p) => p.param), ['id']);
  });
});
