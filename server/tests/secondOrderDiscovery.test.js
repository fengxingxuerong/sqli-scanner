// SecondOrderDiscovery 单元测试：extractLinks 纯函数 + discoverLinks + confirmTriggers + run。
// mock HttpClient 维护"已存值状态"：POST 写入、GET 触发页按 reflectUrls 回显存储值。
// 全程不发真实请求。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecondOrderDiscovery } from '../src/engine/SecondOrderDiscovery.js';
import { createInjectionPoint } from '../src/engine/models.js';

// 仅用于 discoverLinks / confirmTriggers 的 mock：GET 返回固定 HTML（无 <a>）。
function makeLinkMock(html) {
  const httpClient = {
    async request(opts) {
      if (opts.method === 'GET') return { data: html, status: 200 };
      return { data: '', status: 200 };
    },
  };
  return { httpClient };
}

// 用于 confirmTriggers / run：POST 写值；GET 时 reflectUrls 命中回显存储值，否则返回静态页。
function makeReflectMock({ param = 'username', reflectUrls = [] } = {}) {
  const state = { value: '1', posts: 0, gets: 0 };
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') {
        state.posts++;
        const data = opts.data && typeof opts.data === 'object' ? opts.data : {};
        state.value = param && data[param] != null ? data[param] : Object.values(data)[0] ?? state.value;
        return { data: 'OK', status: 200 };
      }
      if (opts.method === 'GET') {
        state.gets++;
        if (reflectUrls.includes(opts.url)) {
          return { data: `<html>profile: ${state.value}</html>`, status: 200 };
        }
        return { data: '<html>static page, no reflection</html>', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
  return { httpClient, state };
}

// 用于 run 端到端：GET baseUrl 返回含链接 HTML；reflectUrls 命中回显；POST 写值。
function makeRunMock({ param = 'username', reflectUrls = [] } = {}) {
  const linksHtml = '<a href="/profile">profile</a><a href="/about">about</a><a href="#top">top</a>';
  const state = { value: '1', posts: 0, gets: 0 };
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') {
        state.posts++;
        const data = opts.data && typeof opts.data === 'object' ? opts.data : {};
        state.value = param && data[param] != null ? data[param] : Object.values(data)[0] ?? state.value;
        return { data: 'OK', status: 200 };
      }
      if (opts.method === 'GET') {
        if (opts.url === 'http://mock/') return { data: linksHtml, status: 200 };
        if (reflectUrls.includes(opts.url)) return { data: `<html>profile: ${state.value}</html>`, status: 200 };
        return { data: '<html>static</html>', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
  return { httpClient, state };
}

function makeStorePoint(param = 'username', isStore = true) {
  return createInjectionPoint('body', param, '1', {
    formMethod: 'POST',
    actionUrl: 'http://mock/store',
    formValues: { [param]: '1', _token: 'c' },
    csrfTokenName: '_token',
    isStorePoint: isStore,
    storeKind: isStore ? 'registration' : null,
  });
}

test('extractLinks：绝对化 + 去重 + 过滤 mailto/锚点/js', () => {
  const d = new SecondOrderDiscovery();
  const html =
    '<a href="/page">p</a>' +
    '<a href="http://x/b">b</a>' +
    '<a href="#a">#</a>' +
    '<a href="mailto:x@y.com">m</a>' +
    '<a href="javascript:void(0)">j</a>' +
    '<a href="https://y/c">c</a>' +
    '<a href="/page">dup</a>' +
    '<a href="tel:123">t</a>' +
    '<a href="data:text/html,1">d</a>';
  const links = d.extractLinks(html, 'http://mock/');
  assert.equal(links.length, 3, '应仅保留 /page、http://x/b、https://y/c（dup 合并，mailto/tel/data/js/锚点过滤）');
  assert.ok(links.includes('http://mock/page'));
  assert.ok(links.includes('http://x/b'));
  assert.ok(links.includes('https://y/c'));
  assert.ok(!links.some((l) => l.startsWith('mailto:') || l.startsWith('#') || l.startsWith('javascript:')));
});

test('extractLinks：空/非字符串 HTML 安全返回 []', () => {
  const d = new SecondOrderDiscovery();
  assert.deepEqual(d.extractLinks('', 'http://mock/'), []);
  assert.deepEqual(d.extractLinks(null, 'http://mock/'), []);
});

test('discoverLinks：抓 baseUrl 取候选链接', async () => {
  const html = '<a href="/profile">p</a><a href="http://x/b">b</a><a href="https://y/c">c</a><a href="#x">#</a>';
  const { httpClient } = makeLinkMock(html);
  const d = new SecondOrderDiscovery(httpClient);
  const candidates = await d.discoverLinks({ baseUrl: 'http://mock/', config: {} });
  assert.equal(candidates.length, 3);
  assert.ok(candidates.includes('http://mock/profile'));
});

test('discoverLinks：取页失败返回 []（不中断）', async () => {
  const httpClient = { async request() { throw new Error('net'); } };
  const d = new SecondOrderDiscovery(httpClient);
  const candidates = await d.discoverLinks({ baseUrl: 'http://mock/', config: {} });
  assert.deepEqual(candidates, []);
});

test('confirmTriggers：回显页确认 / 非回显页排除 / 哨兵仅存一次', async () => {
  const { httpClient, state } = makeReflectMock({
    param: 'username',
    reflectUrls: ['http://mock/reflect', 'http://mock/another-reflect'],
  });
  const d = new SecondOrderDiscovery(httpClient);
  const confirmed = await d.confirmTriggers({
    target: { baseUrl: 'http://mock/', config: {} },
    config: {},
    storePoints: [makeStorePoint('username', true)],
    candidates: ['http://mock/reflect', 'http://mock/nope', 'http://mock/another-reflect'],
  });
  assert.deepEqual(confirmed, ['http://mock/reflect', 'http://mock/another-reflect']);
  assert.equal(state.posts, 1, '哨兵仅存一次（最小写代价）');
});

test('confirmTriggers：无存储点时返回 []（无法确认）', async () => {
  const { httpClient } = makeReflectMock();
  const d = new SecondOrderDiscovery(httpClient);
  const confirmed = await d.confirmTriggers({
    target: { baseUrl: 'http://mock/', config: {} },
    config: {},
    storePoints: [makeStorePoint('username', false)], // 非存储点
    candidates: ['http://mock/reflect'],
  });
  assert.deepEqual(confirmed, []);
});

test('confirmTriggers：存储失败（POST 抛错）返回 []', async () => {
  const httpClient = {
    async request(opts) {
      if (opts.method === 'POST') throw new Error('store failed');
      return { data: '<html>static</html>', status: 200 };
    },
  };
  const d = new SecondOrderDiscovery(httpClient);
  const confirmed = await d.confirmTriggers({
    target: { baseUrl: 'http://mock/', config: {} },
    config: {},
    storePoints: [makeStorePoint('username', true)],
    candidates: ['http://mock/reflect'],
  });
  assert.deepEqual(confirmed, []);
});

test('run：端到端发现候选 + 哨兵确认', async () => {
  const { httpClient } = makeRunMock({ param: 'username', reflectUrls: ['http://mock/profile'] });
  const d = new SecondOrderDiscovery(httpClient);
  const sp = makeStorePoint('username', true);
  const target = { baseUrl: 'http://mock/', config: {} };
  const { candidates, confirmed } = await d.run({ target, config: {}, storePoints: [sp] });
  assert.ok(candidates.includes('http://mock/profile'), '候选应包含 /profile');
  assert.ok(candidates.includes('http://mock/about'), '候选应包含 /about');
  assert.deepEqual(confirmed, ['http://mock/profile'], '仅 /profile 回显存储值被确认');
});
