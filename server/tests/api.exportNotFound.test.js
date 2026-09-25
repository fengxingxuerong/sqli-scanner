// ============================================================================
// api.exportNotFound.test.js —— 报告下载端点的失败形态
//
// 为什么单独一条文件（2026-09-25，审计输出层时执行复现）：
//   `/scan/:id/report/export` 是**文件下载**端点，历史上它在"扫描不存在/已结束"时返回
//   **200 + application/json**，而且不带 Content-Disposition。前端
//   `src/hooks/useScan.ts` 只判 `res.ok` 然后把响应体另存盘 ⇒ 用户拿到一个装着
//   `{"code":2001,"message":"扫描不存在或已结束"}` 的 report_xxx.csv。
//   实测证据（真 app + 真 fetch）：
//     format=csv → status 200 | ct application/json | 有 Content-Disposition? null
//   症状会被读成"报告导出坏了"，真因是扫描早被回收 —— 归因方向整个错。
//
// 三条断言，缺一不可：
//   ① 缺扫描 → 4xx（不是 200）；
//   ② 成功路径仍然带 Content-Disposition（这条是前端判别式赖以成立的前提，
//      一旦谁把它去掉，②会红，而不是前端静默退回"存错误体"的老坑）；
//   ③ 设了 reportToken 时未带 token 必须 401 —— 下载路径是 src/ 里唯一绕开
//      apiClient 的 fetch，鉴权头历史上根本没发出去（实测裸 fetch 401 / 带 header 200）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createRoutes } from '../src/api/scanRoutes.js';

const CSV_BODY = 'url,param,technique\nhttp://x?id=1,id,union\n';

/** 只实现本测试用到的方法的桩管理器（不依赖 ScanManager 真跑扫描/DB） */
const stubManager = {
  exportReport: (id, format) => (id === 'good' ? (format === 'csv' ? CSV_BODY : JSON.stringify({ scanId: id })) : null),
};

async function withApp(opts, fn) {
  const app = express();
  app.use('/api', createRoutes({ scanManager: stubManager, ...opts }));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('下载端点：扫描不存在 → 4xx，且不得伪装成一份可存盘的产物', async () => {
  await withApp({}, async (base) => {
    for (const format of ['csv', 'sarif', 'markdown', 'json']) {
      const res = await fetch(`${base}/api/scan/gone/report/export?format=${format}`);
      assert.equal(res.status, 404, `format=${format} 返回 ${res.status}：200 会让前端把错误体另存成报告文件`);
      assert.equal(res.headers.get('content-disposition'), null, '失败响应不得带文件名头');
      const body = await res.json();
      assert.ok(body.message?.includes('不存在'), `错误体丢了原因：${JSON.stringify(body)}`);
    }
  });
});

test('下载端点：成功路径必须带 Content-Disposition（前端的"是不是产物"就靠它）', async () => {
  await withApp({}, async (base) => {
    const res = await fetch(`${base}/api/scan/good/report/export?format=csv`);
    assert.equal(res.status, 200);
    assert.match(String(res.headers.get('content-disposition')), /filename="report_good\.csv"/);
    assert.equal(await res.text(), CSV_BODY);
  });
});

test('下载端点：设了 reportToken 时，不带 token 必须 401（带上的才拿到文件）', async () => {
  await withApp({ reportToken: 'sekret' }, async (base) => {
    const url = `${base}/api/scan/good/report/export?format=csv`;
    const bare = await fetch(url);
    assert.equal(bare.status, 401, '裸 fetch 竟然放行 ⇒ 鉴权在这条路径上是空的');
    const withHeader = await fetch(url, { headers: { 'x-api-token': 'sekret' } });
    assert.equal(withHeader.status, 200, '带 token 却被拒 ⇒ 前端补的头白加了');
    assert.ok((await withHeader.text()).includes('union'));
  });
});

test('接线：前端导出确实把 token 发出去（src/ 里唯一一处绕开 apiClient 的 fetch）', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../src/hooks/useScan.ts', import.meta.url), 'utf8');
  const body = src.slice(src.indexOf('const exportReport = useCallback'));
  assert.match(body, /getApiToken\(\)/, '没取 token ⇒ 设了 SCAN_API_TOKEN 时所有导出必 401');
  assert.match(body, /'x-api-token'/, '取了却没发出去');
  assert.match(body, /content-disposition/i, '没检查产物判别式 ⇒ 错误体会被静默存成报告文件');
});
