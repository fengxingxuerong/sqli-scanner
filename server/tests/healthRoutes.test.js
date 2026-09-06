// healthRoutes 零覆盖补测：GET /health 健康检查端点
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { healthRoutes } from '../src/api/healthRoutes.js';

function request(app, path) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const req = http.request({ host: '127.0.0.1', port, method: 'GET', path }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          server.close();
          resolve({ status: res.statusCode, body: JSON.parse(body || '{}') });
        });
      });
      req.on('error', (e) => { server.close(); reject(e); });
      req.end();
    });
  });
}

test('GET /health：返回统一响应包且 status=up', async () => {
  const app = express();
  app.use('/api', healthRoutes);
  const res = await request(app, '/api/health');
  assert.equal(res.status, 200);
  assert.equal(res.body.code, 0);
  assert.equal(res.body.data.status, 'up');
  assert.ok(res.body.data.version);
  assert.equal(res.body.message, 'ok');
});
