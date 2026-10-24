// requestFileParser 增强单测：multipart + JSON 候选提取
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRequestFile } from '../src/core/requestFileParser.js';

test('multipart/form-data：text 字段与 filename 字段提取', () => {
  const raw = [
    'POST /upload HTTP/1.1',
    'Host: up.example.com',
    'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX',
    '',
    '------WebKitFormBoundaryX',
    'Content-Disposition: form-data; name="title"',
    '',
    'my report',
    '------WebKitFormBoundaryX',
    'Content-Disposition: form-data; name="avatar"; filename="a.png"',
    'Content-Type: image/png',
    '',
    'BINDATA',
    '------WebKitFormBoundaryX--',
  ].join('\n');
  const r = parseRequestFile(raw);
  assert.equal(r.method, 'POST');
  assert.equal(r.params.title, 'my report');
  assert.equal(r.params.avatar, 'a.png'); // 文件字段取 filename
  assert.ok(r.body.includes('BINDATA')); // body 原样保留
});

// [D159 2026-10-25] 文件字段必须**单独**进 fileParts：
// 发送侧要按 `filename=` 属性重建，而不是把 filename 当文本字段内容发（那样目标读到的
// 文件名恒空 ⇒ 注入值从未进 SQL）。靶场 e2e/detect-surface-lab /api/upload 实测。
// ⚠️ bodyFields 仍保留全部字段名 —— 它的契约是「body 里有哪些字段」（HAR/Postman 集合
// 契约测试按它断言），从 bodyParams 剔除文件字段的动作在 CLI 的 applyRequestFile 里。
test('[D159] multipart 文件字段进 fileParts（bodyFields 保留集合契约）', () => {
  const raw = [
    'POST /upload HTTP/1.1',
    'Host: up.example.com',
    'Content-Type: multipart/form-data; boundary=----B1',
    '',
    '------B1',
    'Content-Disposition: form-data; name="title"',
    '',
    'my report',
    '------B1',
    'Content-Disposition: form-data; name="avatar"; filename="a.png"',
    'Content-Type: image/png',
    '',
    'BINDATA',
    '------B1--',
  ].join('\n');
  const r = parseRequestFile(raw);
  assert.deepEqual(r.fileParts, [{ name: 'avatar', filename: 'a.png', contentType: 'image/png' }]);
  assert.deepEqual(Object.keys(r.bodyFields).sort(), ['avatar', 'title'], 'bodyFields 是集合契约，仍含文件字段');
  assert.equal(r.params.avatar, 'a.png', 'params 仍保留 filename（候选列表，不改语义）');
});

test('JSON body：顶层叶子并入 params，嵌套走点路径', () => {
  const raw = [
    'POST /api/user HTTP/1.1',
    'Host: api.example.com',
    'Content-Type: application/json',
    '',
    '{"user":{"id":7,"name":"bob"},"role":"admin"}',
  ].join('\n');
  const r = parseRequestFile(raw);
  assert.equal(r.params['user.id'], '7');
  assert.equal(r.params['user.name'], 'bob');
  assert.equal(r.params['role'], 'admin');
});

test('multipart 无 boundary → 不炸，params 仅 query', () => {
  const raw = [
    'POST /up HTTP/1.1',
    'Host: t.example.com',
    'Content-Type: multipart/form-data',
    '',
    'garbage',
  ].join('\n');
  const r = parseRequestFile(raw);
  assert.equal(r.method, 'POST');
  assert.ok(!('title' in r.params));
});
