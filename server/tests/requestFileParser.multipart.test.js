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
