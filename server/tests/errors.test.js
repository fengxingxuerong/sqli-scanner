// errors.js 单元测试：错误码枚举 + AppError
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCode, AppError } from '../src/core/errors.js';

test('ErrorCode 各错误码存在且为数字', () => {
  const expected = {
    OK: 0,
    INVALID_TARGET: 1001,
    UNSUPPORTED_METHOD: 1002,
    SCAN_NOT_FOUND: 2001,
    ENGINE_BUSY: 2002,
    HTTP_TIMEOUT: 3001,
    HTTP_ERROR: 3002,
    DETECT_FAILED: 4001,
    EXTRACT_FAILED: 5001,
    UNKNOWN: 9001,
  };
  for (const [k, v] of Object.entries(expected)) {
    assert.equal(ErrorCode[k], v, `错误码 ${k} 不匹配`);
  }
});

test('AppError 携带 code 与 message', () => {
  const e = new AppError(ErrorCode.INVALID_TARGET, '目标 URL 不能为空');
  assert.ok(e instanceof Error);
  assert.equal(e.name, 'AppError');
  assert.equal(e.code, 1001);
  assert.equal(e.message, '目标 URL 不能为空');
});

test('AppError 默认值', () => {
  const e = new AppError();
  assert.equal(e.code, ErrorCode.UNKNOWN);
  assert.equal(e.message, '未知错误');
});
