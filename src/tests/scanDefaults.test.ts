// [P1-CFG 2026-11-02] 前端默认值必须来自生成物（服务端 sharedDefaults.js 的唯一真源）。
import { describe, it, expect } from 'vitest';
import { DEFAULT_CONFIG } from '../shared/constants';
import GENERATED from '../shared/scanDefaults.generated.json';

describe('默认值单一真源', () => {
  it('DEFAULT_CONFIG 的共享标量与 scanDefaults.generated.json 一致', () => {
    expect(DEFAULT_CONFIG.concurrency).toBe(GENERATED.concurrency);
    expect(DEFAULT_CONFIG.timeoutMs).toBe(GENERATED.timeoutMs);
    expect(DEFAULT_CONFIG.retry).toBe(GENERATED.retry);
    expect(DEFAULT_CONFIG.timeThresholdMs).toBe(GENERATED.timeThresholdMs);
    expect(DEFAULT_CONFIG.ratePerSec).toBe(GENERATED.ratePerSec);
    expect(DEFAULT_CONFIG.enableExtract).toBe(GENERATED.enableExtract);
    expect(DEFAULT_CONFIG.crawlDepth).toBe(GENERATED.crawlDepth);
    expect(DEFAULT_CONFIG.pocRedactAuth).toBe(GENERATED.pocRedactAuth);
    expect(DEFAULT_CONFIG.confirmFormWrites).toBe(GENERATED.confirmFormWrites);
  });

  it('默认关闭拖库与表单写、默认开启 PoC 脱敏', () => {
    expect(DEFAULT_CONFIG.enableExtract).toBe(false);
    expect(DEFAULT_CONFIG.confirmFormWrites).toBe(false);
    expect(DEFAULT_CONFIG.pocRedactAuth).toBe(true);
  });
});
