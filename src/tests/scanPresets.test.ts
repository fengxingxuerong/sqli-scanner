// ============================================================================
// scanPresets.test.ts —— 扫描预设契约（2026-10-02 竞品吸收批次）
//
// 预设 = 一组既有键的 patch 快照（不引入新配置键）。本套件钉住三条：
//   ① 预设覆盖的每个键都在 SCAN_CONFIG_KEYS 里（进得了 /api/scan/start 请求体）；
//   ② 每个键的值类型与 SCAN_CONFIG_VALUE_TYPES 声明一致（不会「勾了但传错类型」）；
//   ③ 数值键的取值在后端 clamp 区间内（level 1-5 / risk 1-3 / crawlDepth 0-3）。
// 另外验证 standard 预设与 DEFAULT_CONFIG 的检测强度面对齐（语义锚点，防两处漂移）。
// ============================================================================
import { describe, it, expect } from 'vitest';
import { SCAN_PRESETS, getScanPreset, type ScanPresetId } from '../shared/scanPresets';
import { SCAN_CONFIG_KEYS, SCAN_CONFIG_VALUE_TYPES, DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfigKey } from '../shared/constants';

const ALL_PRESET_IDS: ScanPresetId[] = ['quick', 'standard', 'deep'];

describe('scanPresets 契约', () => {
  it('三个预设齐全：quick / standard / deep', () => {
    expect(SCAN_PRESETS.map((p) => p.id)).toEqual(ALL_PRESET_IDS);
    for (const id of ALL_PRESET_IDS) {
      expect(getScanPreset(id), `预设 ${id} 应存在`).toBeDefined();
    }
    expect(getScanPreset('nope' as ScanPresetId)).toBeUndefined();
  });

  it('每个预设覆盖的键都在 SCAN_CONFIG_KEYS 白名单里', () => {
    for (const preset of SCAN_PRESETS) {
      const keys = Object.keys(preset.patch) as ScanConfigKey[];
      expect(keys.length, `${preset.id} 至少覆盖一个键`).toBeGreaterThan(0);
      for (const key of keys) {
        expect(
          SCAN_CONFIG_KEYS.includes(key),
          `${preset.id}.${key} 不在 SCAN_CONFIG_KEYS：后端会静默丢弃该键`
        ).toBe(true);
      }
    }
  });

  it('每个键的值类型与 SCAN_CONFIG_VALUE_TYPES 一致', () => {
    for (const preset of SCAN_PRESETS) {
      for (const [key, value] of Object.entries(preset.patch)) {
        const expected = SCAN_CONFIG_VALUE_TYPES[key as ScanConfigKey];
        expect(expected, `${preset.id}.${key} 缺类型声明`).toBeDefined();
        if (expected === 'boolean') expect(typeof value, `${preset.id}.${key}`).toBe('boolean');
        if (expected === 'number') {
          expect(typeof value, `${preset.id}.${key}`).toBe('number');
          expect(Number.isFinite(value as number), `${preset.id}.${key}`).toBe(true);
        }
        if (expected === 'stringArray') {
          expect(Array.isArray(value), `${preset.id}.${key}`).toBe(true);
        }
      }
    }
  });

  it('数值键落在后端 clamp 区间内（level 1-5 / risk 1-3 / crawlDepth 0-3）', () => {
    const RANGES: Partial<Record<ScanConfigKey, [number, number]>> = {
      level: [1, 5],
      risk: [1, 3],
      crawlDepth: [0, 3],
    };
    for (const preset of SCAN_PRESETS) {
      for (const [key, range] of Object.entries(RANGES)) {
        const v = preset.patch[key as ScanConfigKey];
        if (typeof v === 'number') {
          expect(v, `${preset.id}.${key}=${v} 越界`).toBeGreaterThanOrEqual(range![0]);
          expect(v, `${preset.id}.${key}=${v} 越界`).toBeLessThanOrEqual(range![1]);
        }
      }
    }
  });

  it('standard 预设与 DEFAULT_CONFIG 的检测强度面对齐（防两处漂移）', () => {
    const standard = getScanPreset('standard')!;
    expect(standard.patch.techniques).toEqual(DEFAULT_CONFIG.techniques);
    expect(standard.patch.crawlDepth).toBe(DEFAULT_CONFIG.crawlDepth);
  });

  it('预设刻意不含 paramMine（挖掘是显式 opt-in，不该被预设顺带打开）', () => {
    for (const preset of SCAN_PRESETS) {
      expect(preset.patch).not.toHaveProperty('paramMine');
    }
  });
});
